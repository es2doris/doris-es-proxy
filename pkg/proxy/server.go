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
	"html"
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
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// HitRow represents a single matched document returned by Doris for Query 1 (HitsSQL).
type HitRow struct {
	Index     string
	ID        string
	Routing   string
	Version   int64
	Source    json.RawMessage
	RawSource json.RawMessage
	Score     float64
	TotalHits int64
	Schema    *schema.IndexSchema
	Query     *esast.Query
}

// EffectiveSource returns the original unfiltered document JSON when RawSource is set,
// or Source otherwise.
func (h HitRow) EffectiveSource() json.RawMessage {
	if len(h.RawSource) > 0 {
		return h.RawSource
	}
	return h.Source
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
	docRouting            map[string]map[string]string        // indexName -> docID -> routing
	docVersions           map[string]map[string]int64         // indexName -> docID -> last known version (including tombstones)
	indexDefaultPipelines map[string]string                   // indexName -> default ingest pipeline ID
	indexFinalPipelines   map[string]string                   // indexName -> final ingest pipeline ID
	templates             map[string]esast.IndexTemplateRequest
	componentTemplates    map[string]map[string]any
	pipelines             map[string]map[string]any
	enrichPolicies        map[string]map[string]any
	ilmPolicies           map[string]map[string]any
	dataStreams           map[string]map[string]any
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
		docRouting:            make(map[string]map[string]string),
		docVersions:           make(map[string]map[string]int64),
		indexDefaultPipelines: make(map[string]string),
		indexFinalPipelines:   make(map[string]string),
		templates:             make(map[string]esast.IndexTemplateRequest),
		componentTemplates:    make(map[string]map[string]any),
		pipelines:             make(map[string]map[string]any),
		enrichPolicies:        make(map[string]map[string]any),
		ilmPolicies:           make(map[string]map[string]any),
		dataStreams:           make(map[string]map[string]any),
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
		next := time.Now().UnixMicro()
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

func (s *Server) setDocRouting(indexName, docID, routing string) {
	if indexName == "" || docID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.docRouting == nil {
		s.docRouting = make(map[string]map[string]string)
	}
	if routing == "" {
		if m, ok := s.docRouting[indexName]; ok {
			delete(m, docID)
		}
		return
	}
	if s.docRouting[indexName] == nil {
		s.docRouting[indexName] = make(map[string]string)
	}
	s.docRouting[indexName][docID] = routing
}

func (s *Server) getDocRouting(indexName, docID string) string {
	if indexName == "" || docID == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.docRouting == nil {
		return ""
	}
	if m, ok := s.docRouting[indexName]; ok {
		return m[docID]
	}
	return ""
}

func (s *Server) setDocVersion(indexName, docID string, ver int64) {
	if indexName == "" || docID == "" || ver <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.docVersions == nil {
		s.docVersions = make(map[string]map[string]int64)
	}
	if s.docVersions[indexName] == nil {
		s.docVersions[indexName] = make(map[string]int64)
	}
	s.docVersions[indexName][docID] = ver
}

func (s *Server) getDocVersion(indexName, docID string) int64 {
	if indexName == "" || docID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.docVersions == nil {
		return 0
	}
	if m, ok := s.docVersions[indexName]; ok {
		return m[docID]
	}
	return 0
}

func (s *Server) resolveEffectiveWriteRouting(rawIndex, targetIndex, reqRouting, pipeRouting string) string {
	if pipeRouting != "" {
		return pipeRouting
	}
	if reqRouting != "" {
		return reqRouting
	}
	if rawIndex != "" && targetIndex != "" {
		s.mu.RLock()
		meta := s.aliasMeta[rawIndex][targetIndex]
		s.mu.RUnlock()
		if meta.IndexRouting != "" {
			return meta.IndexRouting
		}
		if meta.Routing != "" {
			return meta.Routing
		}
	}
	return ""
}

func (s *Server) resolveEffectiveReadRouting(rawIndex, targetIndex, reqRouting string) string {
	if reqRouting != "" {
		return reqRouting
	}
	if rawIndex != "" && targetIndex != "" {
		s.mu.RLock()
		meta := s.aliasMeta[rawIndex][targetIndex]
		s.mu.RUnlock()
		if meta.SearchRouting != "" {
			return meta.SearchRouting
		}
		if meta.Routing != "" {
			return meta.Routing
		}
	}
	return ""
}

func (s *Server) docMatchesRequestRouting(indexName, docID, reqRouting string) bool {
	reqRouting = strings.TrimSpace(reqRouting)
	if reqRouting == "" {
		return true
	}
	effDocRouting := s.getDocRouting(indexName, docID)
	if effDocRouting == "" {
		effDocRouting = docID
	}
	for _, part := range strings.Split(reqRouting, ",") {
		if strings.TrimSpace(part) == effDocRouting {
			return true
		}
	}
	return false
}

func (s *Server) isRoutingRequired(idxSchema *schema.IndexSchema) bool {
	return idxSchema != nil && idxSchema.RawMapping != nil && idxSchema.RawMapping.Routing != nil && idxSchema.RawMapping.Routing.Required
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
		case "component_template":
			if isDeleted {
				delete(s.componentTemplates, e.EntityKey)
				continue
			}
			var comp map[string]any
			if err := json.Unmarshal([]byte(e.PayloadJSON), &comp); err == nil && comp != nil {
				if s.componentTemplates == nil {
					s.componentTemplates = make(map[string]map[string]any)
				}
				s.componentTemplates[e.EntityKey] = comp
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
			if len(spec.Properties) > 0 || len(spec.Runtime) > 0 || spec.Dynamic != nil || spec.Subobjects != nil || spec.Routing != nil {
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
		case "enrich_policy":
			if isDeleted {
				delete(s.enrichPolicies, e.EntityKey)
				continue
			}
			var pol map[string]any
			if err := json.Unmarshal([]byte(e.PayloadJSON), &pol); err == nil && pol != nil {
				if s.enrichPolicies == nil {
					s.enrichPolicies = make(map[string]map[string]any)
				}
				s.enrichPolicies[e.EntityKey] = pol
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
		case "data_stream":
			if isDeleted {
				delete(s.dataStreams, e.EntityKey)
				continue
			}
			var ds map[string]any
			if err := json.Unmarshal([]byte(e.PayloadJSON), &ds); err == nil && len(ds) > 0 {
				if s.dataStreams == nil {
					s.dataStreams = make(map[string]map[string]any)
				}
				s.dataStreams[e.EntityKey] = ds
			}
		case "ilm_policy":
			if isDeleted {
				delete(s.ilmPolicies, e.EntityKey)
				continue
			}
			var pol map[string]any
			if err := json.Unmarshal([]byte(e.PayloadJSON), &pol); err == nil && len(pol) > 0 {
				if s.ilmPolicies == nil {
					s.ilmPolicies = make(map[string]map[string]any)
				}
				s.ilmPolicies[e.EntityKey] = pol
			}
		}
	}
	s.queryCache.InvalidateAll()
	return nil
}

func (s *Server) persistDataStream(ctx context.Context, name string, ds map[string]any) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(ds); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "data_stream",
				EntityKey:      name,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) deleteDataStreamCatalog(ctx context.Context, name string) {
	s.deleteCatalogEntity(ctx, "data_stream", name)
}

func (s *Server) persistILMPolicy(ctx context.Context, name string, pol map[string]any) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(pol); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "ilm_policy",
				EntityKey:      name,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) deleteILMPolicyCatalog(ctx context.Context, name string) {
	s.deleteCatalogEntity(ctx, "ilm_policy", name)
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

func (s *Server) persistComponentTemplate(ctx context.Context, name string, comp map[string]any) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(comp); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "component_template",
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

func (s *Server) persistEnrichPolicy(ctx context.Context, name string, body map[string]any) {
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(body); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "enrich_policy",
				EntityKey:      name,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) deleteEnrichPolicyCatalog(ctx context.Context, name string) {
	s.deleteCatalogEntity(ctx, "enrich_policy", name)
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
			if len(idxSchema.RawMapping.Runtime) > 0 {
				payloadMap["runtime"] = idxSchema.RawMapping.Runtime
			}
			if idxSchema.RawMapping.Dynamic != nil {
				payloadMap["dynamic"] = idxSchema.RawMapping.Dynamic
			}
			if idxSchema.RawMapping.Subobjects != nil {
				payloadMap["subobjects"] = idxSchema.RawMapping.Subobjects
			}
			if idxSchema.RawMapping.Routing != nil {
				payloadMap["_routing"] = idxSchema.RawMapping.Routing
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
			case "_settings":
				s.handleIndexSettings(w, r)
			case "_refresh", "_flush", "_forcemerge":
				s.handleRefresh(w, r)
			case "_cat":
				s.handleCatRoot(w, r)
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
				s.handleCatHealth(w, r)
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
			case segs[0] == "_resolve" && segs[1] == "index":
				r.SetPathValue("name", "*")
				s.handleResolveIndex(w, r)
			case segs[0] == "_ingest" && segs[1] == "pipeline":
				s.handleIngestPipeline(w, r)
			case segs[0] == "_enrich" && (segs[1] == "policy" || segs[1] == "_stats" || segs[1] == "stats"):
				s.handleEnrichAPI(w, r)
			case segs[0] == "_security" && segs[1] == "_authenticate":
				s.handleSecurityAuthenticate(w, r)
			case segs[0] == "_alias" || segs[0] == "_aliases":
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
				case "_doc":
					if r.Method == http.MethodPost {
						s.handlePutDoc(w, r)
					} else {
						writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
					}
				case "_create":
					writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
				case "_clone", "_shrink", "_split":
					writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: target index is missing;")
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
			if segs[0] == "_search" && segs[1] == "scroll" {
				r.SetPathValue("scroll_id", segs[2])
				s.handleScroll(w, r)
				return
			}
			if segs[0] == "_resolve" && segs[1] == "index" {
				r.SetPathValue("name", segs[2])
				s.handleResolveIndex(w, r)
				return
			}
			if segs[0] == "_data_stream" && segs[2] == "_rollover" {
				r.SetPathValue("alias", segs[1])
				s.handleRollover(w, r)
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
			if segs[0] == "_enrich" && segs[1] == "policy" {
				r.SetPathValue("name", segs[2])
				s.handleEnrichAPI(w, r)
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
			case "_doc":
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
			case "_create":
				switch r.Method {
				case http.MethodPut, http.MethodPost:
					s.handlePutDoc(w, r)
				default:
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
			case "_update":
				if r.Method == http.MethodPost {
					s.handleUpdateDoc(w, r)
				} else {
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
			case "_source":
				if r.Method == http.MethodGet || r.Method == http.MethodHead {
					s.handleGetSource(w, r)
				} else {
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
			case "_explain":
				s.handleExplainDoc(w, r)
			case "_clone", "_shrink", "_split":
				if r.Method == http.MethodPost || r.Method == http.MethodPut {
					r.SetPathValue("target", segs[2])
					s.handleResizeOrCloneIndex(w, r)
				} else {
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
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
			if segs[0] == "_enrich" && segs[1] == "policy" && segs[3] == "_execute" {
				r.SetPathValue("name", segs[2])
				r.SetPathValue("action", "_execute")
				s.handleEnrichAPI(w, r)
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
	if inner, ok := settings["settings"].(map[string]any); ok {
		settings = inner
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
	if inner, ok := settings["settings"].(map[string]any); ok {
		settings = inner
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
	if p := strings.TrimSpace(reqPipeline); p != "" {
		if p == "_none" || p == "none" {
			return ""
		}
		return p
	}
	if p := strings.TrimSpace(itemPipeline); p != "" {
		if p == "_none" || p == "none" {
			return ""
		}
		return p
	}
	s.mu.RLock()
	defPipe, hasPipe := s.indexDefaultPipelines[indexName]
	_, hasIdx := s.indices[indexName]
	s.mu.RUnlock()
	if !hasPipe && !hasIdx {
		if resolved, _, wErr := s.resolveWriteIndexWithFilter(indexName); wErr == nil && resolved != "" && resolved != indexName {
			s.mu.RLock()
			defPipe, hasPipe = s.indexDefaultPipelines[resolved]
			_, hasIdx = s.indices[resolved]
			s.mu.RUnlock()
		}
		if !hasPipe && !hasIdx {
			if resolved := s.resolveIndexName(indexName); resolved != "" && resolved != indexName {
				s.mu.RLock()
				defPipe, hasPipe = s.indexDefaultPipelines[resolved]
				_, hasIdx = s.indices[resolved]
				s.mu.RUnlock()
			}
		}
	}
	if !hasPipe && !hasIdx {
		_ = s.syncCatalogFromBackend(context.Background())
		s.mu.RLock()
		defPipe, hasPipe = s.indexDefaultPipelines[indexName]
		_, hasIdx = s.indices[indexName]
		if !hasPipe && !hasIdx {
			_, tplDef, hasTplDef, _, _, _ := s.matchingTemplateConfigLocked(indexName)
			if hasTplDef {
				defPipe = tplDef
			}
		}
		s.mu.RUnlock()
	}
	if defPipe == "_none" || defPipe == "none" {
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
		if resolved, _, wErr := s.resolveWriteIndexWithFilter(indexName); wErr == nil && resolved != "" && resolved != indexName {
			s.mu.RLock()
			finPipe, hasPipe = s.indexFinalPipelines[resolved]
			_, hasIdx = s.indices[resolved]
			s.mu.RUnlock()
		}
		if !hasPipe && !hasIdx {
			if resolved := s.resolveIndexName(indexName); resolved != "" && resolved != indexName {
				s.mu.RLock()
				finPipe, hasPipe = s.indexFinalPipelines[resolved]
				_, hasIdx = s.indices[resolved]
				s.mu.RUnlock()
			}
		}
	}
	if !hasPipe && !hasIdx {
		_ = s.syncCatalogFromBackend(context.Background())
		s.mu.RLock()
		finPipe, hasPipe = s.indexFinalPipelines[indexName]
		_, hasIdx = s.indices[indexName]
		if !hasPipe && !hasIdx {
			_, _, _, tplFin, hasTplFin, _ := s.matchingTemplateConfigLocked(indexName)
			if hasTplFin {
				finPipe = tplFin
			}
		}
		s.mu.RUnlock()
	}
	if finPipe == "_none" || finPipe == "none" {
		return ""
	}
	return finPipe
}

func (s *Server) handleIndexSettings(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	validTargets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}

	if r.Method == http.MethodPut {
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var settings map[string]any
			if err := json.Unmarshal(bodyBytes, &settings); err != nil {
				writeESError(w, http.StatusBadRequest, "parse_exception", "Failed to parse content to map")
				return
			}
			defPipe, hasDef := extractDefaultPipelineFromSettings(settings)
			finPipe, hasFin := extractFinalPipelineFromSettings(settings)
			for _, pName := range []string{defPipe, finPipe} {
				if pName != "" && pName != "_none" && pName != "none" {
					s.mu.RLock()
					_, exists := s.pipelines[pName]
					s.mu.RUnlock()
					if !exists {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "Pipeline ["+pName+"] is not defined")
						return
					}
				}
			}
			if hasDef || hasFin {
				for _, indexName := range validTargets {
					s.mu.Lock()
					if hasDef {
						if defPipe == "" {
							delete(s.indexDefaultPipelines, indexName)
						} else {
							s.indexDefaultPipelines[indexName] = defPipe
						}
					}
					if hasFin {
						if finPipe == "" {
							delete(s.indexFinalPipelines, indexName)
						} else {
							s.indexFinalPipelines[indexName] = finPipe
						}
					}
					idxSchema := s.indices[indexName]
					s.mu.Unlock()
					s.persistIndex(r.Context(), indexName, idxSchema)
				}
			}
		}
		s.queryCache.InvalidateAll()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		return
	}

	out := make(map[string]any, len(validTargets))
	s.mu.RLock()
	for _, indexName := range validTargets {
		defPipe := s.indexDefaultPipelines[indexName]
		finPipe := s.indexFinalPipelines[indexName]
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
		out[indexName] = map[string]any{
			"settings": map[string]any{
				"index": idxSettings,
			},
		}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
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
			docMap := map[string]any{"properties": idx.RawMapping.Properties}
			if idx.RawMapping.Dynamic != nil {
				docMap["dynamic"] = idx.RawMapping.Dynamic
			}
			mappings["_doc"] = docMap
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
	_ = s.syncCatalogFromBackend(r.Context())
	policy := strings.TrimSpace(r.PathValue("policy"))
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if policy == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: lifecycle policy name is missing;")
			return
		}
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var polObj map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &polObj); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		if polObj == nil {
			polObj = map[string]any{"policy": map[string]any{"phases": map[string]any{}}}
		}
		s.mu.Lock()
		if s.ilmPolicies == nil {
			s.ilmPolicies = make(map[string]map[string]any)
		}
		ver := 1
		if existing, exists := s.ilmPolicies[policy]; exists {
			if v, okV := toInt64(existing["version"]); okV && v > 0 {
				ver = int(v) + 1
			}
		}
		polInner, okInner := polObj["policy"].(map[string]any)
		if !okInner {
			polInner = polObj
		}
		storedPol := map[string]any{
			"version":       ver,
			"modified_date": "2026-01-01T00:00:00.000Z",
			"policy":        polInner,
		}
		s.ilmPolicies[policy] = storedPol
		s.mu.Unlock()
		s.persistILMPolicy(r.Context(), policy, storedPol)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		if policy == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: lifecycle policy name is missing;")
			return
		}
		s.mu.Lock()
		var toDelete []string
		if strings.ContainsAny(policy, "*?,") || strings.HasPrefix(policy, "-") || policy == "_all" {
			for k := range s.ilmPolicies {
				if matchMultiWildcardWithExclusions(policy, k) {
					toDelete = append(toDelete, k)
				}
			}
		} else if _, exists := s.ilmPolicies[policy]; exists {
			toDelete = []string{policy}
		}
		for _, k := range toDelete {
			delete(s.ilmPolicies, k)
		}
		s.mu.Unlock()
		if len(toDelete) == 0 {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "lifecycle policy ["+policy+"] does not exist")
			return
		}
		for _, k := range toDelete {
			s.deleteILMPolicyCatalog(r.Context(), k)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodHead:
		if policy != "" {
			s.mu.RLock()
			exists := false
			if strings.ContainsAny(policy, "*?,") || strings.HasPrefix(policy, "-") || policy == "_all" {
				for k := range s.ilmPolicies {
					if matchMultiWildcardWithExclusions(policy, k) {
						exists = true
						break
					}
				}
			} else {
				_, exists = s.ilmPolicies[policy]
			}
			s.mu.RUnlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	default:
		s.mu.RLock()
		if policy != "" && policy != "_all" && policy != "*" {
			if strings.ContainsAny(policy, "*?,") || strings.HasPrefix(policy, "-") {
				for _, part := range strings.Split(policy, ",") {
					part = strings.TrimSpace(part)
					if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
						continue
					}
					if _, exists := s.ilmPolicies[part]; !exists {
						s.mu.RUnlock()
						writeESError(w, http.StatusNotFound, "resource_not_found_exception", "lifecycle policy ["+part+"] does not exist")
						return
					}
				}
				out := make(map[string]any)
				for k, v := range s.ilmPolicies {
					if matchMultiWildcardWithExclusions(policy, k) {
						out[k] = deepCloneDocMap(v)
					}
				}
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, out)
				return
			}
			if stored, exists := s.ilmPolicies[policy]; exists {
				cp := deepCloneDocMap(stored)
				s.mu.RUnlock()
				writeJSON(w, http.StatusOK, map[string]any{policy: cp})
				return
			}
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "lifecycle policy ["+policy+"] does not exist")
			return
		}
		out := make(map[string]any, len(s.ilmPolicies))
		for k, v := range s.ilmPolicies {
			out[k] = deepCloneDocMap(v)
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, out)
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
	_ = s.syncCatalogFromBackend(r.Context())
	name := strings.TrimSpace(r.PathValue("name"))
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		s.mu.RLock()
		_, dsExists := s.dataStreams[name]
		_, idxExists := s.indices[name]
		aliasExists := len(s.aliases[name]) > 0
		s.mu.RUnlock()
		if dsExists {
			writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "data_stream ["+name+"] already exists")
			return
		}
		if idxExists || aliasExists {
			writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "index or alias ["+name+"] already exists")
			return
		}
		_ = s.ensureIndexSchema(r.Context(), name)
		s.mu.Lock()
		if s.dataStreams == nil {
			s.dataStreams = make(map[string]map[string]any)
		}
		dsObj := map[string]any{
			"name":            name,
			"timestamp_field": map[string]any{"name": "@timestamp"},
			"indices": []any{
				map[string]any{
					"index_name": name,
					"index_uuid": name,
				},
			},
			"generation": 1,
			"status":     "GREEN",
			"hidden":     false,
			"system":     false,
			"replicated": false,
		}
		s.dataStreams[name] = dsObj
		s.mu.Unlock()
		s.persistDataStream(r.Context(), name, dsObj)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodDelete:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		s.mu.Lock()
		var matched []string
		var backingIndices []string
		seenBacking := make(map[string]bool)
		addBacking := func(idx string) {
			if idx != "" && !seenBacking[idx] {
				seenBacking[idx] = true
				backingIndices = append(backingIndices, idx)
			}
		}
		for k, ds := range s.dataStreams {
			if matchMultiWildcardWithExclusions(name, k) {
				matched = append(matched, k)
				addBacking(k)
				if rawIndices, ok := ds["indices"].([]any); ok {
					for _, item := range rawIndices {
						if m, okM := item.(map[string]any); okM {
							if idxName, okS := m["index_name"].(string); okS {
								addBacking(idxName)
							}
						}
					}
				}
				for _, t := range s.aliases[k] {
					addBacking(t)
				}
			}
		}
		var tablesToDrop []*schema.IndexSchema
		modifiedAliases := make(map[string][]string)
		for _, k := range matched {
			delete(s.dataStreams, k)
			delete(s.aliases, k)
			delete(s.aliasMeta, k)
			modifiedAliases[k] = nil
		}
		for _, idxName := range backingIndices {
			if idx, ok := s.indices[idxName]; ok {
				tablesToDrop = append(tablesToDrop, idx)
			}
			delete(s.indices, idxName)
			delete(s.docRouting, idxName)
			delete(s.docVersions, idxName)
			delete(s.indexDefaultPipelines, idxName)
			delete(s.indexFinalPipelines, idxName)
			for alias := range s.aliases {
				s.removeAliasTargetLocked(alias, idxName)
				modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
			}
		}
		s.mu.Unlock()
		if len(matched) == 0 {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_streams ["+name+"] missing")
			return
		}
		for _, k := range matched {
			s.deleteDataStreamCatalog(r.Context(), k)
		}
		for _, idxName := range backingIndices {
			s.deleteCatalogEntity(r.Context(), "index", idxName)
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
	case http.MethodHead, http.MethodGet:
		s.mu.RLock()
		var list []any
		var names []string
		for k := range s.dataStreams {
			if name == "" || matchMultiWildcardWithExclusions(name, k) {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		for _, k := range names {
			list = append(list, deepCloneDocMap(s.dataStreams[k]))
		}
		s.mu.RUnlock()
		if r.Method == http.MethodHead {
			if len(list) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if name != "" && !strings.ContainsAny(name, "*?") && !strings.HasPrefix(name, "-") && name != "_all" && len(list) == 0 {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "data_streams ["+name+"] missing")
			return
		}
		if list == nil {
			list = []any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data_streams": list})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) handleCatIndices(w http.ResponseWriter, r *http.Request) {
	var names []string
	if pat := r.PathValue("index"); pat != "" {
		names = s.resolveTargetIndices(pat)
	} else {
		_ = s.syncCatalogFromBackend(r.Context())
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
			"health":         "green",
			"status":         "open",
			"index":          name,
			"uuid":           name,
			"pri":            "1",
			"rep":            "0",
			"docs.count":     "0",
			"docs.deleted":   "0",
			"store.size":     "0b",
			"pri.store.size": "0b",
		})
	}
	writeCatResponse(w, r, []string{"health", "status", "index", "uuid", "pri", "rep", "docs.count", "docs.deleted", "store.size", "pri.store.size"}, list)
}

func (s *Server) handleCatAliases(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	namePattern := r.PathValue("name")
	s.mu.RLock()
	list := make([]map[string]any, 0)
	aliasNames := make([]string, 0, len(s.aliases))
	for alias := range s.aliases {
		aliasNames = append(aliasNames, alias)
	}
	sort.Strings(aliasNames)
	for _, alias := range aliasNames {
		if namePattern != "" && namePattern != "*" && namePattern != "_all" && !matchMultiWildcardWithExclusions(namePattern, alias) {
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

func (s *Server) handleCatRoot(w http.ResponseWriter, r *http.Request) {
	endpoints := []string{
		"/_cat/allocation",
		"/_cat/shards",
		"/_cat/master",
		"/_cat/nodes",
		"/_cat/tasks",
		"/_cat/indices",
		"/_cat/segments",
		"/_cat/count",
		"/_cat/recovery",
		"/_cat/health",
		"/_cat/pending_tasks",
		"/_cat/aliases",
		"/_cat/thread_pool",
		"/_cat/plugins",
		"/_cat/fielddata",
		"/_cat/nodeattrs",
		"/_cat/repositories",
		"/_cat/snapshots",
		"/_cat/templates",
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, endpoints)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("=^.^=\n" + strings.Join(endpoints, "\n") + "\n"))
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex != "" {
		if _, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex); !ok {
			return
		}
	}
	_ = s.coalescer.FlushAll(r.Context())
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
	})
}

type scrollCursor struct {
	Index     string              `json:"idx"`
	Req       esast.SearchRequest `json:"req"`
	LastSort  []any               `json:"after,omitempty"`
	Total     int64               `json:"tot,omitempty"`
	Exhausted bool                `json:"eof,omitempty"`
}

func extractRespTotalHits(resp map[string]any) int64 {
	if resp == nil {
		return 0
	}
	if hitsWrapper, ok := resp["hits"].(map[string]any); ok {
		switch tot := hitsWrapper["total"].(type) {
		case map[string]any:
			if v, okV := toInt64(tot["value"]); okV {
				return v
			}
		default:
			if v, okV := toInt64(tot); okV {
				return v
			}
		}
	}
	return 0
}

func encodeScrollCursorWithState(indexName string, req *esast.SearchRequest, lastSort []any, total int64, exhausted bool) string {
	var r esast.SearchRequest
	if req != nil {
		r = *req
	}
	c := scrollCursor{
		Index:     indexName,
		Req:       r,
		LastSort:  lastSort,
		Total:     total,
		Exhausted: exhausted,
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
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
	if c.Index == "" && !c.Exhausted && len(c.LastSort) == 0 {
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
		if pathScrollID := strings.TrimSpace(r.PathValue("scroll_id")); pathScrollID != "" && pathScrollID != "_all" {
			parts := strings.Split(pathScrollID, ",")
			cnt := 0
			for _, p := range parts {
				if strings.TrimSpace(p) != "" {
					cnt++
				}
			}
			if cnt > 0 {
				numFreed = cnt
			}
		}
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			var body struct {
				ScrollID any `json:"scroll_id"`
			}
			if err := json.Unmarshal(bodyBytes, &body); err == nil {
				switch sid := body.ScrollID.(type) {
				case []any:
					if len(sid) > 0 {
						numFreed = len(sid)
					}
				case string:
					if strings.Contains(sid, ",") {
						cnt := 0
						for _, p := range strings.Split(sid, ",") {
							if strings.TrimSpace(p) != "" {
								cnt++
							}
						}
						if cnt > 0 {
							numFreed = cnt
						}
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"succeeded": true, "num_freed": numFreed})
		return
	}
	scrollID := r.URL.Query().Get("scroll_id")
	if scrollID == "" {
		scrollID = strings.TrimSpace(r.PathValue("scroll_id"))
	}
	if trimmedBody := bytes.TrimSpace(bodyBytes); len(trimmedBody) > 0 {
		var body struct {
			ScrollID any `json:"scroll_id"`
		}
		if err := json.Unmarshal(trimmedBody, &body); err == nil {
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
		} else {
			var rawStr string
			if errStr := json.Unmarshal(trimmedBody, &rawStr); errStr == nil && rawStr != "" {
				scrollID = rawStr
			} else if trimmedBody[0] != '{' && trimmedBody[0] != '[' {
				scrollID = strings.Trim(string(trimmedBody), "\"'")
			}
		}
	}
	cursor, ok := decodeScrollCursor(scrollID)
	if !ok {
		writeESError(w, http.StatusNotFound, "search_context_missing_exception", "No search context found for id ["+scrollID+"]")
		return
	}
	if cursor.Exhausted || len(cursor.LastSort) == 0 {
		eofRel := "eq"
		if thresh, okT := trackTotalHitsThreshold(&cursor.Req); okT && thresh > 0 && cursor.Total >= thresh {
			eofRel = "gte"
		}
		eofTotal := any(map[string]any{"value": cursor.Total, "relation": eofRel})
		if !cursor.Req.ShouldTrackTotalHits() {
			eofTotal = nil
		}
		if isTruthyBoolQueryParam(r, "rest_total_hits_as_int") {
			if !cursor.Req.ShouldTrackTotalHits() {
				eofTotal = int64(-1)
			} else {
				eofTotal = cursor.Total
			}
		}
		hitsMap := map[string]any{
			"max_score": nil,
			"hits":      []any{},
		}
		if eofTotal != nil {
			hitsMap["total"] = eofTotal
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"_scroll_id": encodeScrollCursorWithState(cursor.Index, &cursor.Req, nil, cursor.Total, true),
			"took":       1,
			"timed_out":  false,
			"_shards":    map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
			"hits":       hitsMap,
		})
		return
	}
	req := cursor.Req
	zero := 0
	req.From = &zero
	req.SearchAfter = cursor.LastSort
	req.Aggs = nil
	req.Aggregations = nil
	req.Suggest = nil
	resp, status, errType, errReason := s.executeSearchRequest(r.Context(), cursor.Index, &req)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	total := cursor.Total
	if respTot := extractRespTotalHits(resp); respTot > total {
		total = respTot
	} else if total > 0 && req.ShouldTrackTotalHits() {
		if hitsMap, okH := resp["hits"].(map[string]any); okH {
			rel := "eq"
			if thresh, okT := trackTotalHitsThreshold(&req); okT && thresh > 0 && total >= thresh {
				rel = "gte"
			}
			hitsMap["total"] = map[string]any{"value": total, "relation": rel}
		}
	}
	lastSort := extractLastHitSort(resp)
	nextScrollID := encodeScrollCursorWithState(cursor.Index, &req, lastSort, total, len(lastSort) == 0)
	resp["_scroll_id"] = nextScrollID
	if isTruthyBoolQueryParam(r, "typed_keys") {
		if aggsMap, ok := resp["aggregations"].(map[string]any); ok {
			applyTypedKeysToAggregations(aggsMap, req.EffectiveAggs())
		}
		if sugMap, ok := resp["suggest"].(map[string]any); ok {
			applyTypedKeysToSuggestions(sugMap, req.Suggest)
		}
	}
	if isTruthyBoolQueryParam(r, "rest_total_hits_as_int") {
		applyRestTotalHitsAsInt(resp, &req)
	}
	writeJSON(w, http.StatusOK, resp)
}

func isTruthyBoolQueryParam(r *http.Request, key string) bool {
	if r == nil || r.URL == nil {
		return false
	}
	q := r.URL.Query()
	if !q.Has(key) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(q.Get(key))) {
	case "", "true", "1":
		return true
	default:
		return false
	}
}

func parseOptionalBoolAny(v any) (bool, bool) {
	if v == nil {
		return false, false
	}
	switch tv := v.(type) {
	case bool:
		return tv, true
	case string:
		switch strings.ToLower(strings.TrimSpace(tv)) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	}
	return false, false
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

func matchesTemplateNamePatterns(name string, patterns []string) bool {
	matched := false
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "-") {
			if matchWildcardPattern(strings.TrimPrefix(pat, "-"), name) {
				return false
			}
			continue
		}
		if pat == "_all" || matchWildcardPattern(pat, name) {
			matched = true
		}
	}
	return matched
}

func (s *Server) handleIndexTemplate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	isComponent := strings.Contains(r.URL.Path, "_component_template")
	if isComponent {
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			if name == "" {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
				return
			}
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
			if isTruthyBoolQueryParam(r, "create") {
				_ = s.syncCatalogFromBackend(r.Context())
				s.mu.RLock()
				_, exists := s.componentTemplates[name]
				s.mu.RUnlock()
				if exists {
					writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "component_template ["+name+"] already exists")
					return
				}
			}
			s.mu.Lock()
			s.componentTemplates[name] = comp
			s.mu.Unlock()
			s.persistComponentTemplate(r.Context(), name, comp)
			s.queryCache.InvalidateAll()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		case http.MethodHead:
			_ = s.syncCatalogFromBackend(r.Context())
			patterns := []string{"*"}
			if name != "" && name != "_all" {
				patterns = strings.Split(name, ",")
				for i := range patterns {
					patterns[i] = strings.TrimSpace(patterns[i])
				}
			}
			s.mu.RLock()
			ok := false
			if name != "" && name != "_all" && !strings.ContainsAny(name, "*?") && !strings.HasPrefix(name, "-") {
				ok = true
				for _, p := range patterns {
					if p == "" {
						continue
					}
					if _, exists := s.componentTemplates[p]; !exists {
						ok = false
						break
					}
				}
			} else {
				for k := range s.componentTemplates {
					if matchesTemplateNamePatterns(k, patterns) {
						ok = true
						break
					}
				}
			}
			s.mu.RUnlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			_ = s.syncCatalogFromBackend(r.Context())
			patterns := []string{"*"}
			if name != "" && name != "_all" {
				patterns = strings.Split(name, ",")
				for i := range patterns {
					patterns[i] = strings.TrimSpace(patterns[i])
				}
			}
			s.mu.RLock()
			var matchedNames []string
			for k := range s.componentTemplates {
				if matchesTemplateNamePatterns(k, patterns) {
					matchedNames = append(matchedNames, k)
				}
			}
			sort.Strings(matchedNames)
			list := make([]map[string]any, 0, len(matchedNames))
			for _, k := range matchedNames {
				list = append(list, map[string]any{"name": k, "component_template": s.componentTemplates[k]})
			}
			s.mu.RUnlock()
			if name != "" && !strings.ContainsAny(name, "*?,") && !strings.HasPrefix(name, "-") && name != "_all" && len(list) == 0 {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "component_template ["+name+"] missing")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"component_templates": list})
		case http.MethodDelete:
			if name == "" {
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
				return
			}
			_ = s.syncCatalogFromBackend(r.Context())
			patterns := []string{"*"}
			if name != "_all" {
				patterns = strings.Split(name, ",")
				for i := range patterns {
					patterns[i] = strings.TrimSpace(patterns[i])
				}
			}
			s.mu.Lock()
			var toDelete []string
			if strings.ContainsAny(name, "*?,") || strings.HasPrefix(name, "-") || name == "_all" {
				for k := range s.componentTemplates {
					if matchesTemplateNamePatterns(k, patterns) {
						toDelete = append(toDelete, k)
					}
				}
			} else if _, existed := s.componentTemplates[name]; existed {
				toDelete = []string{name}
			}
			for _, k := range toDelete {
				delete(s.componentTemplates, k)
			}
			s.mu.Unlock()
			if len(toDelete) == 0 {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception", "component_template ["+name+"] missing")
				return
			}
			for _, k := range toDelete {
				s.deleteCatalogEntity(r.Context(), "component_template", k)
			}
			s.queryCache.InvalidateAll()
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
		default:
			writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		}
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
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
		if isTruthyBoolQueryParam(r, "create") {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			_, exists := s.templates[name]
			s.mu.RUnlock()
			if exists {
				writeESError(w, http.StatusBadRequest, "resource_already_exists_exception", "index_template ["+name+"] already exists")
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
		_ = s.syncCatalogFromBackend(r.Context())
		patterns := []string{"*"}
		if name != "" && name != "_all" {
			patterns = strings.Split(name, ",")
			for i := range patterns {
				patterns[i] = strings.TrimSpace(patterns[i])
			}
		}
		s.mu.RLock()
		ok := false
		if name != "" && name != "_all" && !strings.ContainsAny(name, "*?") && !strings.HasPrefix(name, "-") {
			ok = true
			for _, p := range patterns {
				if p == "" {
					continue
				}
				if _, exists := s.templates[p]; !exists {
					ok = false
					break
				}
			}
		} else {
			for k := range s.templates {
				if matchesTemplateNamePatterns(k, patterns) {
					ok = true
					break
				}
			}
		}
		s.mu.RUnlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		_ = s.syncCatalogFromBackend(r.Context())
		trimmedPath := strings.Trim(r.URL.Path, "/")
		isLegacy := strings.HasPrefix(trimmedPath, "_template")
		patterns := []string{"*"}
		if name != "" && name != "_all" {
			patterns = strings.Split(name, ",")
			for i := range patterns {
				patterns[i] = strings.TrimSpace(patterns[i])
			}
		}
		s.mu.RLock()
		var matchedNames []string
		for k := range s.templates {
			if matchesTemplateNamePatterns(k, patterns) {
				matchedNames = append(matchedNames, k)
			}
		}
		sort.Strings(matchedNames)
		if name != "" && !strings.ContainsAny(name, "*?,") && !strings.HasPrefix(name, "-") && name != "_all" && len(matchedNames) == 0 {
			s.mu.RUnlock()
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", "index_template ["+name+"] missing")
			return
		}
		if isLegacy {
			legacyOut := make(map[string]any, len(matchedNames))
			for _, k := range matchedNames {
				legacyOut[k] = s.templates[k]
			}
			s.mu.RUnlock()
			writeJSON(w, http.StatusOK, legacyOut)
			return
		}
		list := make([]map[string]any, 0, len(matchedNames))
		for _, k := range matchedNames {
			list = append(list, map[string]any{"name": k, "index_template": s.templates[k]})
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"index_templates": list})
	case http.MethodDelete:
		if name == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: name is missing;")
			return
		}
		_ = s.syncCatalogFromBackend(r.Context())
		patterns := []string{"*"}
		if name != "_all" {
			patterns = strings.Split(name, ",")
			for i := range patterns {
				patterns[i] = strings.TrimSpace(patterns[i])
			}
		}
		s.mu.Lock()
		var toDelete []string
		if strings.ContainsAny(name, "*?,") || strings.HasPrefix(name, "-") || name == "_all" {
			for k := range s.templates {
				if matchesTemplateNamePatterns(k, patterns) {
					toDelete = append(toDelete, k)
				}
			}
		} else if _, existed := s.templates[name]; existed {
			toDelete = []string{name}
		}
		for _, k := range toDelete {
			delete(s.templates, k)
		}
		s.mu.Unlock()
		if len(toDelete) == 0 {
			writeESError(w, http.StatusNotFound, "index_template_missing_exception", "index_template ["+name+"] missing")
			return
		}
		for _, k := range toDelete {
			s.deleteCatalogEntity(r.Context(), "template", k)
		}
		s.queryCache.InvalidateAll()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) matchingTemplateMappingsLocked(indexName string) *esast.MappingSpec {
	merged, _, _, _, _, _ := s.matchingTemplateConfigLocked(indexName)
	return merged
}

func (s *Server) matchingTemplateConfigLocked(indexName string) (*esast.MappingSpec, string, bool, string, bool, map[string]map[string]any) {
	var merged *esast.MappingSpec
	var defaultPipeline string
	var hasDefaultPipeline bool
	var finalPipeline string
	var hasFinalPipeline bool
	var mergedAliases map[string]map[string]any

	var matchedNames []string
	for k, tpl := range s.templates {
		for _, pat := range tpl.EffectivePatterns() {
			if matchWildcardPattern(pat, indexName) {
				matchedNames = append(matchedNames, k)
				break
			}
		}
	}
	sort.Slice(matchedNames, func(i, j int) bool {
		pi := s.templates[matchedNames[i]].EffectivePriority()
		pj := s.templates[matchedNames[j]].EffectivePriority()
		if pi != pj {
			return pi < pj
		}
		return matchedNames[i] < matchedNames[j]
	})

	applyTemplateSpec := func(t esast.IndexTemplateRequest) {
		if m := t.EffectiveMappings(); m != nil {
			merged = schema.MergeMappingSpecs(merged, m)
		}
		if ts := t.EffectiveSettings(); len(ts) > 0 {
			if p, found := extractDefaultPipelineFromSettings(ts); found {
				defaultPipeline = p
				hasDefaultPipeline = true
			}
			if fp, found := extractFinalPipelineFromSettings(ts); found {
				finalPipeline = fp
				hasFinalPipeline = true
			}
		}
		if ta := t.EffectiveAliases(); len(ta) > 0 {
			if mergedAliases == nil {
				mergedAliases = make(map[string]map[string]any, len(ta))
			}
			for al, meta := range ta {
				mergedAliases[al] = meta
			}
		}
	}

	for _, name := range matchedNames {
		tpl := s.templates[name]
		for _, compName := range tpl.ComposedOf {
			if compRaw, ok := s.componentTemplates[compName]; ok && len(compRaw) > 0 {
				if rawBytes, err := json.Marshal(compRaw); err == nil {
					var compTpl esast.IndexTemplateRequest
					if err := json.Unmarshal(rawBytes, &compTpl); err == nil {
						applyTemplateSpec(compTpl)
					}
				}
			}
		}
		applyTemplateSpec(tpl)
	}
	return merged, defaultPipeline, hasDefaultPipeline, finalPipeline, hasFinalPipeline, mergedAliases
}

func validateESIndexName(name string) (string, bool) {
	if name == "" {
		return "index name may not be empty", false
	}
	if name == "." || name == ".." {
		return fmt.Sprintf("Invalid index name [%s], must not be '.' or '..'", name), false
	}
	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "_") || strings.HasPrefix(name, "+") {
		return fmt.Sprintf("Invalid index name [%s], must not start with '_', '-', or '+'", name), false
	}
	if strings.ToLower(name) != name {
		return fmt.Sprintf("Invalid index name [%s], must be lowercase", name), false
	}
	if len(name) > 255 {
		return fmt.Sprintf("Invalid index name [%s], index name is too long, (%d > 255)", name, len(name)), false
	}
	if strings.ContainsAny(name, "\\/*?\"<>| ,#:") {
		return fmt.Sprintf("Invalid index name [%s], must not contain the following characters [\\, /, *, ?, \", <, >, |,  , ,, #, :]", name), false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return fmt.Sprintf("Invalid index name [%s], must not contain control characters", name), false
		}
	}
	return "", true
}

func (s *Server) resolveValidatedReadTargets(w http.ResponseWriter, r *http.Request, rawIndex string) ([]string, map[string]*esast.Query, bool) {
	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex = strings.TrimSpace(rawIndex)
	ew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
	if (ew == "none" || ew == "closed") && (strings.ContainsAny(rawIndex, "*?") || rawIndex == "_all") {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return nil, nil, false
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return nil, nil, false
	}
	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	allowNoIndices := true
	hasExplicitAllowNoIndices := false
	if rawAllow := strings.TrimSpace(r.URL.Query().Get("allow_no_indices")); rawAllow != "" {
		hasExplicitAllowNoIndices = true
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}

	s.mu.RLock()
	var missingConcrete string
	if rawIndex != "" && rawIndex != "_all" && rawIndex != "*" {
		for _, part := range strings.Split(rawIndex, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
				continue
			}
			_, isIdx := s.indices[part]
			_, isAlias := s.aliases[part]
			_, isDS := s.dataStreams[part]
			if !isIdx && !isAlias && !isDS && strings.HasPrefix(part, ".ds-") && strings.HasSuffix(part, "-000001") {
				dsName := strings.TrimSuffix(strings.TrimPrefix(part, ".ds-"), "-000001")
				if _, okDS := s.dataStreams[dsName]; okDS {
					isDS = true
				}
			}
			if !isIdx && !isAlias && !isDS && missingConcrete == "" {
				missingConcrete = part
			}
		}
	}
	s.mu.RUnlock()

	if missingConcrete != "" && !ignoreUnavailable {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return nil, nil, false
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+missingConcrete+"]")
		return nil, nil, false
	}

	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)
	s.mu.RLock()
	var validTargets []string
	for _, t := range targets {
		if _, ok := s.indices[t]; ok {
			validTargets = append(validTargets, t)
		} else if strings.HasPrefix(t, ".ds-") && strings.HasSuffix(t, "-000001") {
			dsName := strings.TrimSuffix(strings.TrimPrefix(t, ".ds-"), "-000001")
			if _, isDS := s.dataStreams[dsName]; isDS {
				if _, okDS := s.indices[dsName]; okDS {
					validTargets = append(validTargets, t)
				}
			}
		}
	}
	s.mu.RUnlock()

	if len(validTargets) == 0 && rawIndex != "" {
		if !allowNoIndices || (!hasExplicitAllowNoIndices && !ignoreUnavailable && !strings.ContainsAny(rawIndex, "*?,") && !strings.HasPrefix(rawIndex, "-") && rawIndex != "_all") {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return nil, nil, false
			}
			errName := rawIndex
			if missingConcrete != "" {
				errName = missingConcrete
			}
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+errName+"]")
			return nil, nil, false
		}
	}
	return validTargets, aliasFilters, true
}

func (s *Server) handleCreateIndex(w http.ResponseWriter, r *http.Request) {
	indexName := r.PathValue("index")
	if reason, ok := validateESIndexName(indexName); !ok {
		writeESError(w, http.StatusBadRequest, "invalid_index_name_exception", reason)
		return
	}
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
	hasAliasCollision := s.dataStreams[indexName] != nil || (oldSchema == nil && len(s.aliases[indexName]) > 0)
	var collidingAlias string
	for alias := range req.Aliases {
		if alias == indexName || s.indices[alias] != nil || s.dataStreams[alias] != nil {
			collidingAlias = alias
			break
		}
	}
	tplMappings, tplDefPipe, hasTplDefPipe, tplFinPipe, hasTplFinPipe, tplAliases := s.matchingTemplateConfigLocked(indexName)
	s.mu.RUnlock()
	if hasAliasCollision {
		writeESError(w, http.StatusBadRequest, "invalid_index_name_exception",
			fmt.Sprintf("Invalid index name [%s], an alias or data stream with the same name already exists", indexName))
		return
	}
	if collidingAlias != "" {
		writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception",
			fmt.Sprintf("Invalid alias name [%s], an index exists with the same name as the alias", collidingAlias))
		return
	}

	if p, found := extractDefaultPipelineFromSettings(req.Settings); found && p != "" && p != "_none" && p != "none" {
		s.mu.RLock()
		hasPipes := len(s.pipelines) > 0
		_, pipeExists := s.pipelines[p]
		s.mu.RUnlock()
		if hasPipes && !pipeExists {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("pipeline with id [%s] does not exist", p))
			return
		}
	}
	if fp, found := extractFinalPipelineFromSettings(req.Settings); found && fp != "" && fp != "_none" && fp != "none" {
		s.mu.RLock()
		hasPipes := len(s.pipelines) > 0
		_, pipeExists := s.pipelines[fp]
		s.mu.RUnlock()
		if hasPipes && !pipeExists {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("pipeline with id [%s] does not exist", fp))
			return
		}
	}

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
	if hasTplDefPipe {
		if tplDefPipe == "" {
			delete(s.indexDefaultPipelines, indexName)
		} else {
			s.indexDefaultPipelines[indexName] = tplDefPipe
		}
	}
	if hasTplFinPipe {
		if tplFinPipe == "" {
			delete(s.indexFinalPipelines, indexName)
		} else {
			s.indexFinalPipelines[indexName] = tplFinPipe
		}
	}
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
	for alias, rawMeta := range tplAliases {
		meta := parseAliasMetadata(rawMeta)
		s.addAliasWithMetaLocked(alias, indexName, meta)
		aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
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
	targets, _, ok := s.resolveValidatedReadTargets(w, r, r.PathValue("index"))
	if !ok {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := make(map[string]any, len(targets))
	for _, indexName := range targets {
		idx, ok := s.indices[indexName]
		if !ok {
			continue
		}
		mappings := map[string]any{}
		if idx.RawMapping != nil {
			mappings["properties"] = idx.RawMapping.Properties
			if len(idx.RawMapping.Runtime) > 0 {
				mappings["runtime"] = idx.RawMapping.Runtime
			}
			if idx.RawMapping.Dynamic != nil {
				mappings["dynamic"] = idx.RawMapping.Dynamic
			}
			if idx.RawMapping.Routing != nil && idx.RawMapping.Routing.Required {
				mappings["_routing"] = map[string]any{"required": true}
			}
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
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeadIndex(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	raw := strings.TrimSpace(r.PathValue("index"))
	if raw == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ignoreUnavailable := strings.EqualFold(r.URL.Query().Get("ignore_unavailable"), "true")
	checkExistsLocked := func(name string) bool {
		if _, ok := s.indices[name]; ok {
			return true
		}
		if targets, ok := s.aliases[name]; ok && len(targets) > 0 {
			return true
		}
		if _, ok := s.dataStreams[name]; ok {
			return true
		}
		return false
	}

	if !strings.ContainsAny(raw, "*,") && raw != "_all" {
		s.mu.RLock()
		exists := checkExistsLocked(raw)
		s.mu.RUnlock()
		if !exists {
			_ = s.syncCatalogFromBackend(r.Context())
			s.mu.RLock()
			exists = checkExistsLocked(raw)
			s.mu.RUnlock()
		}
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	if !ignoreUnavailable {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "-") || strings.Contains(part, "*") || part == "_all" {
				continue
			}
			s.mu.RLock()
			exists := checkExistsLocked(part)
			s.mu.RUnlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
	}

	targets := s.resolveTargetIndices(raw)
	s.mu.RLock()
	matched := 0
	for _, t := range targets {
		if checkExistsLocked(t) {
			matched++
		}
	}
	s.mu.RUnlock()
	if matched == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteIndex(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	_ = s.syncCatalogFromBackend(r.Context())

	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	allowNoIndices := true
	if r.URL.Query().Has("allow_no_indices") {
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}

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
		if strings.ContainsAny(part, "*?") {
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
		if !isConcreteIndex {
			if !ignoreUnavailable {
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+part+"]")
				return
			}
			continue
		}
		addDeleteTarget(part)
	}
	s.mu.RUnlock()

	if len(targets) == 0 && !allowNoIndices {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}

	modifiedAliases := make(map[string][]string)
	var tablesToDrop []*schema.IndexSchema
	s.mu.Lock()
	for _, indexName := range targets {
		if idx, ok := s.indices[indexName]; ok {
			tablesToDrop = append(tablesToDrop, idx)
		}
		delete(s.indices, indexName)
		delete(s.docRouting, indexName)
		delete(s.docVersions, indexName)
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

func (s *Server) handleGetAllMappings(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]any, len(s.indices))
	for indexName, idx := range s.indices {
		props := map[string]esast.FieldProperty{}
		if idx.RawMapping != nil {
			props = idx.RawMapping.Properties
		}
		mappings := map[string]any{"properties": props}
		if idx.RawMapping != nil && len(idx.RawMapping.Runtime) > 0 {
			mappings["runtime"] = idx.RawMapping.Runtime
		}
		if idx.RawMapping != nil && idx.RawMapping.Dynamic != nil {
			mappings["dynamic"] = idx.RawMapping.Dynamic
		}
		if idx.RawMapping != nil && idx.RawMapping.Routing != nil && idx.RawMapping.Routing.Required {
			mappings["_routing"] = map[string]any{"required": true}
		}
		out[indexName] = map[string]any{
			"mappings": mappings,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetMapping(w http.ResponseWriter, r *http.Request) {
	rawIndex := r.PathValue("index")
	targets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	s.mu.RLock()
	out := make(map[string]any, len(targets))
	for _, indexName := range targets {
		idx, exists := s.indices[indexName]
		if !exists && strings.HasPrefix(indexName, ".ds-") && strings.HasSuffix(indexName, "-000001") {
			dsName := strings.TrimSuffix(strings.TrimPrefix(indexName, ".ds-"), "-000001")
			if _, isDS := s.dataStreams[dsName]; isDS {
				idx, exists = s.indices[dsName]
			}
		}
		if exists {
			props := map[string]esast.FieldProperty{}
			if idx.RawMapping != nil {
				props = idx.RawMapping.Properties
			}
			mappings := map[string]any{"properties": props}
			if idx.RawMapping != nil && len(idx.RawMapping.Runtime) > 0 {
				mappings["runtime"] = idx.RawMapping.Runtime
			}
			if idx.RawMapping != nil && idx.RawMapping.Dynamic != nil {
				mappings["dynamic"] = idx.RawMapping.Dynamic
			}
			if idx.RawMapping != nil && idx.RawMapping.Routing != nil && idx.RawMapping.Routing.Required {
				mappings["_routing"] = map[string]any{"required": true}
			}
			out[indexName] = map[string]any{
				"mappings": mappings,
			}
		}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetFieldMapping(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	targets := s.resolveTargetIndices(rawIndex)
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
		augSchema := s.augmentSchemaWithRuntimeMappings(idxSchema, nil)
		mappingsOut := make(map[string]any)
		for esPath, fb := range augSchema.Fields {
			if matchesAnyGlob(esPath, fieldPatterns) {
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
				fieldDef := map[string]any{"type": esType}
				if fb.AliasTarget != "" {
					fieldDef["type"] = "alias"
					fieldDef["path"] = fb.AliasTarget
				}
				mappingsOut[esPath] = map[string]any{
					"full_name": esPath,
					"mapping": map[string]any{
						lastSeg: fieldDef,
					},
				}
			}
			if fb.KeywordCompanion != "" && fb.AliasTarget == "" {
				kwPath := esPath + ".keyword"
				if _, explicitKW := augSchema.Fields[kwPath]; !explicitKW && matchesAnyGlob(kwPath, fieldPatterns) {
					mappingsOut[kwPath] = map[string]any{
						"full_name": kwPath,
						"mapping": map[string]any{
							"keyword": map[string]any{"type": "keyword"},
						},
					}
				}
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
	if len(out) == 0 && rawIndex != "" && rawIndex != "_all" && !strings.ContainsAny(rawIndex, "*?,") && !strings.HasPrefix(rawIndex, "-") && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutMapping(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var spec esast.MappingSpec
	if err := json.Unmarshal(bodyBytes, &spec); err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}
	if len(spec.Properties) == 0 && len(spec.Runtime) == 0 {
		var envelope struct {
			Mappings *esast.MappingSpec `json:"mappings"`
		}
		if err := json.Unmarshal(bodyBytes, &envelope); err == nil && envelope.Mappings != nil {
			spec = *envelope.Mappings
		}
	}

	targets := s.resolveTargetIndices(rawIndex)
	s.mu.RLock()
	var validTargets []string
	var missingConcrete string
	for _, part := range strings.Split(rawIndex, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "-") || strings.Contains(part, "*") || part == "_all" {
			continue
		}
		if _, isAlias := s.aliases[part]; !isAlias {
			if _, isIdx := s.indices[part]; !isIdx && missingConcrete == "" {
				missingConcrete = part
			}
		}
	}
	for _, t := range targets {
		if _, exists := s.indices[t]; exists {
			validTargets = append(validTargets, t)
		}
	}
	s.mu.RUnlock()

	ignoreUnavailable := isTruthyBoolQueryParam(r, "ignore_unavailable")
	allowNoIndices := true
	if rawAllow := strings.TrimSpace(r.URL.Query().Get("allow_no_indices")); rawAllow != "" {
		allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
	}
	if missingConcrete != "" && !ignoreUnavailable {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", missingConcrete))
		return
	}
	if len(validTargets) == 0 {
		if hasExclusionOrWildcard(rawIndex) && allowNoIndices {
			writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
			return
		}
		missingName := rawIndex
		if missingConcrete != "" {
			missingName = missingConcrete
		}
		writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", missingName))
		return
	}

	// Validate mapping compatibility on all target indices before mutating any index.
	s.mu.RLock()
	for _, indexName := range validTargets {
		oldSchema := s.indices[indexName]
		var oldRaw *esast.MappingSpec
		if oldSchema != nil {
			oldRaw = oldSchema.RawMapping
		}
		if err := schema.ValidateMappingUpdateCompatibility(oldRaw, &spec); err != nil {
			s.mu.RUnlock()
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
	}
	s.mu.RUnlock()

	for _, indexName := range validTargets {
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
	}
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleGetAliases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	aliasFilter := r.PathValue("name")
	s.mu.RLock()
	defer s.mu.RUnlock()

	if aliasFilter != "" && aliasFilter != "*" && aliasFilter != "_all" {
		out := make(map[string]any)
		for alias, targets := range s.aliases {
			if matchMultiWildcardWithExclusions(aliasFilter, alias) {
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
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "alias_not_found_exception", "aliases ["+aliasFilter+"] missing")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	out := make(map[string]any)
	totalMatchedAliases := 0
	for idxName := range s.indices {
		idxAliases := make(map[string]any)
		for alias, targets := range s.aliases {
			for _, t := range targets {
				if t == idxName {
					idxAliases[alias] = s.getAliasMetaMapLocked(alias, idxName)
					totalMatchedAliases++
				}
			}
		}
		out[idxName] = map[string]any{"aliases": idxAliases}
	}
	if r.Method == http.MethodHead {
		if totalMatchedAliases == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetIndexAliases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawIndex := r.PathValue("index")
	targets, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex)
	if !ok {
		return
	}
	s.mu.RLock()
	out := make(map[string]any, len(targets))
	totalAliases := 0
	for _, indexName := range targets {
		if _, ok := s.indices[indexName]; !ok {
			continue
		}
		idxAliases := make(map[string]any)
		for alias, aliasTargets := range s.aliases {
			for _, t := range aliasTargets {
				if t == indexName {
					idxAliases[alias] = s.getAliasMetaMapLocked(alias, indexName)
					totalAliases++
				}
			}
		}
		out[indexName] = map[string]any{"aliases": idxAliases}
	}
	s.mu.RUnlock()
	if r.Method == http.MethodHead {
		if totalAliases == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
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
		var existingTargets []string
		for _, indexName := range targetIndices {
			if _, ok := s.indices[indexName]; ok {
				existingTargets = append(existingTargets, indexName)
			}
		}
		if len(existingTargets) == 0 {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return
		}
		if _, exists := s.indices[aliasName]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], an index exists with the same name as the alias", aliasName))
			return
		}
		if _, exists := s.dataStreams[aliasName]; exists {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], a data stream exists with the same name as the alias", aliasName))
			return
		}
		for _, indexName := range existingTargets {
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
		var existingTargets []string
		for _, indexName := range targetIndices {
			if _, ok := s.indices[indexName]; ok {
				existingTargets = append(existingTargets, indexName)
			}
		}
		if len(existingTargets) == 0 {
			s.mu.Unlock()
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return
		}
		removedAny := false
		aliasHasAnyTargetLocked := func(al string, idxs []string) bool {
			for _, t := range s.aliases[al] {
				for _, idx := range idxs {
					if t == idx {
						return true
					}
				}
			}
			return false
		}
		if strings.ContainsAny(aliasName, "*?,") || strings.HasPrefix(aliasName, "-") || aliasName == "_all" {
			var matchingAliases []string
			for al := range s.aliases {
				if matchMultiWildcardWithExclusions(aliasName, al) {
					matchingAliases = append(matchingAliases, al)
				}
			}
			for _, al := range matchingAliases {
				if aliasHasAnyTargetLocked(al, existingTargets) {
					removedAny = true
				}
				for _, indexName := range existingTargets {
					s.removeAliasTargetLocked(al, indexName)
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		} else {
			if aliasHasAnyTargetLocked(aliasName, existingTargets) {
				removedAny = true
			}
			for _, indexName := range existingTargets {
				s.removeAliasTargetLocked(aliasName, indexName)
			}
			modifiedAliases[aliasName] = append([]string(nil), s.aliases[aliasName]...)
		}
		s.mu.Unlock()
		if !removedAny {
			writeESError(w, http.StatusNotFound, "aliases_not_found_exception", "aliases ["+aliasName+"] missing")
			return
		}
		for al, targets := range modifiedAliases {
			s.persistAlias(r.Context(), al, targets)
		}
		s.queryCache.InvalidateAll()
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet, http.MethodHead:
		targetSet := make(map[string]bool, len(targetIndices))
		s.mu.RLock()
		for _, idx := range targetIndices {
			if _, ok := s.indices[idx]; ok {
				targetSet[idx] = true
			}
		}
		if len(targetSet) == 0 && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
			s.mu.RUnlock()
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
			return
		}
		out := make(map[string]any)
		for al, targets := range s.aliases {
			if aliasName != "" && aliasName != "*" && aliasName != "_all" && !matchMultiWildcardWithExclusions(aliasName, al) {
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
	var removedIndices []string
	var tablesToDrop []*schema.IndexSchema
	s.mu.Lock()
	expandIndexListLocked := func(rawList []string) []string {
		var out []string
		seen := make(map[string]bool)
		for _, pat := range rawList {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if pat == "*" || pat == "_all" {
				for idxName := range s.indices {
					if !seen[idxName] {
						seen[idxName] = true
						out = append(out, idxName)
					}
				}
				continue
			}
			if strings.ContainsAny(pat, "*?") {
				for idxName := range s.indices {
					if matchWildcardPattern(pat, idxName) && !seen[idxName] {
						seen[idxName] = true
						out = append(out, idxName)
					}
				}
				continue
			}
			if !seen[pat] {
				seen[pat] = true
				out = append(out, pat)
			}
		}
		return out
	}
	expandAliasListLocked := func(rawList []string) []string {
		var out []string
		seen := make(map[string]bool)
		for _, pat := range rawList {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if pat == "*" || pat == "_all" {
				for alName := range s.aliases {
					if !seen[alName] {
						seen[alName] = true
						out = append(out, alName)
					}
				}
				continue
			}
			if strings.ContainsAny(pat, "*?") {
				for alName := range s.aliases {
					if matchWildcardPattern(pat, alName) && !seen[alName] {
						seen[alName] = true
						out = append(out, alName)
					}
				}
				continue
			}
			if !seen[pat] {
				seen[pat] = true
				out = append(out, pat)
			}
		}
		return out
	}
	simulatedIndices := make(map[string]bool, len(s.indices))
	for k := range s.indices {
		simulatedIndices[k] = true
	}
	simulatedAliases := make(map[string]map[string]bool, len(s.aliases))
	for al, tList := range s.aliases {
		m := make(map[string]bool, len(tList))
		for _, t := range tList {
			m[t] = true
		}
		simulatedAliases[al] = m
	}
	writeIndexSetForAlias := make(map[string]string)
	for _, action := range payload.Actions {
		if len(action) == 0 {
			s.mu.Unlock()
			writeESError(w, http.StatusBadRequest, "parsing_exception", "action object must specify one of [add, remove, remove_index]")
			return
		}
		for actType := range action {
			if actType != "add" && actType != "remove" && actType != "remove_index" {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "parsing_exception", fmt.Sprintf("unknown alias action [%s]", actType))
				return
			}
		}
		if add, ok := action["add"]; ok {
			rawIndices := add.Indices
			if add.Index != "" {
				rawIndices = append(rawIndices, add.Index)
			}
			rawAliases := add.Aliases
			if add.Alias != "" {
				rawAliases = append(rawAliases, add.Alias)
			}
			if len(rawIndices) == 0 || len(rawAliases) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index and alias are required for [add];")
				return
			}
			for _, pat := range rawIndices {
				pat = strings.TrimSpace(pat)
				if pat != "" && !strings.ContainsAny(pat, "*?") && pat != "_all" && !simulatedIndices[pat] {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+pat+"]")
					return
				}
			}
			indices := expandIndexListLocked(rawIndices)
			if len(indices) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+strings.Join(rawIndices, ",")+"]")
				return
			}
			for _, al := range rawAliases {
				if simulatedIndices[al] {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], an index exists with the same name as the alias", al))
					return
				}
				if _, isDS := s.dataStreams[al]; isDS {
					s.mu.Unlock()
					writeESError(w, http.StatusBadRequest, "invalid_alias_name_exception", fmt.Sprintf("Invalid alias name [%s], a data stream exists with the same name as the alias", al))
					return
				}
				if add.IsWriteIndex != nil && *add.IsWriteIndex {
					if len(indices) > 1 {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Alias [%s] has more than one write index", al))
						return
					}
					if prevIdx, hadPrev := writeIndexSetForAlias[al]; hadPrev && prevIdx != indices[0] {
						s.mu.Unlock()
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Alias [%s] has more than one write index [%s, %s]", al, prevIdx, indices[0]))
						return
					}
					writeIndexSetForAlias[al] = indices[0]
				}
				if simulatedAliases[al] == nil {
					simulatedAliases[al] = make(map[string]bool)
				}
				for _, idx := range indices {
					simulatedAliases[al][idx] = true
				}
			}
		}
		if rem, ok := action["remove"]; ok {
			rawIndices := rem.Indices
			if rem.Index != "" {
				rawIndices = append(rawIndices, rem.Index)
			}
			rawAliases := rem.Aliases
			if rem.Alias != "" {
				rawAliases = append(rawAliases, rem.Alias)
			}
			if len(rawIndices) == 0 || len(rawAliases) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index and alias are required for [remove];")
				return
			}
			for _, pat := range rawIndices {
				pat = strings.TrimSpace(pat)
				if pat != "" && !strings.ContainsAny(pat, "*?") && pat != "_all" && !simulatedIndices[pat] {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+pat+"]")
					return
				}
			}
			indices := expandIndexListLocked(rawIndices)
			for _, al := range rawAliases {
				al = strings.TrimSpace(al)
				if al == "" || strings.ContainsAny(al, "*?") || al == "_all" {
					continue
				}
				foundOnTarget := false
				if idxMap := simulatedAliases[al]; idxMap != nil {
					for _, idx := range indices {
						if idxMap[idx] {
							foundOnTarget = true
							delete(idxMap, idx)
						}
					}
				}
				if !foundOnTarget {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "aliases_not_found_exception", fmt.Sprintf("aliases [%s] missing", al))
					return
				}
			}
		}
		if remIdx, ok := action["remove_index"]; ok {
			rawIndices := remIdx.Indices
			if remIdx.Index != "" {
				rawIndices = append(rawIndices, remIdx.Index)
			}
			if len(rawIndices) == 0 {
				s.mu.Unlock()
				writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is required for [remove_index];")
				return
			}
			for _, pat := range rawIndices {
				pat = strings.TrimSpace(pat)
				if pat != "" && !strings.ContainsAny(pat, "*?") && pat != "_all" && !simulatedIndices[pat] {
					s.mu.Unlock()
					writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+pat+"]")
					return
				}
			}
			for _, indexName := range expandIndexListLocked(rawIndices) {
				delete(simulatedIndices, indexName)
				for _, idxMap := range simulatedAliases {
					delete(idxMap, indexName)
				}
			}
		}
	}
	for _, action := range payload.Actions {
		if add, ok := action["add"]; ok {
			rawIndices := add.Indices
			if add.Index != "" {
				rawIndices = append(rawIndices, add.Index)
			}
			indices := expandIndexListLocked(rawIndices)
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
			rawIndices := rem.Indices
			if rem.Index != "" {
				rawIndices = append(rawIndices, rem.Index)
			}
			rawAliases := rem.Aliases
			if rem.Alias != "" {
				rawAliases = append(rawAliases, rem.Alias)
			}
			aliases := expandAliasListLocked(rawAliases)
			hasAllIdx := false
			for _, ri := range rawIndices {
				if ri == "*" || ri == "_all" {
					hasAllIdx = true
					break
				}
			}
			indices := expandIndexListLocked(rawIndices)
			for _, al := range aliases {
				if hasAllIdx {
					delete(s.aliases, al)
					delete(s.aliasMeta, al)
				} else {
					for _, idx := range indices {
						s.removeAliasTargetLocked(al, idx)
					}
				}
				modifiedAliases[al] = append([]string(nil), s.aliases[al]...)
			}
		}
		if remIdx, ok := action["remove_index"]; ok {
			rawIndices := remIdx.Indices
			if remIdx.Index != "" {
				rawIndices = append(rawIndices, remIdx.Index)
			}
			for _, indexName := range expandIndexListLocked(rawIndices) {
				if idx, exists := s.indices[indexName]; exists {
					tablesToDrop = append(tablesToDrop, idx)
				}
				delete(s.indices, indexName)
				delete(s.docRouting, indexName)
				delete(s.docVersions, indexName)
				delete(s.indexDefaultPipelines, indexName)
				delete(s.indexFinalPipelines, indexName)
				removedIndices = append(removedIndices, indexName)
				for alias := range s.aliases {
					s.removeAliasTargetLocked(alias, indexName)
					modifiedAliases[alias] = append([]string(nil), s.aliases[alias]...)
				}
			}
		}
	}
	s.mu.Unlock()
	for _, indexName := range removedIndices {
		s.deleteCatalogEntity(r.Context(), "index", indexName)
	}
	for al, targets := range modifiedAliases {
		s.persistAlias(r.Context(), al, targets)
	}
	for _, idx := range tablesToDrop {
		ddl := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`;", idx.DorisDB, idx.DorisTable)
		_ = s.backend.ExecDDL(r.Context(), ddl)
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
	if meta.IsWriteIndex != nil && *meta.IsWriteIndex && s.aliasMeta[alias] != nil {
		for otherIdx, otherMeta := range s.aliasMeta[alias] {
			if otherIdx != indexName && otherMeta.IsWriteIndex != nil && *otherMeta.IsWriteIndex {
				falseVal := false
				otherMeta.IsWriteIndex = &falseVal
				s.aliasMeta[alias][otherIdx] = otherMeta
			}
		}
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
	if srcVals := q["_source"]; len(srcVals) > 0 {
		srcParam := strings.TrimSpace(strings.Join(srcVals, ","))
		if strings.EqualFold(srcParam, "false") {
			sf = &esast.SourceFilter{Disabled: true}
		} else if strings.EqualFold(srcParam, "true") {
			sf = &esast.SourceFilter{Fetch: true}
		} else if srcParam != "" {
			sf = &esast.SourceFilter{Fetch: true, Includes: esast.StoredFieldsSlice(srcParam)}
		}
	}
	for _, key := range []string{"_source_includes", "_source_include"} {
		if incVals := q[key]; len(incVals) > 0 {
			if sf == nil {
				sf = &esast.SourceFilter{Fetch: true}
			}
			sf.Disabled = false
			sf.Fetch = true
			sf.Includes = append(sf.Includes, esast.StoredFieldsSlice(strings.Join(incVals, ","))...)
		}
	}
	for _, key := range []string{"_source_excludes", "_source_exclude"} {
		if excVals := q[key]; len(excVals) > 0 {
			if sf == nil {
				sf = &esast.SourceFilter{Fetch: true}
			}
			sf.Disabled = false
			sf.Fetch = true
			sf.Excludes = append(sf.Excludes, esast.StoredFieldsSlice(strings.Join(excVals, ","))...)
		}
	}
	return sf
}

func parseOCCParamsFromRequest(r *http.Request) (ifSeqNo *int64, ifPrimaryTerm *int64, version *int64, versionType string, errReason string) {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return nil, nil, nil, "", ""
	}
	q := r.URL.Query()
	if q.Has("if_seq_no") {
		raw := strings.TrimSpace(q.Get("if_seq_no"))
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 0 {
			return nil, nil, nil, "", fmt.Sprintf("invalid if_seq_no [%s]", raw)
		}
		ifSeqNo = &v
	}
	if q.Has("if_primary_term") {
		raw := strings.TrimSpace(q.Get("if_primary_term"))
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v <= 0 {
			return nil, nil, nil, "", fmt.Sprintf("invalid if_primary_term [%s]", raw)
		}
		ifPrimaryTerm = &v
	}
	if (ifSeqNo != nil) != (ifPrimaryTerm != nil) {
		return nil, nil, nil, "", "Validation Failed: 1: both if_seq_no and if_primary_term must be provided;"
	}
	if q.Has("version") {
		raw := strings.TrimSpace(q.Get("version"))
		if raw != "" {
			v, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || v <= 0 {
				return nil, nil, nil, "", fmt.Sprintf("invalid version [%s]", raw)
			}
			version = &v
		}
	}
	versionType = strings.ToLower(strings.TrimSpace(q.Get("version_type")))
	return ifSeqNo, ifPrimaryTerm, version, versionType, ""
}

func validateOCC(docID string, found bool, currentVer int64, ifSeqNo, ifPrimaryTerm, reqVersion *int64, versionType string) (assignedVersion int64, status int, errType string, errReason string) {
	if (ifSeqNo != nil) != (ifPrimaryTerm != nil) {
		return 0, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: both if_seq_no and if_primary_term must be provided;"
	}
	if (ifSeqNo != nil || ifPrimaryTerm != nil) && (reqVersion != nil || strings.TrimSpace(versionType) != "") {
		return 0, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: can't provide both seq_no/primary_term and version/version_type;"
	}
	if ifSeqNo != nil && ifPrimaryTerm != nil {
		if !found {
			return 0, http.StatusConflict, "version_conflict_engine_exception",
				fmt.Sprintf("[%s]: version conflict, required seqNo [%d], primary term [%d]. but no document was found", docID, *ifSeqNo, *ifPrimaryTerm)
		}
		if *ifPrimaryTerm != 1 || currentVer != *ifSeqNo {
			return 0, http.StatusConflict, "version_conflict_engine_exception",
				fmt.Sprintf("[%s]: version conflict, required seqNo [%d], primary term [%d]. current document has seqNo [%d] and primary term [1]", docID, *ifSeqNo, *ifPrimaryTerm, currentVer)
		}
	}
	vt := strings.ToLower(strings.TrimSpace(versionType))
	if reqVersion == nil && vt != "" {
		switch vt {
		case "internal":
		case "external", "external_gt", "external_gte":
			return 0, http.StatusBadRequest, "action_request_validation_exception",
				fmt.Sprintf("Validation Failed: 1: version must be set when version_type is [%s];", vt)
		default:
			return 0, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unknown version_type [%s]", versionType)
		}
	}
	if reqVersion != nil {
		switch vt {
		case "", "internal":
			if !found || currentVer != *reqVersion {
				return 0, http.StatusConflict, "version_conflict_engine_exception",
					fmt.Sprintf("[%s]: version conflict, current version [%d] is different than the one provided [%d]", docID, currentVer, *reqVersion)
			}
		case "external", "external_gt":
			if *reqVersion <= 0 {
				return 0, http.StatusBadRequest, "action_request_validation_exception", "version must be > 0 for external version_type"
			}
			if found && currentVer >= *reqVersion {
				return 0, http.StatusConflict, "version_conflict_engine_exception",
					fmt.Sprintf("[%s]: version conflict, current version [%d] is higher or equal to the one provided [%d]", docID, currentVer, *reqVersion)
			}
			return *reqVersion, 0, "", ""
		case "external_gte":
			if *reqVersion <= 0 {
				return 0, http.StatusBadRequest, "action_request_validation_exception", "version must be > 0 for external_gte version_type"
			}
			if found && currentVer > *reqVersion {
				return 0, http.StatusConflict, "version_conflict_engine_exception",
					fmt.Sprintf("[%s]: version conflict, current version [%d] is higher than the one provided [%d]", docID, currentVer, *reqVersion)
			}
			return *reqVersion, 0, "", ""
		default:
			return 0, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unknown version_type [%s]", versionType)
		}
	}
	return 0, 0, "", ""
}

func (s *Server) isTargetAliasOrDataStream(rawName string) bool {
	rawName = strings.TrimSpace(rawName)
	if rawName == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.aliases[rawName]) > 0 {
		return true
	}
	if _, ok := s.dataStreams[rawName]; ok {
		return true
	}
	return false
}

func validateReadDocVersionParams(rawVer, rawVerType, docID string, found bool, currentVer int64) (int, string, string) {
	vt := strings.ToLower(strings.TrimSpace(rawVerType))
	if rawVer == "" && vt == "" {
		return 0, "", ""
	}
	switch vt {
	case "", "internal", "external", "external_gt", "external_gte", "force":
	default:
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("unknown version_type [%s]", rawVerType)
	}
	if rawVer == "" {
		return 0, "", ""
	}
	reqVer, err := strconv.ParseInt(strings.TrimSpace(rawVer), 10, 64)
	if err != nil {
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Failed to parse value [%s] for [version]", rawVer)
	}
	if vt == "" || vt == "internal" {
		if reqVer <= 0 {
			return http.StatusBadRequest, "action_request_validation_exception",
				fmt.Sprintf("Validation Failed: 1: version must be > 0 for internal version_type, got [%d];", reqVer)
		}
	} else if reqVer < 0 {
		return http.StatusBadRequest, "action_request_validation_exception",
			fmt.Sprintf("Validation Failed: 1: version must be >= 0, got [%d];", reqVer)
	}
	if found && vt != "force" {
		conflict := false
		switch vt {
		case "external", "external_gt":
			conflict = reqVer <= currentVer
		case "external_gte":
			conflict = reqVer < currentVer
		default:
			conflict = currentVer != reqVer
		}
		if conflict {
			return http.StatusConflict, "version_conflict_engine_exception",
				fmt.Sprintf("[%s]: version conflict, current version [%d] is different than the one provided [%d]", docID, currentVer, reqVer)
		}
	}
	return 0, "", ""
}

func (s *Server) handlePutDoc(w http.ResponseWriter, r *http.Request) {
	rawReqIndex := r.PathValue("index")
	if isTruthyBoolQueryParam(r, "require_alias") && !s.isTargetAliasOrDataStream(rawReqIndex) {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such alias [%s] (require_alias=true)", rawReqIndex))
		return
	}
	indexName, aliasFilter, writeErr := s.resolveWriteIndexWithFilter(rawReqIndex)
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}
	ifSeqNo, ifPrimaryTerm, reqVer, verType, occParseErr := parseOCCParamsFromRequest(r)
	if occParseErr != "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", occParseErr)
		return
	}
	docID := r.PathValue("id")
	isCreate := strings.Contains(r.URL.Path, "/_create/") || strings.EqualFold(r.URL.Query().Get("op_type"), "create")
	rawDoc, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	pipeInputIdx := rawReqIndex
	if pipeInputIdx == "" {
		pipeInputIdx = indexName
	}
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	if reqRouting == "" {
		reqRouting = s.resolveEffectiveIndexRouting(pipeInputIdx, "")
	}
	docPayload, nextIndex, nextDocID, pipeRouting, dropped, pipeErr := s.applyEffectiveAndFinalPipelinesWithRouting(pipeInputIdx, docID, r.URL.Query().Get("pipeline"), "", reqRouting, json.RawMessage(rawDoc))
	if pipeErr != nil {
		writeESError(w, http.StatusBadRequest, ingestErrorType(pipeErr), pipeErr.Error())
		return
	}
	if nextDocID != "" {
		docID = nextDocID
	}
	if docID == "" {
		docID = esast.NextAutoID()
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
	effRawIndex := rawReqIndex
	if nextIndex != "" && nextIndex != pipeInputIdx {
		resolvedIdx, resolvedFilter, rErr := s.resolveWriteIndexWithFilter(nextIndex)
		if rErr != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
			return
		}
		indexName = resolvedIdx
		aliasFilter = resolvedFilter
		effRawIndex = nextIndex
	}
	effRouting := s.resolveEffectiveWriteRouting(effRawIndex, indexName, "", pipeRouting)

	roSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	if s.isRoutingRequired(roSchema) && effRouting == "" {
		writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
		return
	}
	var minVer int64
	var curVer int64
	var tombVer int64
	wasExisting := false
	_ = s.coalescer.FlushTable(r.Context(), roSchema.DorisTable)
	if existing, found, err := s.backend.GetDocByID(r.Context(), roSchema.DorisDB, roSchema.DorisTable, docID); err == nil && found {
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
			curVer = existing.Version
			minVer = existing.Version + 1
		}
	} else if existing != nil {
		tombVer = existing.Version
		minVer = existing.Version + 1
	}
	occFound := wasExisting
	if !occFound && strings.HasPrefix(strings.ToLower(strings.TrimSpace(verType)), "external") {
		if tombVer > 0 && tombVer < 1_000_000_000_000 {
			occFound = true
			curVer = tombVer
		} else if lastVer := s.getDocVersion(indexName, docID); lastVer > 0 && lastVer < 1_000_000_000_000 {
			occFound = true
			curVer = lastVer
		}
	}
	assignedVer, occStatus, occType, occReason := validateOCC(docID, occFound, curVer, ifSeqNo, ifPrimaryTerm, reqVer, verType)
	if occType != "" {
		writeESError(w, occStatus, occType, occReason)
		return
	}
	if aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, docPayload, aliasFilter) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("document [%s] does not match alias filter for write alias [%s]", docID, r.PathValue("index")))
		return
	}

	idxSchema := s.ensureWritableIndexSchemaWithDocs(r.Context(), indexName, []json.RawMessage{docPayload})
	nextVer := s.allocVersion(minVer)
	if minVer > 0 && minVer < 1_000_000_000_000 {
		nextVer = minVer
	}
	if assignedVer > 0 {
		nextVer = assignedVer
		_ = s.allocVersion(assignedVer)
	}
	shredded, err := schema.ShredDocument(idxSchema, docID, nextVer, false, docPayload)
	if err != nil {
		writeESError(w, http.StatusBadRequest, shredErrorType(err), err.Error())
		return
	}

	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	if err := s.streamLoad(r.Context(), idxSchema.DorisTable, append(shredded, '\n'), syncRefresh); err != nil {
		s.queryCache.InvalidateAll()
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}
	s.setDocRouting(indexName, docID, effRouting)
	s.setDocVersion(indexName, docID, nextVer)
	s.queryCache.InvalidateAll()

	status := http.StatusCreated
	result := "created"
	reportedVer := nextVer
	if assignedVer > 0 {
		reportedVer = assignedVer
	}
	if wasExisting {
		status = http.StatusOK
		result = "updated"
		reportedVer = nextVer
	}
	respPayload := map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      reportedVer,
		"result":        result,
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       nextVer,
		"_primary_term": 1,
	}
	if effRouting != "" {
		respPayload["_routing"] = effRouting
	}
	writeJSON(w, status, respPayload)
}

func (s *Server) handleHeadDoc(w http.ResponseWriter, r *http.Request) {
	rawReqIndex := r.PathValue("index")
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(rawReqIndex)
	if readErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	docID := r.PathValue("id")
	if status, _, _ := validateReadDocVersionParams(r.URL.Query().Get("version"), r.URL.Query().Get("version_type"), docID, false, 0); status != 0 {
		w.WriteHeader(status)
		return
	}
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	effRouting := s.resolveEffectiveReadRouting(rawReqIndex, indexName, reqRouting)
	if s.isRoutingRequired(idxSchema) && effRouting == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil || !found || !s.docMatchesRequestRouting(indexName, docID, effRouting) || (hit != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter)) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if status, _, _ := validateReadDocVersionParams(r.URL.Query().Get("version"), r.URL.Query().Get("version_type"), docID, true, hit.Version); status != 0 {
		w.WriteHeader(status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetSource(w http.ResponseWriter, r *http.Request) {
	rawReqIndex := r.PathValue("index")
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(rawReqIndex)
	if readErr != nil {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
		return
	}
	docID := r.PathValue("id")
	if status, errType, errReason := validateReadDocVersionParams(r.URL.Query().Get("version"), r.URL.Query().Get("version_type"), docID, false, 0); status != 0 {
		if r.Method == http.MethodHead {
			w.WriteHeader(status)
			return
		}
		writeESError(w, status, errType, errReason)
		return
	}
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	effRouting := s.resolveEffectiveReadRouting(rawReqIndex, indexName, reqRouting)
	if s.isRoutingRequired(idxSchema) && effRouting == "" {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
		return
	}
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if found && (!s.docMatchesRequestRouting(indexName, docID, effRouting) || (hit != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter))) {
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
	if status, errType, errReason := validateReadDocVersionParams(r.URL.Query().Get("version"), r.URL.Query().Get("version_type"), docID, true, hit.Version); status != 0 {
		if r.Method == http.MethodHead {
			w.WriteHeader(status)
			return
		}
		writeESError(w, status, errType, errReason)
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
	rawReqIndex := r.PathValue("index")
	indexName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(rawReqIndex)
	if readErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", readErr.Error())
		return
	}
	docID := r.PathValue("id")
	if status, errType, errReason := validateReadDocVersionParams(r.URL.Query().Get("version"), r.URL.Query().Get("version_type"), docID, false, 0); status != 0 {
		writeESError(w, status, errType, errReason)
		return
	}
	idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	effRouting := s.resolveEffectiveReadRouting(rawReqIndex, indexName, reqRouting)
	if s.isRoutingRequired(idxSchema) && effRouting == "" {
		writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
		return
	}
	_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)

	hit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if found && (!s.docMatchesRequestRouting(indexName, docID, effRouting) || (hit != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, hit.Source, aliasFilter))) {
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
	if status, errType, errReason := validateReadDocVersionParams(r.URL.Query().Get("version"), r.URL.Query().Get("version_type"), docID, true, hit.Version); status != 0 {
		writeESError(w, status, errType, errReason)
		return
	}
	urlSF := extractURLSourceFilter(r)
	urlStoredFields := esast.StoredFieldsSlice(strings.Join(r.URL.Query()["stored_fields"], ","))
	hasStoredNone := false
	var sfSpecs []esast.FieldRequestSpec
	for _, sf := range urlStoredFields {
		if sf == "_none_" {
			hasStoredNone = true
		} else {
			sfSpecs = append(sfSpecs, esast.FieldRequestSpec{Field: sf})
		}
	}
	resp := map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           hit.ID,
		"_version":      hit.Version,
		"_seq_no":       hit.Version,
		"_primary_term": 1,
		"found":         true,
	}
	if rt := s.getDocRouting(indexName, hit.ID); rt != "" {
		resp["_routing"] = rt
		hit.Routing = rt
	} else if reqRt := strings.TrimSpace(r.URL.Query().Get("routing")); reqRt != "" {
		resp["_routing"] = reqRt
		hit.Routing = reqRt
	}
	if (urlSF == nil || !urlSF.Disabled) && (!hasStoredNone || urlSF != nil) {
		resp["_source"] = filterSourceJSON(hit.Source, urlSF)
	}
	if len(sfSpecs) > 0 {
		if fm := extractHitFieldsMap(*hit, indexName, &esast.SearchRequest{Fields: sfSpecs}, idxSchema); len(fm) > 0 {
			resp["fields"] = fm
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func mergeMGetSourceFilter(base *esast.SourceFilter, incRaw, excRaw any) *esast.SourceFilter {
	inc := esast.StoredFieldsSlice(incRaw)
	exc := esast.StoredFieldsSlice(excRaw)
	if len(inc) == 0 && len(exc) == 0 {
		return base
	}
	var out esast.SourceFilter
	if base != nil {
		out = *base
	}
	out.Disabled = false
	out.Fetch = true
	out.Includes = append(append([]string(nil), out.Includes...), inc...)
	out.Excludes = append(append([]string(nil), out.Excludes...), exc...)
	return &out
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
	urlStoredFields := esast.StoredFieldsSlice(strings.Join(r.URL.Query()["stored_fields"], ","))
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	type mgetDocSpec struct {
		Index           string              `json:"_index"`
		ID              string              `json:"_id"`
		Routing         string              `json:"routing,omitempty"`
		MetaRouting     string              `json:"_routing,omitempty"`
		Version         *int64              `json:"version,omitempty"`
		MetaVersion     *int64              `json:"_version,omitempty"`
		VersionType     string              `json:"version_type,omitempty"`
		MetaVersionType string              `json:"_version_type,omitempty"`
		Source          *esast.SourceFilter `json:"_source,omitempty"`
		SourceIncludes  any                 `json:"_source_includes,omitempty"`
		SourceExcludes  any                 `json:"_source_excludes,omitempty"`
		StoredFields    any                 `json:"stored_fields,omitempty"`
	}
	var body struct {
		IDs            []string            `json:"ids"`
		Docs           []mgetDocSpec       `json:"docs"`
		Source         *esast.SourceFilter `json:"_source,omitempty"`
		SourceIncludes any                 `json:"_source_includes,omitempty"`
		SourceExcludes any                 `json:"_source_excludes,omitempty"`
		StoredFields   any                 `json:"stored_fields,omitempty"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return
		}
	}
	defaultSF := body.Source
	if defaultSF == nil {
		defaultSF = urlSF
	} else if !defaultSF.Disabled && len(defaultSF.Includes) == 0 && len(defaultSF.Excludes) == 0 && urlSF != nil && !urlSF.Disabled {
		cp := *defaultSF
		cp.Includes = urlSF.Includes
		cp.Excludes = urlSF.Excludes
		defaultSF = &cp
	}
	defaultSF = mergeMGetSourceFilter(defaultSF, body.SourceIncludes, body.SourceExcludes)
	defaultStoredFields := esast.StoredFieldsSlice(body.StoredFields)
	if len(defaultStoredFields) == 0 {
		defaultStoredFields = urlStoredFields
	}
	for _, id := range body.IDs {
		body.Docs = append(body.Docs, mgetDocSpec{Index: rawDefaultIndex, ID: id})
	}
	for _, spec := range body.Docs {
		rawIdx := strings.TrimSpace(rawDefaultIndex)
		if strings.TrimSpace(spec.Index) != "" {
			rawIdx = strings.TrimSpace(spec.Index)
		}
		if rawIdx == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
			return
		}
		if strings.TrimSpace(spec.ID) == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: id is missing;")
			return
		}
	}

	idsByIndex := make(map[string][]string)
	for _, spec := range body.Docs {
		rawIdx := rawDefaultIndex
		if spec.Index != "" {
			rawIdx = spec.Index
		}
		idxName, _, readErr := s.resolveReadDocIndexWithFilter(rawIdx)
		if readErr != nil {
			continue
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

	urlRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	docsOut := make([]map[string]any, 0, len(body.Docs))
	for _, spec := range body.Docs {
		rawIdx := rawDefaultIndex
		if spec.Index != "" {
			rawIdx = spec.Index
		}
		idxName, aliasFilter, readErr := s.resolveReadDocIndexWithFilter(rawIdx)
		if readErr != nil {
			docsOut = append(docsOut, map[string]any{
				"_index": rawIdx,
				"_type":  "_doc",
				"_id":    spec.ID,
				"error": map[string]any{
					"root_cause": []map[string]any{
						{"type": "illegal_argument_exception", "reason": readErr.Error()},
					},
					"type":   "illegal_argument_exception",
					"reason": readErr.Error(),
				},
			})
			continue
		}
		s.mu.RLock()
		_, indexKnown := s.indices[idxName]
		s.mu.RUnlock()
		if !indexKnown && len(prefetched[idxName]) == 0 {
			errReason := "no such index [" + idxName + "]"
			docsOut = append(docsOut, map[string]any{
				"_index": idxName,
				"_type":  "_doc",
				"_id":    spec.ID,
				"error": map[string]any{
					"root_cause": []map[string]any{
						{"type": "index_not_found_exception", "reason": errReason, "index": idxName},
					},
					"type":   "index_not_found_exception",
					"reason": errReason,
					"index":  idxName,
				},
			})
			continue
		}
		specRouting := strings.TrimSpace(spec.Routing)
		if specRouting == "" {
			specRouting = strings.TrimSpace(spec.MetaRouting)
		}
		if specRouting == "" {
			specRouting = urlRouting
		}
		effRouting := s.resolveEffectiveReadRouting(rawIdx, idxName, specRouting)
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
		if s.isRoutingRequired(idxSchema) && effRouting == "" {
			errReason := fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", idxName, spec.ID)
			docsOut = append(docsOut, map[string]any{
				"_index": idxName,
				"_type":  "_doc",
				"_id":    spec.ID,
				"error": map[string]any{
					"root_cause": []map[string]any{
						{"type": "routing_missing_exception", "reason": errReason, "index": idxName},
					},
					"type":   "routing_missing_exception",
					"reason": errReason,
					"index":  idxName,
				},
			})
			continue
		}
		hit, found := prefetched[idxName][spec.ID]
		if found && (!s.docMatchesRequestRouting(idxName, spec.ID, effRouting) || !s.docMatchesAliasFilter(r.Context(), idxName, spec.ID, hit.Source, aliasFilter)) {
			found = false
		}
		rawSpecVer := r.URL.Query().Get("version")
		if spec.Version != nil {
			rawSpecVer = strconv.FormatInt(*spec.Version, 10)
		} else if spec.MetaVersion != nil {
			rawSpecVer = strconv.FormatInt(*spec.MetaVersion, 10)
		}
		rawSpecVT := r.URL.Query().Get("version_type")
		if spec.VersionType != "" {
			rawSpecVT = spec.VersionType
		} else if spec.MetaVersionType != "" {
			rawSpecVT = spec.MetaVersionType
		}
		if vStatus, vErrType, vErrReason := validateReadDocVersionParams(rawSpecVer, rawSpecVT, spec.ID, found, hit.Version); vStatus != 0 {
			docsOut = append(docsOut, map[string]any{
				"_index": idxName,
				"_type":  "_doc",
				"_id":    spec.ID,
				"error": map[string]any{
					"root_cause": []map[string]any{
						{"type": vErrType, "reason": vErrReason, "index": idxName},
					},
					"type":   vErrType,
					"reason": vErrReason,
					"index":  idxName,
				},
			})
			continue
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
			"_index":        idxName,
			"_type":         "_doc",
			"_id":           hit.ID,
			"_version":      hit.Version,
			"_seq_no":       hit.Version,
			"_primary_term": 1,
			"found":         true,
		}
		if rt := s.getDocRouting(idxName, hit.ID); rt != "" {
			docItem["_routing"] = rt
			hit.Routing = rt
		} else if spec.Routing != "" {
			docItem["_routing"] = spec.Routing
			hit.Routing = spec.Routing
		} else if spec.MetaRouting != "" {
			docItem["_routing"] = spec.MetaRouting
			hit.Routing = spec.MetaRouting
		}
		effSF := spec.Source
		if effSF == nil {
			effSF = defaultSF
		} else if !effSF.Disabled && len(effSF.Includes) == 0 && len(effSF.Excludes) == 0 && defaultSF != nil && !defaultSF.Disabled {
			cp := *effSF
			cp.Includes = defaultSF.Includes
			cp.Excludes = defaultSF.Excludes
			effSF = &cp
		}
		effSF = mergeMGetSourceFilter(effSF, spec.SourceIncludes, spec.SourceExcludes)
		effStored := esast.StoredFieldsSlice(spec.StoredFields)
		if len(effStored) == 0 {
			effStored = defaultStoredFields
		}
		hasStoredNone := false
		var sfSpecs []esast.FieldRequestSpec
		for _, sf := range effStored {
			if sf == "_none_" {
				hasStoredNone = true
			} else {
				sfSpecs = append(sfSpecs, esast.FieldRequestSpec{Field: sf})
			}
		}
		if (effSF == nil || !effSF.Disabled) && (!hasStoredNone || effSF != nil) {
			docItem["_source"] = filterSourceJSON(hit.Source, effSF)
		}
		if len(sfSpecs) > 0 {
			idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
			if fm := extractHitFieldsMap(hit, idxName, &esast.SearchRequest{Fields: sfSpecs}, idxSchema); len(fm) > 0 {
				docItem["fields"] = fm
			}
		}
		docsOut = append(docsOut, docItem)
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": docsOut})
}

func (s *Server) handleDeleteDoc(w http.ResponseWriter, r *http.Request) {
	rawReqIndex := r.PathValue("index")
	indexName, aliasFilter, writeErr := s.resolveWriteIndexWithFilter(rawReqIndex)
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}
	ifSeqNo, ifPrimaryTerm, reqVer, verType, occParseErr := parseOCCParamsFromRequest(r)
	if occParseErr != "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", occParseErr)
		return
	}
	docID := r.PathValue("id")
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	effRouting := s.resolveEffectiveWriteRouting(rawReqIndex, indexName, reqRouting, "")
	roSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	if s.isRoutingRequired(roSchema) && effRouting == "" {
		writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
		return
	}

	_ = s.coalescer.FlushTable(r.Context(), roSchema.DorisTable)
	existingHit, found, err := s.backend.GetDocByID(r.Context(), roSchema.DorisDB, roSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	docFound := found && existingHit != nil &&
		s.docMatchesRequestRouting(indexName, docID, effRouting) &&
		(aliasFilter == nil || s.docMatchesAliasFilter(r.Context(), indexName, docID, existingHit.Source, aliasFilter))
	var curVer int64
	occFound := docFound
	if docFound {
		curVer = existingHit.Version
	} else if strings.HasPrefix(strings.ToLower(strings.TrimSpace(verType)), "external") {
		if existingHit != nil && existingHit.Version > 0 && existingHit.Version < 1_000_000_000_000 {
			occFound = true
			curVer = existingHit.Version
		} else if lastVer := s.getDocVersion(indexName, docID); lastVer > 0 && lastVer < 1_000_000_000_000 {
			occFound = true
			curVer = lastVer
		}
	}
	assignedVer, occStatus, occType, occReason := validateOCC(docID, occFound, curVer, ifSeqNo, ifPrimaryTerm, reqVer, verType)
	if occType != "" {
		writeESError(w, occStatus, occType, occReason)
		return
	}
	if !docFound {
		notFoundVer := int64(1)
		if assignedVer > 0 {
			notFoundVer = assignedVer
			_ = s.allocVersion(assignedVer)
			s.setDocVersion(indexName, docID, assignedVer)
		}
		notFoundResp := map[string]any{
			"_index":        indexName,
			"_type":         "_doc",
			"_id":           docID,
			"_version":      notFoundVer,
			"result":        "not_found",
			"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
			"_seq_no":       0,
			"_primary_term": 1,
		}
		if effRouting != "" {
			notFoundResp["_routing"] = effRouting
		}
		writeJSON(w, http.StatusNotFound, notFoundResp)
		return
	}

	idxSchema := s.ensureIndexSchema(r.Context(), indexName)
	nextVer := s.allocVersion(existingHit.Version + 1)
	if existingHit.Version > 0 && existingHit.Version < 1_000_000_000_000 {
		nextVer = existingHit.Version + 1
	}
	if assignedVer > 0 && assignedVer >= existingHit.Version {
		nextVer = assignedVer
		_ = s.allocVersion(assignedVer)
	}
	tombstoneVer := nextVer
	tombstone, err := schema.ShredDocument(idxSchema, docID, tombstoneVer, true, nil)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "internal_exception", err.Error())
		return
	}
	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	if err := s.streamLoad(r.Context(), idxSchema.DorisTable, append(tombstone, '\n'), syncRefresh); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}
	s.setDocRouting(indexName, docID, "")
	s.setDocVersion(indexName, docID, tombstoneVer)
	s.queryCache.InvalidateAll()
	delResp := map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      nextVer,
		"result":        "deleted",
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       nextVer,
		"_primary_term": 1,
	}
	if effRouting != "" {
		delResp["_routing"] = effRouting
	}
	writeJSON(w, http.StatusOK, delResp)
}

func (s *Server) handleUpdateDoc(w http.ResponseWriter, r *http.Request) {
	rawReqIndex := r.PathValue("index")
	if isTruthyBoolQueryParam(r, "require_alias") && !s.isTargetAliasOrDataStream(rawReqIndex) {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such alias [%s] (require_alias=true)", rawReqIndex))
		return
	}
	indexName, aliasFilter, writeErr := s.resolveWriteIndexWithFilter(rawReqIndex)
	if writeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", writeErr.Error())
		return
	}
	ifSeqNo, ifPrimaryTerm, reqVer, verType, occParseErr := parseOCCParamsFromRequest(r)
	if occParseErr != "" {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", occParseErr)
		return
	}
	if strings.HasPrefix(verType, "external") {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
			fmt.Sprintf("Validation Failed: 1: version types [external, external_gt, external_gte] are not supported by update, got [%s];", verType))
		return
	}
	docID := r.PathValue("id")
	reqRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	var updReq painless.UpdateRequest
	if err := json.Unmarshal(bodyBytes, &updReq); err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}
	if qDocAsUpsert := r.URL.Query().Get("doc_as_upsert"); qDocAsUpsert != "" {
		if b, err := strconv.ParseBool(qDocAsUpsert); err == nil {
			updReq.DocAsUpsert = b
		}
	}
	if qDetectNoop := r.URL.Query().Get("detect_noop"); qDetectNoop != "" {
		if b, err := strconv.ParseBool(qDetectNoop); err == nil {
			updReq.DetectNoop = &b
		}
	}
	if updReq.Doc == nil && (updReq.Script == nil || strings.TrimSpace(updReq.Script.Source) == "") {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: script or doc is missing;")
		return
	}
	var updBodyMeta struct {
		Source         *esast.SourceFilter `json:"_source,omitempty"`
		SourceIncludes any                 `json:"_source_includes,omitempty"`
		SourceExcludes any                 `json:"_source_excludes,omitempty"`
	}
	_ = json.Unmarshal(bodyBytes, &updBodyMeta)
	effUpdateSF := updBodyMeta.Source
	if effUpdateSF == nil {
		effUpdateSF = extractURLSourceFilter(r)
	}
	effUpdateSF = mergeMGetSourceFilter(effUpdateSF, updBodyMeta.SourceIncludes, updBodyMeta.SourceExcludes)

	roSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
	initEffRouting := s.resolveEffectiveWriteRouting(rawReqIndex, indexName, reqRouting, "")
	if s.isRoutingRequired(roSchema) && initEffRouting == "" && (updReq.Script == nil || !strings.Contains(updReq.Script.Source, "_routing")) {
		writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
		return
	}
	_ = s.coalescer.FlushTable(r.Context(), roSchema.DorisTable)
	existingHit, found, err := s.backend.GetDocByID(r.Context(), roSchema.DorisDB, roSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if found && initEffRouting != "" && !s.docMatchesRequestRouting(indexName, docID, initEffRouting) {
		found = false
	}
	if found && aliasFilter != nil && (existingHit == nil || !s.docMatchesAliasFilter(r.Context(), indexName, docID, existingHit.Source, aliasFilter)) {
		if updReq.DocAsUpsert || updReq.Upsert != nil || updReq.ScriptedUpsert {
			writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document belongs to another alias partition", docID))
			return
		}
		writeESError(w, http.StatusNotFound, "document_missing_exception", fmt.Sprintf("[%s]: document missing", docID))
		return
	}
	var curVer int64
	if found && existingHit != nil {
		curVer = existingHit.Version
	}
	assignedVer, occStatus, occType, occReason := validateOCC(docID, found, curVer, ifSeqNo, ifPrimaryTerm, reqVer, verType)
	if occType != "" {
		writeESError(w, occStatus, occType, occReason)
		return
	}
	if !found && (!updReq.DocAsUpsert || updReq.Doc == nil) && updReq.Upsert == nil && !updReq.ScriptedUpsert {
		writeESError(w, http.StatusNotFound, "document_missing_exception", fmt.Sprintf("[%s]: document missing", docID))
		return
	}

	var baseSource json.RawMessage
	var minFloor int64
	if found {
		baseSource = existingHit.Source
		minFloor = existingHit.Version + 1
	} else {
		if existingHit != nil && existingHit.Version+1 > minFloor {
			minFloor = existingHit.Version + 1
		}
		if delVer := s.getDocVersion(indexName, docID); delVer > 0 && delVer < 1_000_000_000_000 && delVer+1 > minFloor {
			minFloor = delVer + 1
		}
	}
	updReq.MetaID = docID
	updReq.MetaIndex = indexName
	updReq.MetaRouting = initEffRouting
	if updReq.MetaRouting == "" && found && !s.isRoutingRequired(roSchema) {
		updReq.MetaRouting = s.getDocRouting(indexName, docID)
	}
	if found && existingHit != nil {
		updReq.MetaVersion = existingHit.Version
	} else {
		updReq.MetaVersion = 1
	}
	mutatedSource, opResult, err := painless.ApplyUpdateWithResult(baseSource, &updReq, found)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
		return
	}
	if !found && opResult == "deleted" {
		opResult = "noop"
		mutatedSource = nil
	}
	if found && opResult == "created" {
		writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document already exists", docID))
		return
	}

	var nextVersion int64
	var pipeRouting string
	scriptRouting := strings.TrimSpace(updReq.MetaRouting)
	effRouting := s.resolveEffectiveWriteRouting(rawReqIndex, indexName, scriptRouting, "")
	var prePiped bool
	var prePipedDoc json.RawMessage
	var preNextIndex, preNextDocID string
	var preDropped bool
	if opResult == "noop" && len(mutatedSource) > 0 {
		pipeInputIdx := rawReqIndex
		if pipeInputIdx == "" {
			pipeInputIdx = indexName
		}
		reqPipe := r.URL.Query().Get("pipeline")
		if s.resolveEffectivePipeline(pipeInputIdx, reqPipe, "") != "" || s.resolveFinalPipeline(pipeInputIdx) != "" {
			var pipeErr error
			prePipedDoc, preNextIndex, preNextDocID, pipeRouting, preDropped, pipeErr = s.applyEffectiveAndFinalPipelinesWithRouting(pipeInputIdx, docID, reqPipe, "", scriptRouting, mutatedSource)
			if pipeErr != nil {
				writeESError(w, http.StatusBadRequest, ingestErrorType(pipeErr), pipeErr.Error())
				return
			}
			prePiped = true
			if preDropped ||
				(preNextIndex != "" && preNextIndex != pipeInputIdx && preNextIndex != indexName) ||
				(preNextDocID != "" && preNextDocID != docID) ||
				(pipeRouting != scriptRouting) ||
				!jsonStructurallyEqual(mutatedSource, prePipedDoc) {
				if found {
					opResult = "updated"
				} else {
					opResult = "created"
				}
			}
		}
	}
	if opResult != "noop" {
		isDelete := opResult == "deleted"
		origIndex := indexName
		origDocID := docID
		effRawIndex := rawReqIndex
		hadPipeRouting := false
		if !isDelete && len(mutatedSource) > 0 {
			hadPipeRouting = true
			pipeInputIdx := rawReqIndex
			if pipeInputIdx == "" {
				pipeInputIdx = indexName
			}
			var pipedDoc json.RawMessage
			var nextIndex, nextDocID string
			var dropped bool
			if prePiped {
				pipedDoc, nextIndex, nextDocID, dropped = prePipedDoc, preNextIndex, preNextDocID, preDropped
			} else {
				var pipeErr error
				pipedDoc, nextIndex, nextDocID, pipeRouting, dropped, pipeErr = s.applyEffectiveAndFinalPipelinesWithRouting(pipeInputIdx, docID, r.URL.Query().Get("pipeline"), "", scriptRouting, mutatedSource)
				if pipeErr != nil {
					writeESError(w, http.StatusBadRequest, ingestErrorType(pipeErr), pipeErr.Error())
					return
				}
			}
			if dropped {
				dropVer := int64(1)
				if found && existingHit.Version > 0 {
					dropVer = existingHit.Version
				}
				dropResp := map[string]any{
					"_index":        indexName,
					"_type":         "_doc",
					"_id":           docID,
					"_version":      dropVer,
					"result":        "noop",
					"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
					"_seq_no":       dropVer,
					"_primary_term": 1,
				}
				if effUpdateSF != nil && !effUpdateSF.Disabled {
					if found && len(existingHit.Source) > 0 {
						dropResp["get"] = map[string]any{
							"found":   true,
							"_source": filterSourceJSON(existingHit.Source, effUpdateSF),
						}
					} else {
						dropResp["get"] = map[string]any{
							"found": false,
						}
					}
				}
				writeJSON(w, http.StatusOK, dropResp)
				return
			}
			if nextDocID != "" {
				docID = nextDocID
			}
			if nextIndex != "" && nextIndex != pipeInputIdx {
				resolvedIdx, resolvedFilter, rErr := s.resolveWriteIndexWithFilter(nextIndex)
				if rErr != nil {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
					return
				}
				indexName = resolvedIdx
				aliasFilter = resolvedFilter
				effRawIndex = nextIndex
			}
			if docID != origDocID || indexName != origIndex {
				destSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
				_ = s.coalescer.FlushTable(r.Context(), destSchema.DorisTable)
				if destHit, destFound, dErr := s.backend.GetDocByID(r.Context(), destSchema.DorisDB, destSchema.DorisTable, docID); dErr == nil && destHit != nil {
					if destFound && aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, destHit.Source, aliasFilter) {
						writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document belongs to another alias partition", docID))
						return
					}
					if destHit.Version+1 > minFloor {
						minFloor = destHit.Version + 1
					}
				}
				if delVer := s.getDocVersion(indexName, docID); delVer > 0 && delVer < 1_000_000_000_000 && delVer+1 > minFloor {
					minFloor = delVer + 1
				}
			}
			mutatedSource = pipedDoc
		}
		if hadPipeRouting {
			effRouting = s.resolveEffectiveWriteRouting(effRawIndex, indexName, "", pipeRouting)
		} else {
			effRouting = s.resolveEffectiveWriteRouting(effRawIndex, indexName, scriptRouting, "")
		}
		if !isDelete && aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), indexName, docID, mutatedSource, aliasFilter) {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("updated document [%s] does not match alias filter for [%s]", docID, r.PathValue("index")))
			return
		}
		nextVersion = s.allocVersion(minFloor)
		if minFloor > 0 && minFloor < 1_000_000_000_000 {
			nextVersion = minFloor
		}
		if assignedVer > 0 {
			nextVersion = assignedVer
			_ = s.allocVersion(assignedVer)
		}
		var sampleDocs []json.RawMessage
		if !isDelete && len(mutatedSource) > 0 {
			sampleDocs = []json.RawMessage{mutatedSource}
		}
		idxSchema := s.ensureWritableIndexSchemaWithDocs(r.Context(), indexName, sampleDocs)
		if s.isRoutingRequired(idxSchema) && effRouting == "" {
			writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
			return
		}
		if effRouting == "" && found && updReq.Script == nil && !hadPipeRouting {
			effRouting = s.getDocRouting(origIndex, origDocID)
		}
		shredded, err := schema.ShredDocument(idxSchema, docID, nextVersion, isDelete, mutatedSource)
		if err != nil {
			writeESError(w, http.StatusBadRequest, shredErrorType(err), err.Error())
			return
		}
		syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
		payload := append(shredded, '\n')
		var clearOrigRouting bool
		var origTombVer int64
		if found && !isDelete && (docID != origDocID || indexName != origIndex) {
			origSchema := s.ensureIndexSchema(r.Context(), origIndex)
			origTombVer = s.allocVersion(existingHit.Version + 1)
			if existingHit.Version > 0 && existingHit.Version < 1_000_000_000_000 {
				origTombVer = existingHit.Version + 1
			}
			if tombShredded, tErr := schema.ShredDocument(origSchema, origDocID, origTombVer, true, nil); tErr == nil {
				if origSchema.DorisTable == idxSchema.DorisTable {
					payload = append(append(tombShredded, '\n'), payload...)
				} else if err := s.streamLoad(r.Context(), origSchema.DorisTable, append(tombShredded, '\n'), syncRefresh); err != nil {
					s.queryCache.InvalidateAll()
					writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
					return
				}
			}
			clearOrigRouting = true
		}
		if err := s.streamLoad(r.Context(), idxSchema.DorisTable, payload, syncRefresh); err != nil {
			s.queryCache.InvalidateAll()
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
		if clearOrigRouting {
			s.setDocRouting(origIndex, origDocID, "")
			s.setDocVersion(origIndex, origDocID, origTombVer)
		}
		if isDelete {
			s.setDocRouting(indexName, docID, "")
		} else {
			s.setDocRouting(indexName, docID, effRouting)
		}
		s.setDocVersion(indexName, docID, nextVersion)
		s.queryCache.InvalidateAll()
	} else {
		if s.isRoutingRequired(roSchema) && effRouting == "" {
			writeESError(w, http.StatusBadRequest, "routing_missing_exception", fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", indexName, docID))
			return
		}
		if effRouting == "" && found {
			effRouting = s.getDocRouting(indexName, docID)
		}
	}

	status := http.StatusOK
	if opResult == "created" {
		status = http.StatusCreated
	}
	reportedVer := nextVersion
	if opResult == "noop" {
		if found && existingHit != nil && existingHit.Version > 0 {
			reportedVer = existingHit.Version
		} else {
			reportedVer = 1
		}
	}
	respPayload := map[string]any{
		"_index":        indexName,
		"_type":         "_doc",
		"_id":           docID,
		"_version":      reportedVer,
		"result":        opResult,
		"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"_seq_no":       reportedVer,
		"_primary_term": 1,
	}
	if effRouting != "" {
		respPayload["_routing"] = effRouting
	}
	if effUpdateSF != nil && !effUpdateSF.Disabled && opResult != "deleted" {
		if (found || opResult == "created" || opResult == "updated") && len(mutatedSource) > 0 {
			respPayload["get"] = map[string]any{
				"found":   true,
				"_source": filterSourceJSON(mutatedSource, effUpdateSF),
			}
		} else if !found && opResult == "noop" {
			respPayload["get"] = map[string]any{
				"found": false,
			}
		}
	}
	writeJSON(w, status, respPayload)
}

type sliceSpec struct {
	ID  *int `json:"id,omitempty"`
	Max *int `json:"max,omitempty"`
}

func parseAndValidateSliceParams(r *http.Request, bodySlices any, bodySlice *sliceSpec) (int, int, bool, int, string, string) {
	if slicesQuery := strings.TrimSpace(r.URL.Query().Get("slices")); slicesQuery != "" {
		if !strings.EqualFold(slicesQuery, "auto") {
			n, err := strconv.Atoi(slicesQuery)
			if err != nil || n <= 0 {
				return 0, 0, false, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("slices must be a positive integer or \"auto\" but was [%s]", slicesQuery)
			}
		}
	} else if bodySlices != nil {
		switch v := bodySlices.(type) {
		case string:
			s := strings.TrimSpace(v)
			if !strings.EqualFold(s, "auto") {
				n, err := strconv.Atoi(s)
				if err != nil || n <= 0 {
					return 0, 0, false, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("slices must be a positive integer or \"auto\" but was [%s]", s)
				}
			}
		default:
			fv, ok := toFloat64(v)
			if !ok || fv <= 0 || fv != math.Trunc(fv) {
				return 0, 0, false, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("slices must be a positive integer or \"auto\" but was [%v]", v)
			}
		}
	}
	if bodySlice != nil {
		if bodySlice.ID == nil || bodySlice.Max == nil {
			return 0, 0, false, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: slice id and max are required;"
		}
		id := *bodySlice.ID
		maxVal := *bodySlice.Max
		if id < 0 || maxVal <= 1 || id >= maxVal {
			return 0, 0, false, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("invalid slice: id [%d] must be >= 0 and < max [%d] (with max > 1)", id, maxVal)
		}
		return id, maxVal, true, 0, "", ""
	}
	return 0, 0, false, 0, "", ""
}

func docMatchesSlice(docID string, sliceID, sliceMax int) bool {
	if sliceMax <= 1 {
		return sliceID == 0
	}
	var h uint32 = 2166136261
	for i := 0; i < len(docID); i++ {
		h ^= uint32(docID[i])
		h *= 16777619
	}
	return int64(h)%int64(sliceMax) == int64(sliceID)
}

func (s *Server) handleUpdateByQuery(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rawIndex := r.PathValue("index")
	ew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
	if (ew == "none" || ew == "closed") && (strings.ContainsAny(rawIndex, "*?") || rawIndex == "_all") {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)
	if len(targets) == 0 && strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("allow_no_indices")), "false") {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	if len(targets) == 0 && !hasExclusionOrWildcard(rawIndex) {
		targets = []string{s.resolveIndexName(rawIndex)}
	}

	var body struct {
		MaxDocs           *int                 `json:"max_docs,omitempty"`
		Size              *int                 `json:"size,omitempty"`
		Conflicts         string               `json:"conflicts,omitempty"`
		RequestsPerSecond any                  `json:"requests_per_second,omitempty"`
		Slices            any                  `json:"slices,omitempty"`
		Slice             *sliceSpec           `json:"slice,omitempty"`
		Pipeline          string               `json:"pipeline,omitempty"`
		Query             *esast.Query         `json:"query,omitempty"`
		Script            *painless.ScriptSpec `json:"script,omitempty"`
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
	sliceID, sliceMax, hasSlice, sliceErrStatus, sliceErrType, sliceErrReason := parseAndValidateSliceParams(r, body.Slices, body.Slice)
	if sliceErrStatus != 0 {
		writeESError(w, sliceErrStatus, sliceErrType, sliceErrReason)
		return
	}
	if body.Query == nil && r.URL.Query().Get("q") != "" {
		tmpReq := esast.SearchRequest{}
		applyURISearchParams(r, &tmpReq)
		body.Query = tmpReq.Query
	}

	effConflicts := strings.TrimSpace(r.URL.Query().Get("conflicts"))
	if effConflicts == "" {
		effConflicts = strings.TrimSpace(body.Conflicts)
	}
	if effConflicts != "" && !strings.EqualFold(effConflicts, "abort") && !strings.EqualFold(effConflicts, "proceed") {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Invalid conflicts value [%s], must be [abort] or [proceed]", effConflicts))
		return
	}
	reqsPerSec := float64(-1)
	if rpsQuery := strings.TrimSpace(r.URL.Query().Get("requests_per_second")); rpsQuery != "" {
		if !strings.EqualFold(rpsQuery, "infinity") {
			if v, err := strconv.ParseFloat(rpsQuery, 64); err == nil {
				if v == 0 {
					reqsPerSec = -1
				} else {
					reqsPerSec = v
				}
			}
		}
	} else if body.RequestsPerSecond != nil {
		if fv, ok := toFloat64(body.RequestsPerSecond); ok {
			if fv == 0 {
				reqsPerSec = -1
			} else {
				reqsPerSec = fv
			}
		}
	}

	maxDocs := 0
	if body.MaxDocs != nil && *body.MaxDocs > 0 {
		maxDocs = *body.MaxDocs
	} else if body.Size != nil && *body.Size > 0 {
		maxDocs = *body.Size
	}
	if qMax := r.URL.Query().Get("max_docs"); qMax != "" {
		if parsed, err := strconv.Atoi(qMax); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	} else if qSize := r.URL.Query().Get("size"); qSize != "" {
		if parsed, err := strconv.Atoi(qSize); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	}

	totalMatched := 0
	totalUpdated := 0
	totalDeleted := 0
	totalNoops := 0
	versionConflicts := 0
	batches := 0
	conflictsProceed := strings.EqualFold(effConflicts, "proceed")
	if body.Query != nil && hasTermsLookupInQuery(body.Query) {
		s.resolveTermsLookupsInQuery(r.Context(), body.Query)
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(r.Context(), aliasFilters)

	for _, indexName := range targets {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		var searchAfter []any
		effQuery := combineQueryWithAliasFilter(body.Query, aliasFilters[indexName])
		hasRuntimeQueryScript := queryHasRuntimeScript(effQuery)
		urlRouting := strings.TrimSpace(r.URL.Query().Get("routing"))
		effSearchRouting := s.resolveEffectiveReadRouting(rawIndex, indexName, urlRouting)

		batchLimit := 1000
		if qScrollSize := r.URL.Query().Get("scroll_size"); qScrollSize != "" {
			if parsed, err := strconv.Atoi(qScrollSize); err == nil && parsed > 0 {
				batchLimit = parsed
			}
		}

		for {
			fetchSize := batchLimit
			if !hasRuntimeQueryScript && !hasSlice && effSearchRouting == "" && maxDocs > 0 && totalMatched+fetchSize > maxDocs {
				fetchSize = maxDocs - totalMatched
			}
			if fetchSize <= 0 || (maxDocs > 0 && totalMatched >= maxDocs) {
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
				s.mu.RLock()
				_, indexKnown := s.indices[indexName]
				s.mu.RUnlock()
				if !indexKnown {
					break
				}
				writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
				return
			}
			if len(hits) == 0 {
				break
			}
			batches++

			type pendingUpdate struct {
				id                string
				oldID             string
				oldIndex          string
				targetIndex       string
				targetAliasFilter *esast.Query
				version           int64
				isDel             bool
				source            json.RawMessage
				routing           string
			}
			var pending []pendingUpdate
			sampleDocsByIdx := make(map[string][]json.RawMessage)
			candIDsByIdx := make(map[string][]string)
			for _, h := range hits {
				if maxDocs > 0 && totalMatched >= maxDocs {
					break
				}
				if hasSlice && !docMatchesSlice(h.ID, sliceID, sliceMax) {
					continue
				}
				if effSearchRouting != "" && !s.docMatchesRequestRouting(indexName, h.ID, effSearchRouting) {
					continue
				}
				if hasRuntimeQueryScript {
					var rawMap map[string]any
					dec := json.NewDecoder(bytes.NewReader(h.Source))
					dec.UseNumber()
					_ = dec.Decode(&rawMap)
					if rawMap == nil {
						rawMap = make(map[string]any)
					}
					rawMap["__meta_id"] = h.ID
					if !evalQueryScriptFilterOnDocWithScore(idxSchema, rawMap, effQuery, h.Score) {
						continue
					}
				}
				totalMatched++
				docInitRouting := s.getDocRouting(indexName, h.ID)
				if docInitRouting == "" && !strings.Contains(urlRouting, ",") {
					docInitRouting = urlRouting
				}
				updItem := &painless.UpdateRequest{
					Script:      body.Script,
					MetaID:      h.ID,
					MetaIndex:   indexName,
					MetaRouting: docInitRouting,
					MetaVersion: h.Version,
				}
				mutated, opRes, err := painless.ApplyUpdateWithResult(h.Source, updItem, true)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
					return
				}
				if opRes == "created" {
					if conflictsProceed {
						versionConflicts++
						continue
					}
					writeESError(w, http.StatusConflict, "version_conflict_engine_exception", fmt.Sprintf("[%s]: version conflict, document already exists", h.ID))
					return
				}
				isDel := opRes == "deleted"
				targetDocID := h.ID
				targetIdx := indexName
				effRawIdx := rawIndex
				targetAliasFilter := aliasFilters[indexName]
				initRouting := strings.TrimSpace(updItem.MetaRouting)
				pipeRouting := initRouting
				hadPipe := false
				if !isDel && len(mutated) > 0 {
					pipeInputIdx := indexName
					if len(targets) == 1 && rawIndex != "" && !hasExclusionOrWildcard(rawIndex) {
						pipeInputIdx = rawIndex
					}
					reqPipe := r.URL.Query().Get("pipeline")
					if opRes != "noop" || s.resolveEffectivePipeline(pipeInputIdx, reqPipe, body.Pipeline) != "" || s.resolveFinalPipeline(pipeInputIdx) != "" {
						piped, nextIdx, nextID, nextRouting, dropped, pipeErr := s.applyEffectiveAndFinalPipelinesWithRouting(pipeInputIdx, h.ID, reqPipe, body.Pipeline, initRouting, mutated)
						if pipeErr != nil {
							writeESError(w, http.StatusBadRequest, ingestErrorType(pipeErr), pipeErr.Error())
							return
						}
						if dropped {
							totalNoops++
							continue
						}
						hadPipe = true
						if opRes == "noop" &&
							((nextIdx != "" && nextIdx != pipeInputIdx && nextIdx != indexName) ||
								(nextID != "" && nextID != h.ID) ||
								(nextRouting != initRouting) ||
								!jsonStructurallyEqual(mutated, piped)) {
							opRes = "updated"
						}
						if nextID != "" {
							targetDocID = nextID
						}
						pipeRouting = nextRouting
						if nextIdx != "" && nextIdx != pipeInputIdx {
							resolvedIdx, resolvedFilter, rErr := s.resolveWriteIndexWithFilter(nextIdx)
							if rErr != nil {
								writeESError(w, http.StatusBadRequest, "illegal_argument_exception", rErr.Error())
								return
							}
							targetIdx = resolvedIdx
							targetAliasFilter = resolvedFilter
							effRawIdx = nextIdx
						}
						mutated = piped
					}
				}
				if opRes == "noop" {
					totalNoops++
					continue
				}
				effRouting := s.resolveEffectiveWriteRouting(effRawIdx, targetIdx, "", pipeRouting)
				if effRouting == "" && !isDel && body.Script == nil && !hadPipe {
					effRouting = s.getDocRouting(indexName, h.ID)
				}
				if !isDel && targetAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), targetIdx, targetDocID, mutated, targetAliasFilter) {
					if conflictsProceed {
						versionConflicts++
						continue
					}
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("updated document [%s] does not match alias filter for [%s]", targetDocID, r.PathValue("index")))
					return
				}
				if !isDel && len(mutated) > 0 {
					sampleDocsByIdx[targetIdx] = append(sampleDocsByIdx[targetIdx], mutated)
				}
				oldID := ""
				oldIndex := ""
				if !isDel && (targetDocID != h.ID || targetIdx != indexName) {
					oldID = h.ID
					oldIndex = indexName
					candIDsByIdx[targetIdx] = append(candIDsByIdx[targetIdx], targetDocID)
				}
				pending = append(pending, pendingUpdate{
					id:                targetDocID,
					oldID:             oldID,
					oldIndex:          oldIndex,
					targetIndex:       targetIdx,
					targetAliasFilter: targetAliasFilter,
					version:           h.Version,
					isDel:             isDel,
					source:            mutated,
					routing:           effRouting,
				})
			}

			if len(pending) > 0 {
				idxSchema = s.ensureIndexSchema(r.Context(), indexName)
				schemasByIdx := map[string]*schema.IndexSchema{indexName: idxSchema}
				for tIdx, sDocs := range sampleDocsByIdx {
					sch := s.ensureWritableIndexSchemaWithDocs(r.Context(), tIdx, sDocs)
					schemasByIdx[tIdx] = sch
					if tIdx == indexName {
						idxSchema = sch
					}
				}
				existingByIdx := make(map[string]map[string]HitRow, len(candIDsByIdx))
				for tIdx, ids := range candIDsByIdx {
					if len(ids) == 0 {
						continue
					}
					sch := s.getOrCompileReadOnlySchema(r.Context(), tIdx)
					_ = s.coalescer.FlushTable(r.Context(), sch.DorisTable)
					ex, _ := s.backend.GetDocsByIDs(r.Context(), sch.DorisDB, sch.DorisTable, ids)
					existingByIdx[tIdx] = ex
				}

				batchBufByTable := make(map[string]*bytes.Buffer)
				var tableOrder []string
				getTableBuf := func(table string) *bytes.Buffer {
					buf, ok := batchBufByTable[table]
					if !ok {
						buf = &bytes.Buffer{}
						batchBufByTable[table] = buf
						tableOrder = append(tableOrder, table)
					}
					return buf
				}
				writtenInBatch := make(map[string]bool, len(pending))
				lastVerInBatch := make(map[string]int64, len(pending))
				for _, pu := range pending {
					minVer := pu.version + 1
					targetKey := pu.targetIndex + "\x00" + pu.id
					if prevBatchVer, okBV := lastVerInBatch[targetKey]; okBV && prevBatchVer+1 > minVer {
						minVer = prevBatchVer + 1
					}
					if exMap := existingByIdx[pu.targetIndex]; exMap != nil {
						if exDoc, exists := exMap[pu.id]; exists {
							if pu.oldID != "" && pu.targetAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), pu.targetIndex, pu.id, exDoc.Source, pu.targetAliasFilter) {
								if conflictsProceed {
									versionConflicts++
									continue
								}
								writeESError(w, http.StatusConflict, "version_conflict_engine_exception",
									fmt.Sprintf("[%s]: version conflict, document belongs to another alias partition", pu.id))
								return
							}
							if exDoc.Version+1 > minVer {
								minVer = exDoc.Version + 1
							}
						} else if destSch := schemasByIdx[pu.targetIndex]; destSch != nil {
							if destHit, _, dErr := s.backend.GetDocByID(r.Context(), destSch.DorisDB, destSch.DorisTable, pu.id); dErr == nil && destHit != nil && destHit.Version+1 > minVer {
								minVer = destHit.Version + 1
							}
						}
					}
					if delVer := s.getDocVersion(pu.targetIndex, pu.id); delVer > 0 && delVer < 1_000_000_000_000 && delVer+1 > minVer {
						minVer = delVer + 1
					}
					if pu.oldID != "" {
						oldKey := pu.oldIndex + "\x00" + pu.oldID
						if !writtenInBatch[oldKey] {
							oldSch := schemasByIdx[pu.oldIndex]
							if oldSch == nil {
								oldSch = idxSchema
							}
							tombVer := s.allocVersion(pu.version + 1)
							if pu.version > 0 && pu.version < 1_000_000_000_000 {
								tombVer = pu.version + 1
							}
							tombShredded, err := schema.ShredDocument(oldSch, pu.oldID, tombVer, true, nil)
							if err != nil {
								writeESError(w, http.StatusBadRequest, shredErrorType(err), err.Error())
								return
							}
							tBuf := getTableBuf(oldSch.DorisTable)
							tBuf.Write(tombShredded)
							tBuf.WriteByte('\n')
							lastVerInBatch[oldKey] = tombVer
							s.setDocRouting(pu.oldIndex, pu.oldID, "")
							s.setDocVersion(pu.oldIndex, pu.oldID, tombVer)
							if exMap := existingByIdx[pu.oldIndex]; exMap != nil {
								delete(exMap, pu.oldID)
							}
						}
					}
					tSch := schemasByIdx[pu.targetIndex]
					if tSch == nil {
						tSch = s.ensureIndexSchema(r.Context(), pu.targetIndex)
						schemasByIdx[pu.targetIndex] = tSch
					}
					if !pu.isDel && pu.routing == "" && s.isRoutingRequired(tSch) {
						writeESError(w, http.StatusBadRequest, "routing_missing_exception",
							fmt.Sprintf("routing is required for [%s]/[%s]", pu.targetIndex, pu.id))
						return
					}
					nextVer := s.allocVersion(minVer)
					if minVer > 0 && minVer < 1_000_000_000_000 {
						nextVer = minVer
					}
					shredded, err := schema.ShredDocument(tSch, pu.id, nextVer, pu.isDel, pu.source)
					if err != nil {
						writeESError(w, http.StatusBadRequest, shredErrorType(err), err.Error())
						return
					}
					buf := getTableBuf(tSch.DorisTable)
					buf.Write(shredded)
					buf.WriteByte('\n')
					lastVerInBatch[targetKey] = nextVer
					s.setDocVersion(pu.targetIndex, pu.id, nextVer)
					if pu.isDel {
						writtenInBatch[targetKey] = false
						s.setDocRouting(pu.targetIndex, pu.id, "")
						if exMap := existingByIdx[pu.targetIndex]; exMap != nil {
							delete(exMap, pu.id)
						}
						totalDeleted++
					} else {
						writtenInBatch[targetKey] = true
						s.setDocRouting(pu.targetIndex, pu.id, pu.routing)
						if existingByIdx[pu.targetIndex] == nil {
							existingByIdx[pu.targetIndex] = make(map[string]HitRow)
						}
						existingByIdx[pu.targetIndex][pu.id] = HitRow{ID: pu.id, Version: nextVer, Source: pu.source, Routing: pu.routing}
						totalUpdated++
					}
				}

				for _, tbl := range tableOrder {
					buf := batchBufByTable[tbl]
					if buf != nil && buf.Len() > 0 {
						if err := s.streamLoad(r.Context(), tbl, buf.Bytes(), true); err != nil {
							writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
							return
						}
					}
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
		"took":                   tookMs,
		"timed_out":              false,
		"total":                  totalMatched,
		"updated":                totalUpdated,
		"deleted":                totalDeleted,
		"batches":                batches,
		"version_conflicts":      versionConflicts,
		"noops":                  totalNoops,
		"retries":                map[string]any{"bulk": 0, "search": 0},
		"throttled_millis":       0,
		"requests_per_second":    reqsPerSec,
		"throttled_until_millis": 0,
		"failures":               []any{},
	})
}

func (s *Server) handleDeleteByQuery(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rawIndex := r.PathValue("index")
	ew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
	if (ew == "none" || ew == "closed") && (strings.ContainsAny(rawIndex, "*?") || rawIndex == "_all") {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(rawIndex)
	if len(targets) == 0 && strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("allow_no_indices")), "false") {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+rawIndex+"]")
		return
	}
	if len(targets) == 0 && !hasExclusionOrWildcard(rawIndex) {
		targets = []string{s.resolveIndexName(rawIndex)}
	}

	var body struct {
		MaxDocs           *int         `json:"max_docs,omitempty"`
		Size              *int         `json:"size,omitempty"`
		Conflicts         string       `json:"conflicts,omitempty"`
		RequestsPerSecond any          `json:"requests_per_second,omitempty"`
		Slices            any          `json:"slices,omitempty"`
		Slice             *sliceSpec   `json:"slice,omitempty"`
		Query             *esast.Query `json:"query,omitempty"`
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
	sliceID, sliceMax, hasSlice, sliceErrStatus, sliceErrType, sliceErrReason := parseAndValidateSliceParams(r, body.Slices, body.Slice)
	if sliceErrStatus != 0 {
		writeESError(w, sliceErrStatus, sliceErrType, sliceErrReason)
		return
	}
	if body.Query == nil && r.URL.Query().Get("q") != "" {
		tmpReq := esast.SearchRequest{}
		applyURISearchParams(r, &tmpReq)
		body.Query = tmpReq.Query
	}

	effConflicts := strings.TrimSpace(r.URL.Query().Get("conflicts"))
	if effConflicts == "" {
		effConflicts = strings.TrimSpace(body.Conflicts)
	}
	if effConflicts != "" && !strings.EqualFold(effConflicts, "abort") && !strings.EqualFold(effConflicts, "proceed") {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Invalid conflicts value [%s], must be [abort] or [proceed]", effConflicts))
		return
	}
	reqsPerSec := float64(-1)
	if rpsQuery := strings.TrimSpace(r.URL.Query().Get("requests_per_second")); rpsQuery != "" {
		if !strings.EqualFold(rpsQuery, "infinity") {
			if v, err := strconv.ParseFloat(rpsQuery, 64); err == nil {
				if v == 0 {
					reqsPerSec = -1
				} else {
					reqsPerSec = v
				}
			}
		}
	} else if body.RequestsPerSecond != nil {
		if fv, ok := toFloat64(body.RequestsPerSecond); ok {
			if fv == 0 {
				reqsPerSec = -1
			} else {
				reqsPerSec = fv
			}
		}
	}

	maxDocs := 0
	if body.MaxDocs != nil && *body.MaxDocs > 0 {
		maxDocs = *body.MaxDocs
	} else if body.Size != nil && *body.Size > 0 {
		maxDocs = *body.Size
	}
	if qMax := r.URL.Query().Get("max_docs"); qMax != "" {
		if parsed, err := strconv.Atoi(qMax); err == nil && parsed > 0 {
			maxDocs = parsed
		}
	} else if qSize := r.URL.Query().Get("size"); qSize != "" {
		if parsed, err := strconv.Atoi(qSize); err == nil && parsed > 0 {
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
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), indexName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		var searchAfter []any
		effQuery := combineQueryWithAliasFilter(body.Query, aliasFilters[indexName])
		hasRuntimeQueryScript := queryHasRuntimeScript(effQuery)
		effSearchRouting := s.resolveEffectiveReadRouting(rawIndex, indexName, strings.TrimSpace(r.URL.Query().Get("routing")))

		batchLimit := 1000
		if qScrollSize := r.URL.Query().Get("scroll_size"); qScrollSize != "" {
			if parsed, err := strconv.Atoi(qScrollSize); err == nil && parsed > 0 {
				batchLimit = parsed
			}
		}

		for {
			fetchSize := batchLimit
			if !hasRuntimeQueryScript && !hasSlice && effSearchRouting == "" && maxDocs > 0 && totalDeleted+fetchSize > maxDocs {
				fetchSize = maxDocs - totalDeleted
			}
			if fetchSize <= 0 || (maxDocs > 0 && totalDeleted >= maxDocs) {
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
				s.mu.RLock()
				_, indexKnown := s.indices[indexName]
				s.mu.RUnlock()
				if !indexKnown {
					break
				}
				writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
				return
			}
			if len(hits) == 0 {
				break
			}
			batches++

			var batchBuf bytes.Buffer
			schemaEnsured := false
			for _, h := range hits {
				if maxDocs > 0 && totalDeleted >= maxDocs {
					break
				}
				if hasSlice && !docMatchesSlice(h.ID, sliceID, sliceMax) {
					continue
				}
				if effSearchRouting != "" && !s.docMatchesRequestRouting(indexName, h.ID, effSearchRouting) {
					continue
				}
				if hasRuntimeQueryScript {
					var rawMap map[string]any
					dec := json.NewDecoder(bytes.NewReader(h.Source))
					dec.UseNumber()
					_ = dec.Decode(&rawMap)
					if rawMap == nil {
						rawMap = make(map[string]any)
					}
					rawMap["__meta_id"] = h.ID
					if !evalQueryScriptFilterOnDocWithScore(idxSchema, rawMap, effQuery, h.Score) {
						continue
					}
				}
				if !schemaEnsured {
					idxSchema = s.ensureIndexSchema(r.Context(), indexName)
					schemaEnsured = true
				}
				nextVer := s.allocVersion(h.Version + 1)
				if h.Version > 0 && h.Version < 1_000_000_000_000 {
					nextVer = h.Version + 1
				}
				tombstone, err := schema.ShredDocument(idxSchema, h.ID, nextVer, true, nil)
				if err != nil {
					continue
				}
				batchBuf.Write(tombstone)
				batchBuf.WriteByte('\n')
				s.setDocRouting(indexName, h.ID, "")
				s.setDocVersion(indexName, h.ID, nextVer)
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
		"took":                   tookMs,
		"timed_out":              false,
		"total":                  totalDeleted,
		"deleted":                totalDeleted,
		"batches":                batches,
		"version_conflicts":      0,
		"noops":                  0,
		"retries":                map[string]any{"bulk": 0, "search": 0},
		"throttled_millis":       0,
		"requests_per_second":    reqsPerSec,
		"throttled_until_millis": 0,
		"failures":               []any{},
	})
}

func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rawDefaultIndex := r.PathValue("index")
	ops, err := esast.ParseBulkNDJSON(r.Body, rawDefaultIndex)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeESError(w, http.StatusRequestEntityTooLarge, "circuit_breaking_exception", "bulk request body exceeded max allowed size: "+err.Error())
			return
		}
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", err.Error())
		return
	}
	if rawDefaultIndex != "" {
		usesDefaultIndex := len(ops) == 0
		for _, op := range ops {
			if op.Index == rawDefaultIndex {
				usesDefaultIndex = true
				break
			}
		}
		if usesDefaultIndex {
			if _, err := s.resolveWriteIndex(rawDefaultIndex); err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
		}
	}
	for _, op := range ops {
		if op.Index == "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;")
			return
		}
	}

	defaultPipeline := r.URL.Query().Get("pipeline")
	urlRouting := r.URL.Query().Get("routing")
	droppedOps := make([]bool, len(ops))
	pipeErrs := make([]string, len(ops))
	origOpIndices := make([]string, len(ops))
	pipeRoutings := make([]string, len(ops))
	pipedOps := make([]bool, len(ops))
	// Collect sample docs per target index for dynamic mapping inference on auto-created indices.
	sampleDocsByIndex := make(map[string][]json.RawMessage)
	idsToFetchByIndex := make(map[string][]string)
	for idx := range ops {
		op := &ops[idx]
		origOpIndices[idx] = op.Index
		if op.ParseErr != "" {
			continue
		}
		origOpIndex := op.Index
		idxName, _, writeErr := s.resolveWriteIndexWithFilter(op.Index)
		if writeErr != nil {
			op.ParseErr = writeErr.Error()
			continue
		}
		if (op.Action == "index" || op.Action == "create") && len(op.Source) > 0 {
			initOpRouting := op.Routing
			if initOpRouting == "" {
				initOpRouting = urlRouting
			}
			if initOpRouting == "" {
				initOpRouting = s.resolveEffectiveIndexRouting(origOpIndex, "")
			}
			pipeInputID := op.ID
			if op.AutoGeneratedID {
				pipeInputID = ""
			}
			piped, nextIdx, nextID, nextRouting, dropped, pipeErr := s.applyEffectiveAndFinalPipelinesWithRouting(origOpIndex, pipeInputID, op.Pipeline, defaultPipeline, initOpRouting, op.Source)
			if pipeErr != nil {
				pipeErrs[idx] = pipeErr.Error()
				continue
			}
			if dropped {
				droppedOps[idx] = true
				if op.ID != "" {
					idsToFetchByIndex[idxName] = append(idsToFetchByIndex[idxName], op.ID)
				}
				continue
			}
			if nextID != "" {
				op.ID = nextID
			}
			pipedOps[idx] = true
			pipeRoutings[idx] = nextRouting
			if nextIdx != "" && nextIdx != origOpIndex {
				op.Index = nextIdx
				resolvedIdx, _, rErr := s.resolveWriteIndexWithFilter(op.Index)
				if rErr != nil {
					op.ParseErr = rErr.Error()
					continue
				}
				idxName = resolvedIdx
			}
			op.Source = piped
		}
		if (op.Action == "index" || op.Action == "create") && len(op.Source) > 0 {
			sampleDocsByIndex[idxName] = append(sampleDocsByIndex[idxName], op.Source)
		} else if op.Action == "update" && len(op.Source) > 0 {
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
		if (op.Action == "update" || op.Action == "create" || op.Action == "index" || op.Action == "delete") && op.ID != "" {
			idsToFetchByIndex[idxName] = append(idsToFetchByIndex[idxName], op.ID)
		}
	}
	existingByIndex := make(map[string]map[string]HitRow, len(idsToFetchByIndex))
	initialExistingByIndex := make(map[string]map[string]HitRow, len(idsToFetchByIndex))
	lastVerByIndex := make(map[string]map[string]int64, len(idsToFetchByIndex))
	for idxName, ids := range idsToFetchByIndex {
		idxSchema := s.getOrCompileReadOnlySchema(r.Context(), idxName)
		_ = s.coalescer.FlushTable(r.Context(), idxSchema.DorisTable)
		if m, err := s.backend.GetDocsByIDs(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, ids); err == nil {
			existingByIndex[idxName] = m
			initCopy := make(map[string]HitRow, len(m))
			verMap := make(map[string]int64, len(ids))
			for id, hr := range m {
				initCopy[id] = hr
				verMap[id] = hr.Version
			}
			for _, id := range ids {
				if _, ok := verMap[id]; !ok {
					if delVer := s.getDocVersion(idxName, id); delVer > 0 && delVer < 1_000_000_000_000 {
						verMap[id] = delVer
					}
				}
			}
			initialExistingByIndex[idxName] = initCopy
			lastVerByIndex[idxName] = verMap
		}
	}

	type pendingBulkRow struct {
		id      string
		ver     int64
		deleted bool
		source  json.RawMessage
	}
	byIndex := make(map[string]*bytes.Buffer)
	pendingRowsByTable := make(map[string][]pendingBulkRow)
	pendingRouting := make(map[string]map[string]string)
	setPendingRouting := func(idxName, docID, rVal string) {
		if idxName == "" || docID == "" {
			return
		}
		if pendingRouting[idxName] == nil {
			pendingRouting[idxName] = make(map[string]string)
		}
		pendingRouting[idxName][docID] = rVal
	}
	getPendingOrStoredRouting := func(idxName, docID string) string {
		if m, ok := pendingRouting[idxName]; ok {
			if rVal, has := m[docID]; has {
				return rVal
			}
		}
		return s.getDocRouting(idxName, docID)
	}
	docMatchesBulkRouting := func(idxName, docID, reqRt string) bool {
		reqRt = strings.TrimSpace(reqRt)
		if reqRt == "" {
			return true
		}
		storedRt := getPendingOrStoredRouting(idxName, docID)
		if storedRt == "" {
			storedRt = docID
		}
		for _, part := range strings.Split(reqRt, ",") {
			if strings.TrimSpace(part) == storedRt {
				return true
			}
		}
		return false
	}
	urlRequireAlias := isTruthyBoolQueryParam(r, "require_alias")
	writtenInBatch := make(map[string]bool, len(ops))
	reroutedToInBatch := make(map[string]bool, len(ops))
	var items []map[string]any
	hasErrors := false

	for opIdx, op := range ops {
		origOpIdx := origOpIndices[opIdx]
		if origOpIdx == "" {
			origOpIdx = op.Index
		}
		reqAlias := urlRequireAlias
		if op.RequireAlias != nil {
			reqAlias = *op.RequireAlias
		}
		if reqAlias && !s.isTargetAliasOrDataStream(origOpIdx) {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": origOpIdx,
					"_id":    op.ID,
					"status": http.StatusNotFound,
					"error": map[string]any{
						"type":   "index_not_found_exception",
						"reason": fmt.Sprintf("no such alias [%s] (require_alias=true)", origOpIdx),
					},
				},
			})
			continue
		}
		targetIndex, opAliasFilter, writeErr := s.resolveWriteIndexWithFilter(op.Index)
		if writeErr != nil {
			targetIndex = op.Index
		}
		reqRouting := op.Routing
		if reqRouting == "" {
			reqRouting = urlRouting
		}
		var effRouting string
		if pipedOps[opIdx] {
			effRawOpIdx := origOpIdx
			if op.Index != "" {
				effRawOpIdx = op.Index
			}
			effRouting = s.resolveEffectiveWriteRouting(effRawOpIdx, targetIndex, "", pipeRoutings[opIdx])
		} else {
			effRouting = s.resolveEffectiveWriteRouting(origOpIdx, targetIndex, reqRouting, pipeRoutings[opIdx])
		}
		if pipeErrs[opIdx] != "" {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": ingestErrorType(errors.New(pipeErrs[opIdx])), "reason": pipeErrs[opIdx]},
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

		if droppedOps[opIdx] {
			dropItem := map[string]any{
				"_index":        targetIndex,
				"_type":         "_doc",
				"_id":           op.ID,
				"_version":      -1,
				"result":        "noop",
				"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
				"_seq_no":       -1,
				"_primary_term": 1,
				"status":        http.StatusOK,
			}
			if effRouting != "" {
				dropItem["_routing"] = effRouting
			}
			items = append(items, map[string]any{
				op.Action: dropItem,
			})
			continue
		}

		roSchema := s.getOrCompileReadOnlySchema(r.Context(), targetIndex)
		canDeferUpdateRouting := false
		if op.Action == "update" && len(op.Source) > 0 {
			var updCheck painless.UpdateRequest
			if json.Unmarshal(op.Source, &updCheck) == nil && updCheck.Script != nil && strings.Contains(updCheck.Script.Source, "_routing") {
				canDeferUpdateRouting = true
			}
		}
		if s.isRoutingRequired(roSchema) && effRouting == "" && !canDeferUpdateRouting {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error": map[string]any{
						"type":   "routing_missing_exception",
						"reason": fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", targetIndex, op.ID),
					},
				},
			})
			continue
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

		existingBeforeOp, wasExistingBeforeOp := existingByIndex[targetIndex][op.ID]
		if (op.Action == "delete" || op.Action == "update") && wasExistingBeforeOp && effRouting != "" && !docMatchesBulkRouting(targetIndex, op.ID, effRouting) {
			wasExistingBeforeOp = false
		}
		docFoundForOCC := wasExistingBeforeOp && (opAliasFilter == nil || s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, existingBeforeOp.Source, opAliasFilter))
		var curVerForOCC int64
		if docFoundForOCC {
			curVerForOCC = existingBeforeOp.Version
		} else if !wasExistingBeforeOp && strings.HasPrefix(strings.ToLower(strings.TrimSpace(op.VersionType)), "external") {
			if lastVer, ok := lastVerByIndex[targetIndex][op.ID]; ok && lastVer > 0 {
				docFoundForOCC = true
				curVerForOCC = lastVer
			}
		}
		if op.Action == "update" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(op.VersionType)), "external") {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error": map[string]any{
						"type":   "action_request_validation_exception",
						"reason": fmt.Sprintf("Validation Failed: 1: version types [external, external_gt, external_gte] are not supported by update, got [%s];", op.VersionType),
					},
				},
			})
			continue
		}
		assignedVer, occStatus, occType, occReason := validateOCC(op.ID, docFoundForOCC, curVerForOCC, op.IfSeqNo, op.IfPrimaryTerm, op.Version, op.VersionType)
		if occType != "" {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": occStatus,
					"error":  map[string]any{"type": occType, "reason": occReason},
				},
			})
			continue
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
		if deleted {
			existingHit, found := existingByIndex[targetIndex][op.ID]
			if reroutedToInBatch[targetIndex+"\x00"+op.ID] {
				if initHit, initOK := initialExistingByIndex[targetIndex][op.ID]; initOK {
					existingHit = initHit
					found = true
				}
			}
			if found && effRouting != "" && !docMatchesBulkRouting(targetIndex, op.ID, effRouting) {
				found = false
			}
			if !found || (opAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, existingHit.Source, opAliasFilter)) {
				nfVer := int64(1)
				if assignedVer > 0 {
					nfVer = assignedVer
					_ = s.allocVersion(assignedVer)
					if lastVerByIndex[targetIndex] == nil {
						lastVerByIndex[targetIndex] = make(map[string]int64)
					}
					lastVerByIndex[targetIndex][op.ID] = assignedVer
					s.setDocVersion(targetIndex, op.ID, assignedVer)
				}
				nfItem := map[string]any{
					"_index":        targetIndex,
					"_type":         "_doc",
					"_id":           op.ID,
					"_version":      nfVer,
					"result":        "not_found",
					"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
					"_seq_no":       0,
					"_primary_term": 1,
					"status":        http.StatusNotFound,
				}
				if effRouting != "" {
					nfItem["_routing"] = effRouting
				}
				items = append(items, map[string]any{
					op.Action: nfItem,
				})
				continue
			}
		}
		sourceToShred := op.Source
		var minFloor int64
		if wasExistingBeforeOp {
			minFloor = existingBeforeOp.Version + 1
		}
		if lastVer, ok := lastVerByIndex[targetIndex][op.ID]; ok && lastVer+1 > minFloor {
			minFloor = lastVer + 1
		}
		updateResult := ""
		var bulkUpdateSF *esast.SourceFilter

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
			if op.DocAsUpsert != nil && !upd.DocAsUpsert {
				upd.DocAsUpsert = *op.DocAsUpsert
			}
			if op.DetectNoop != nil && upd.DetectNoop == nil {
				upd.DetectNoop = op.DetectNoop
			}
			if upd.Doc == nil && (upd.Script == nil || strings.TrimSpace(upd.Script.Source) == "") {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusBadRequest,
						"error":  map[string]any{"type": "action_request_validation_exception", "reason": "Validation Failed: 1: script or doc is missing;"},
					},
				})
				continue
			}
			var updMeta struct {
				Source         *esast.SourceFilter `json:"_source,omitempty"`
				SourceIncludes any                 `json:"_source_includes,omitempty"`
				SourceExcludes any                 `json:"_source_excludes,omitempty"`
			}
			_ = json.Unmarshal(op.Source, &updMeta)
			bulkUpdateSF = updMeta.Source
			if bulkUpdateSF == nil {
				bulkUpdateSF = op.SourceFilter
			}
			if bulkUpdateSF == nil {
				bulkUpdateSF = extractURLSourceFilter(r)
			}
			bulkUpdateSF = mergeMGetSourceFilter(bulkUpdateSF, op.SourceIncludes, op.SourceExcludes)
			bulkUpdateSF = mergeMGetSourceFilter(bulkUpdateSF, updMeta.SourceIncludes, updMeta.SourceExcludes)
			existingHit, found := existingByIndex[targetIndex][op.ID]
			if reroutedToInBatch[targetIndex+"\x00"+op.ID] {
				if initHit, initOK := initialExistingByIndex[targetIndex][op.ID]; initOK {
					existingHit = initHit
					found = true
				}
			}
			if found && effRouting != "" && !docMatchesBulkRouting(targetIndex, op.ID, effRouting) {
				found = false
			}
			if found && opAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, existingHit.Source, opAliasFilter) {
				hasErrors = true
				if upd.DocAsUpsert || upd.Upsert != nil || upd.ScriptedUpsert {
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
			if !found && (!upd.DocAsUpsert || upd.Doc == nil) && upd.Upsert == nil && !upd.ScriptedUpsert {
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
			if effRouting == "" && found {
				effRouting = getPendingOrStoredRouting(targetIndex, op.ID)
			}
			var baseSrc json.RawMessage
			upd.MetaID = op.ID
			upd.MetaIndex = targetIndex
			upd.MetaRouting = effRouting
			if found {
				baseSrc = existingHit.Source
				upd.MetaVersion = existingHit.Version
			} else {
				upd.MetaVersion = 1
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
			effRouting = strings.TrimSpace(upd.MetaRouting)
			if s.isRoutingRequired(roSchema) && effRouting == "" {
				hasErrors = true
				items = append(items, map[string]any{
					op.Action: map[string]any{
						"_index": targetIndex,
						"_id":    op.ID,
						"status": http.StatusBadRequest,
						"error": map[string]any{
							"type":   "routing_missing_exception",
							"reason": fmt.Sprintf("routing is required for [%s]/[_doc]/[%s]", targetIndex, op.ID),
						},
					},
				})
				continue
			}
			if !found && opRes == "deleted" {
				opRes = "noop"
				merged = nil
			}
			if found && opRes == "created" {
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
			var prePiped bool
			var prePipedDoc json.RawMessage
			var preNextIdx, preNextID, preUpdPipeRouting string
			var preDropped bool
			if opRes == "noop" && len(merged) > 0 {
				pipeInputIdx := op.Index
				if pipeInputIdx == "" {
					pipeInputIdx = targetIndex
				}
				if s.resolveEffectivePipeline(pipeInputIdx, op.Pipeline, defaultPipeline) != "" || s.resolveFinalPipeline(pipeInputIdx) != "" {
					var pipeErr error
					prePipedDoc, preNextIdx, preNextID, preUpdPipeRouting, preDropped, pipeErr = s.applyEffectiveAndFinalPipelinesWithRouting(pipeInputIdx, op.ID, op.Pipeline, defaultPipeline, effRouting, merged)
					if pipeErr != nil {
						hasErrors = true
						items = append(items, map[string]any{
							op.Action: map[string]any{
								"_index": targetIndex,
								"_id":    op.ID,
								"status": http.StatusBadRequest,
								"error":  map[string]any{"type": ingestErrorType(pipeErr), "reason": pipeErr.Error()},
							},
						})
						continue
					}
					prePiped = true
					if preDropped ||
						(preNextIdx != "" && preNextIdx != pipeInputIdx && preNextIdx != targetIndex) ||
						(preNextID != "" && preNextID != op.ID) ||
						(preUpdPipeRouting != effRouting) ||
						!jsonStructurallyEqual(merged, prePipedDoc) {
						if found {
							opRes = "updated"
						} else {
							opRes = "created"
						}
					}
				}
			}
			noopVer := existingHit.Version
			if noopVer <= 0 {
				noopVer = 1
			}
			if opRes == "noop" {
				noopEntry := map[string]any{
					"_index":        targetIndex,
					"_type":         "_doc",
					"_id":           op.ID,
					"_version":      noopVer,
					"result":        "noop",
					"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
					"_seq_no":       noopVer,
					"_primary_term": 1,
					"status":        http.StatusOK,
				}
				if effRouting != "" {
					noopEntry["_routing"] = effRouting
				}
				if bulkUpdateSF != nil && !bulkUpdateSF.Disabled {
					if found && len(merged) > 0 {
						noopEntry["get"] = map[string]any{
							"found":   true,
							"_source": filterSourceJSON(merged, bulkUpdateSF),
						}
					} else {
						noopEntry["get"] = map[string]any{
							"found": false,
						}
					}
				}
				items = append(items, map[string]any{
					op.Action: noopEntry,
				})
				continue
			}
			updateResult = opRes
			origTargetIndex := targetIndex
			origOpID := op.ID
			if opRes == "deleted" {
				deleted = true
				sourceToShred = merged
			} else {
				if len(merged) > 0 {
					pipeInputIdx := op.Index
					if pipeInputIdx == "" || targetIndex != origTargetIndex {
						pipeInputIdx = targetIndex
					}
					var piped json.RawMessage
					var nextIdx, nextID, updPipeRouting string
					var dropped bool
					if prePiped {
						piped, nextIdx, nextID, updPipeRouting, dropped = prePipedDoc, preNextIdx, preNextID, preUpdPipeRouting, preDropped
					} else {
						var pipeErr error
						piped, nextIdx, nextID, updPipeRouting, dropped, pipeErr = s.applyEffectiveAndFinalPipelinesWithRouting(pipeInputIdx, op.ID, op.Pipeline, defaultPipeline, effRouting, merged)
						if pipeErr != nil {
							hasErrors = true
							items = append(items, map[string]any{
								op.Action: map[string]any{
									"_index": targetIndex,
									"_id":    op.ID,
									"status": http.StatusBadRequest,
									"error":  map[string]any{"type": ingestErrorType(pipeErr), "reason": pipeErr.Error()},
								},
							})
							continue
						}
					}
					if dropped {
						dropEntry := map[string]any{
							"_index":        targetIndex,
							"_type":         "_doc",
							"_id":           op.ID,
							"_version":      noopVer,
							"result":        "noop",
							"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
							"_seq_no":       noopVer,
							"_primary_term": 1,
							"status":        http.StatusOK,
						}
						if effRouting != "" {
							dropEntry["_routing"] = effRouting
						}
						if bulkUpdateSF != nil && !bulkUpdateSF.Disabled {
							if found && len(existingHit.Source) > 0 {
								dropEntry["get"] = map[string]any{
									"found":   true,
									"_source": filterSourceJSON(existingHit.Source, bulkUpdateSF),
								}
							} else {
								dropEntry["get"] = map[string]any{
									"found": false,
								}
							}
						}
						items = append(items, map[string]any{
							op.Action: dropEntry,
						})
						continue
					}
					if nextID != "" {
						op.ID = nextID
					}
					effRawUpdIdx := origOpIdx
					if nextIdx != "" && nextIdx != pipeInputIdx {
						resolvedIdx, resolvedFilter, rErr := s.resolveWriteIndexWithFilter(nextIdx)
						if rErr != nil {
							hasErrors = true
							items = append(items, map[string]any{
								op.Action: map[string]any{
									"_index": nextIdx,
									"_id":    op.ID,
									"status": http.StatusBadRequest,
									"error":  map[string]any{"type": "illegal_argument_exception", "reason": rErr.Error()},
								},
							})
							continue
						}
						targetIndex = resolvedIdx
						opAliasFilter = resolvedFilter
						effRawUpdIdx = nextIdx
					}
					effRouting = s.resolveEffectiveWriteRouting(effRawUpdIdx, targetIndex, "", updPipeRouting)
					if op.ID != origOpID || targetIndex != origTargetIndex {
						var destSrc json.RawMessage
						hasDest := false
						roDestSchema := s.getOrCompileReadOnlySchema(r.Context(), targetIndex)
						if destExisting, destOK := existingByIndex[targetIndex][op.ID]; destOK {
							hasDest = true
							destSrc = destExisting.Source
							if destExisting.Version+1 > minFloor {
								minFloor = destExisting.Version + 1
							}
						} else if destHit, destFound, dErr := s.backend.GetDocByID(r.Context(), roDestSchema.DorisDB, roDestSchema.DorisTable, op.ID); dErr == nil && destHit != nil {
							if destFound {
								hasDest = true
								destSrc = destHit.Source
							}
							if destHit.Version+1 > minFloor {
								minFloor = destHit.Version + 1
							}
						}
						if delVer := s.getDocVersion(targetIndex, op.ID); delVer > 0 && delVer < 1_000_000_000_000 && delVer+1 > minFloor {
							minFloor = delVer + 1
						}
						if hasDest && opAliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), targetIndex, op.ID, destSrc, opAliasFilter) {
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
						if lastVer, okLV := lastVerByIndex[targetIndex][op.ID]; okLV && lastVer+1 > minFloor {
							minFloor = lastVer + 1
						}
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
				if found && (op.ID != origOpID || targetIndex != origTargetIndex) {
					reroutedToInBatch[targetIndex+"\x00"+op.ID] = true
					_, existedInitially := initialExistingByIndex[origTargetIndex][origOpID]
					if !reroutedToInBatch[origTargetIndex+"\x00"+origOpID] || !existedInitially {
						delete(reroutedToInBatch, origTargetIndex+"\x00"+origOpID)
						origSchema := s.ensureIndexSchema(r.Context(), origTargetIndex)
						origBuf, okOrig := byIndex[origSchema.DorisTable]
						if !okOrig {
							origBuf = &bytes.Buffer{}
							byIndex[origSchema.DorisTable] = origBuf
						}
						tombFloor := existingHit.Version + 1
						if lv, okLV := lastVerByIndex[origTargetIndex][origOpID]; okLV && lv+1 > tombFloor {
							tombFloor = lv + 1
						}
						tombVer := s.allocVersion(tombFloor)
						if tombFloor > 0 && tombFloor < 1_000_000_000_000 {
							tombVer = tombFloor
						}
						if tombShredded, tErr := schema.ShredDocument(origSchema, origOpID, tombVer, true, nil); tErr == nil {
							origBuf.Write(tombShredded)
							origBuf.WriteByte('\n')
							pendingRowsByTable[origSchema.DorisTable] = append(pendingRowsByTable[origSchema.DorisTable], pendingBulkRow{
								id:      origOpID,
								ver:     tombVer,
								deleted: true,
							})
						}
						setPendingRouting(origTargetIndex, origOpID, "")
						delete(existingByIndex[origTargetIndex], origOpID)
						if lastVerByIndex[origTargetIndex] == nil {
							lastVerByIndex[origTargetIndex] = make(map[string]int64)
						}
						lastVerByIndex[origTargetIndex][origOpID] = tombVer
					}
				}
			}
		}

		s.mu.RLock()
		prevSchema := s.indices[targetIndex]
		s.mu.RUnlock()
		var idxSchema *schema.IndexSchema
		if !deleted && len(sourceToShred) > 0 {
			samples := append(append([]json.RawMessage(nil), sampleDocsByIndex[targetIndex]...), sourceToShred)
			idxSchema = s.ensureWritableIndexSchemaWithDocs(r.Context(), targetIndex, samples)
		} else {
			idxSchema = s.ensureIndexSchema(r.Context(), targetIndex)
		}
		if effRouting == "" && s.isRoutingRequired(idxSchema) {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": "routing_missing_exception", "reason": fmt.Sprintf("routing is required for [%s]/[%s]", origOpIdx, op.ID)},
				},
			})
			continue
		}
		buf, ok := byIndex[idxSchema.DorisTable]
		if !ok {
			buf = &bytes.Buffer{}
			byIndex[idxSchema.DorisTable] = buf
		}
		if prevSchema != nil && idxSchema != prevSchema && len(pendingRowsByTable[idxSchema.DorisTable]) > 0 {
			buf.Reset()
			for _, prevRow := range pendingRowsByTable[idxSchema.DorisTable] {
				if reShredded, reErr := schema.ShredDocument(idxSchema, prevRow.id, prevRow.ver, prevRow.deleted, prevRow.source); reErr == nil {
					buf.Write(reShredded)
					buf.WriteByte('\n')
				}
			}
		}

		nextVer := s.allocVersion(minFloor)
		if minFloor > 0 && minFloor < 1_000_000_000_000 {
			nextVer = minFloor
		}
		if assignedVer > 0 {
			nextVer = assignedVer
			_ = s.allocVersion(assignedVer)
		}
		shredVer := nextVer
		shredded, err := schema.ShredDocument(idxSchema, op.ID, shredVer, deleted, sourceToShred)
		if err != nil {
			hasErrors = true
			items = append(items, map[string]any{
				op.Action: map[string]any{
					"_index": targetIndex,
					"_id":    op.ID,
					"status": http.StatusBadRequest,
					"error":  map[string]any{"type": shredErrorType(err), "reason": err.Error()},
				},
			})
			continue
		}
		buf.Write(shredded)
		buf.WriteByte('\n')
		pendingRowsByTable[idxSchema.DorisTable] = append(pendingRowsByTable[idxSchema.DorisTable], pendingBulkRow{
			id:      op.ID,
			ver:     shredVer,
			deleted: deleted,
			source:  sourceToShred,
		})

		if existingByIndex[targetIndex] == nil {
			existingByIndex[targetIndex] = make(map[string]HitRow)
		}
		if lastVerByIndex[targetIndex] == nil {
			lastVerByIndex[targetIndex] = make(map[string]int64)
		}
		lastVerByIndex[targetIndex][op.ID] = nextVer
		if deleted {
			writtenInBatch[targetIndex+"\x00"+op.ID] = false
			setPendingRouting(targetIndex, op.ID, "")
			delete(existingByIndex[targetIndex], op.ID)
		} else {
			writtenInBatch[targetIndex+"\x00"+op.ID] = true
			setPendingRouting(targetIndex, op.ID, effRouting)
			existingByIndex[targetIndex][op.ID] = HitRow{ID: op.ID, Version: nextVer, Source: sourceToShred, Routing: effRouting}
		}

		status := http.StatusCreated
		result := "created"
		reportedVer := nextVer
		if assignedVer > 0 {
			reportedVer = assignedVer
		}
		if deleted {
			status = http.StatusOK
			result = "deleted"
			if !wasExistingBeforeOp {
				reportedVer = 1
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
		itemMap := map[string]any{
			"_index":        targetIndex,
			"_type":         "_doc",
			"_id":           op.ID,
			"_version":      reportedVer,
			"result":        result,
			"_shards":       map[string]any{"total": 1, "successful": 1, "failed": 0},
			"_seq_no":       nextVer,
			"_primary_term": 1,
			"status":        status,
		}
		if effRouting != "" {
			itemMap["_routing"] = effRouting
		}
		if op.Action == "update" && bulkUpdateSF != nil && !bulkUpdateSF.Disabled && !deleted && len(sourceToShred) > 0 {
			itemMap["get"] = map[string]any{
				"found":   true,
				"_source": filterSourceJSON(sourceToShred, bulkUpdateSF),
			}
		}
		items = append(items, map[string]any{
			op.Action: itemMap,
		})
	}

	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	for dorisTable, buf := range byIndex {
		if buf.Len() == 0 {
			continue
		}
		if err := s.streamLoad(r.Context(), dorisTable, buf.Bytes(), syncRefresh); err != nil {
			s.queryCache.InvalidateAll()
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
	}
	for idxName, docMap := range pendingRouting {
		for docID, rVal := range docMap {
			s.setDocRouting(idxName, docID, rVal)
		}
	}
	for idxName, verMap := range lastVerByIndex {
		for docID, ver := range verMap {
			s.setDocVersion(idxName, docID, ver)
		}
	}
	s.queryCache.InvalidateAll()

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
		if len(req.Sort) == 0 {
			req.Sort = append(req.Sort, esast.SortSpec{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}})
		}
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
		lastSort := extractLastHitSort(resp)
		total := extractRespTotalHits(resp)
		resp["_scroll_id"] = encodeScrollCursorWithState(rawIndex, &req, lastSort, total, len(lastSort) == 0)
	}
	if r.URL.Query().Get("doris_explain") == "true" || r.URL.Query().Get("doris_explain") == "1" ||
		r.URL.Query().Get("_doris_explain") == "true" || r.URL.Query().Get("_doris_explain") == "1" {
		resp["_doris_explain"] = s.buildDorisExplainObject(r.Context(), rawIndex, &req)
	}
	if isTruthyBoolQueryParam(r, "typed_keys") {
		if aggsMap, ok := resp["aggregations"].(map[string]any); ok {
			applyTypedKeysToAggregations(aggsMap, req.EffectiveAggs())
		}
		if sugMap, ok := resp["suggest"].(map[string]any); ok {
			applyTypedKeysToSuggestions(sugMap, req.Suggest)
		}
	}
	if isTruthyBoolQueryParam(r, "rest_total_hits_as_int") {
		applyRestTotalHitsAsInt(resp, &req)
	}
	tookMs, _ := toInt64(resp["took"])
	syncShadow := r.URL.Query().Get("shadow_sync") == "true" || r.URL.Query().Get("shadow_sync") == "1"
	s.maybeRunShadowSearch(rawIndex, bodyBytes, resp, tookMs, syncShadow)

	writeJSON(w, http.StatusOK, resp)
}

func isTableNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "doesn't exist") || strings.Contains(msg, "Unknown table")
}

func convertInnerHitsTotalToInt(rawHits any) {
	handleHitMap := func(h map[string]any) {
		if h == nil {
			return
		}
		if ihMap, ok := h["inner_hits"].(map[string]any); ok {
			for _, ihVal := range ihMap {
				if ihEntry, ok := ihVal.(map[string]any); ok {
					convertTotalHitsToIntInMap(ihEntry)
				}
			}
		}
	}
	switch list := rawHits.(type) {
	case []map[string]any:
		for _, h := range list {
			handleHitMap(h)
		}
	case []any:
		for _, item := range list {
			if h, ok := item.(map[string]any); ok {
				handleHitMap(h)
			}
		}
	}
}

func convertTotalHitsToIntInMap(m map[string]any) {
	if m == nil {
		return
	}
	if hitsMap, ok := m["hits"].(map[string]any); ok {
		if totalObj, ok := hitsMap["total"].(map[string]any); ok {
			if val, hasVal := totalObj["value"]; hasVal {
				hitsMap["total"] = val
			}
		}
		convertInnerHitsTotalToInt(hitsMap["hits"])
	}
	for k, v := range m {
		if k == "hits" {
			continue
		}
		switch sub := v.(type) {
		case map[string]any:
			convertTotalHitsToIntInMap(sub)
		case []map[string]any:
			for _, item := range sub {
				convertTotalHitsToIntInMap(item)
			}
		case []any:
			for _, item := range sub {
				if itemMap, ok := item.(map[string]any); ok {
					convertTotalHitsToIntInMap(itemMap)
				}
			}
		}
	}
}

func applyRestTotalHitsAsInt(resp map[string]any, req *esast.SearchRequest) {
	if resp == nil {
		return
	}
	if hitsObj, ok := resp["hits"].(map[string]any); ok {
		if req != nil && !req.ShouldTrackTotalHits() {
			hitsObj["total"] = int64(-1)
		} else if totalObj, ok := hitsObj["total"].(map[string]any); ok {
			if val, hasVal := totalObj["value"]; hasVal {
				hitsObj["total"] = val
			}
		}
		convertInnerHitsTotalToInt(hitsObj["hits"])
	}
	if aggsMap, ok := resp["aggregations"].(map[string]any); ok {
		convertTotalHitsToIntInMap(aggsMap)
	}
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
		targets = []string{s.resolveIndexName(rawIndexPattern)}
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
	_ = s.syncCatalogFromBackend(r.Context())
	targets, aliasFilters := s.resolveTargetIndicesWithFilters(r.PathValue("index"))
	var filterPatterns []string
	if fieldsFilter := r.URL.Query().Get("fields"); fieldsFilter != "" {
		filterPatterns = append(filterPatterns, strings.Split(fieldsFilter, ",")...)
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var indexFilter *esast.Query
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		var body struct {
			Fields      []string     `json:"fields"`
			IndexFilter *esast.Query `json:"index_filter"`
		}
		if err := json.Unmarshal(bodyBytes, &body); err == nil {
			if len(body.Fields) > 0 {
				if len(filterPatterns) == 1 && filterPatterns[0] == "*" {
					filterPatterns = body.Fields
				} else {
					filterPatterns = append(filterPatterns, body.Fields...)
				}
			}
			indexFilter = body.IndexFilter
		}
	}
	if len(filterPatterns) == 0 {
		filterPatterns = []string{"*"}
	}
	if indexFilter != nil && len(targets) > 0 {
		filteredTargets := make([]string, 0, len(targets))
		zero := 0
		for _, idxName := range targets {
			cntReq := esast.SearchRequest{
				Size:           &zero,
				TrackTotalHits: true,
				Query:          indexFilter,
				AliasFilter:    aliasFilters[idxName],
			}
			resp, _, errType, _ := s.executeSearchRequest(r.Context(), idxName, &cntReq)
			if errType != "" {
				continue
			}
			if hitsMap, ok := resp["hits"].(map[string]any); ok {
				if totalObj, ok := hitsMap["total"].(map[string]any); ok {
					if cnt, _ := toInt64(totalObj["value"]); cnt > 0 {
						filteredTargets = append(filteredTargets, idxName)
					}
				}
			}
		}
		targets = filteredTargets
	}

	caps := make(map[string]map[string]map[string]any)
	indicesByFieldType := make(map[string]map[string][]string)
	nonSearchableByFieldType := make(map[string]map[string][]string)
	nonAggregatableByFieldType := make(map[string]map[string][]string)
	appendUniqueIdx := func(m map[string]map[string][]string, field, esType, idxName string) {
		if idxName == "" {
			return
		}
		if m[field] == nil {
			m[field] = make(map[string][]string)
		}
		for _, existing := range m[field][esType] {
			if existing == idxName {
				return
			}
		}
		m[field][esType] = append(m[field][esType], idxName)
	}
	addCap := func(idxName, field, esType string, searchable, aggregatable bool) {
		if !matchesAnyGlob(field, filterPatterns) {
			return
		}
		if caps[field] == nil {
			caps[field] = make(map[string]map[string]any)
		}
		if existing, ok := caps[field][esType]; ok {
			if prevS, _ := existing["searchable"].(bool); prevS || searchable {
				existing["searchable"] = true
			}
			if prevA, _ := existing["aggregatable"].(bool); prevA || aggregatable {
				existing["aggregatable"] = true
			}
		} else {
			caps[field][esType] = map[string]any{
				"type":         esType,
				"searchable":   searchable,
				"aggregatable": aggregatable,
			}
		}
		appendUniqueIdx(indicesByFieldType, field, esType, idxName)
		if !searchable {
			appendUniqueIdx(nonSearchableByFieldType, field, esType, idxName)
		}
		if !aggregatable {
			appendUniqueIdx(nonAggregatableByFieldType, field, esType, idxName)
		}
	}

	if targets == nil {
		targets = []string{}
	}
	if len(targets) > 0 {
		addCap("", "_id", "_id", true, true)
		addCap("", "_index", "_index", true, true)
	}

	s.mu.RLock()
	for _, idxName := range targets {
		idxSchema, ok := s.indices[idxName]
		if !ok {
			addCap(idxName, "@timestamp", "date", true, true)
			continue
		}
		augSchema := s.augmentSchemaWithRuntimeMappings(idxSchema, nil)
		if _, hasTS := augSchema.Fields["@timestamp"]; !hasTS {
			addCap(idxName, "@timestamp", "date", true, true)
		}
		for esPath, fb := range augSchema.Fields {
			if fb.ESType == "alias" {
				if fb.AliasTarget == "" {
					continue
				}
				if tb, ok := augSchema.Fields[fb.AliasTarget]; ok && tb.ESType != "alias" {
					fb.ESType = tb.ESType
					fb.DorisType = tb.DorisType
					fb.NotIndexed = tb.NotIndexed
					fb.EnabledFalse = tb.EnabledFalse
					fb.DocValuesFalse = tb.DocValuesFalse
				} else {
					continue
				}
			}
			isSearchable := !fb.NotIndexed && !fb.EnabledFalse && fb.ESType != "nested" && fb.ESType != "object"
			isAggregatableForType := func(esType string) bool {
				if fb.DocValuesFalse || fb.EnabledFalse {
					return false
				}
				switch esType {
				case "text", "match_only_text", "nested", "object", "dense_vector", "knn_vector", "geo_shape":
					return false
				default:
					return true
				}
			}
			switch {
			case fb.ESType != "":
				addCap(idxName, esPath, fb.ESType, isSearchable, isAggregatableForType(fb.ESType))
				if fb.KeywordCompanion != "" && fb.AliasTarget == "" {
					kwSearchable := !fb.EnabledFalse
					kwAggregatable := !fb.EnabledFalse
					if kwB, okKW := augSchema.Fields[esPath+".keyword"]; okKW {
						kwSearchable = !kwB.NotIndexed && !kwB.EnabledFalse
						kwAggregatable = !kwB.DocValuesFalse && !kwB.EnabledFalse
					}
					addCap(idxName, esPath+".keyword", "keyword", kwSearchable, kwAggregatable)
				}
			case fb.DorisType == schema.DorisBigInt:
				if strings.Contains(strings.ToLower(esPath), "time") || strings.Contains(strings.ToLower(esPath), "date") || strings.HasSuffix(esPath, "At") {
					addCap(idxName, esPath, "date", isSearchable, isAggregatableForType("date"))
				} else {
					addCap(idxName, esPath, "long", isSearchable, isAggregatableForType("long"))
				}
			case fb.DorisType == schema.DorisDouble:
				addCap(idxName, esPath, "double", isSearchable, isAggregatableForType("double"))
			case fb.DorisType == schema.DorisBoolean:
				addCap(idxName, esPath, "boolean", isSearchable, isAggregatableForType("boolean"))
			case fb.DorisType == schema.DorisString:
				addCap(idxName, esPath, "text", isSearchable, false)
				if fb.KeywordCompanion != "" && fb.AliasTarget == "" {
					addCap(idxName, esPath+".keyword", "keyword", !fb.EnabledFalse, !fb.EnabledFalse)
				}
			default:
				addCap(idxName, esPath, "keyword", isSearchable, isAggregatableForType("keyword"))
			}
		}
	}
	s.mu.RUnlock()

	for field, byType := range caps {
		for esType, entry := range byType {
			if len(byType) > 1 {
				if idxList := indicesByFieldType[field][esType]; len(idxList) > 0 {
					entry["indices"] = idxList
				}
			}
			if sFlag, _ := entry["searchable"].(bool); sFlag {
				if nonS := nonSearchableByFieldType[field][esType]; len(nonS) > 0 {
					entry["non_searchable_indices"] = nonS
				}
			}
			if aFlag, _ := entry["aggregatable"].(bool); aFlag {
				if nonA := nonAggregatableByFieldType[field][esType]; len(nonA) > 0 {
					entry["non_aggregatable_indices"] = nonA
				}
			}
		}
	}

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
			Index              any    `json:"index"`
			Indices            any    `json:"indices"`
			SearchType         string `json:"search_type"`
			Routing            any    `json:"routing"`
			RestTotalHitsAsInt any    `json:"rest_total_hits_as_int"`
			TypedKeys          any    `json:"typed_keys"`
			FilterPath         string `json:"filter_path"`
			TerminateAfter     *int   `json:"terminate_after"`
		}
		if err := json.Unmarshal(headerLine, &hdr); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
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
		applyURISearchParams(r, &req)
		switch rv := hdr.Routing.(type) {
		case string:
			if strings.TrimSpace(rv) != "" {
				req.Routing = strings.TrimSpace(rv)
			}
		case []any:
			var rParts []string
			for _, item := range rv {
				if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
					rParts = append(rParts, s)
				}
			}
			if len(rParts) > 0 {
				req.Routing = strings.Join(rParts, ",")
			}
		}
		if strings.EqualFold(hdr.SearchType, "count") || (hdr.SearchType == "" && strings.EqualFold(r.URL.Query().Get("search_type"), "count")) {
			zero := 0
			req.Size = &zero
			if req.TrackTotalHits == nil {
				req.TrackTotalHits = true
			}
		}
		if hdr.TerminateAfter != nil {
			req.TerminateAfter = hdr.TerminateAfter
		}

		targetIdx = extractPITIndex(targetIdx, req.PIT)
		resp, status, errType, errReason := s.executeSearchRequest(r.Context(), targetIdx, &req)
		if errType != "" {
			responses = append(responses, map[string]any{
				"status": status,
				"error":  map[string]any{"type": errType, "reason": errReason},
			})
			continue
		}
		if req.PIT != nil && req.PIT.ID != "" {
			resp["pit_id"] = req.PIT.ID
		}
		resp["status"] = http.StatusOK
		hdrTypedKeys, hasHdrTypedKeys := parseOptionalBoolAny(hdr.TypedKeys)
		if (hasHdrTypedKeys && hdrTypedKeys) || (!hasHdrTypedKeys && isTruthyBoolQueryParam(r, "typed_keys")) {
			if aggsMap, ok := resp["aggregations"].(map[string]any); ok {
				applyTypedKeysToAggregations(aggsMap, req.EffectiveAggs())
			}
			if sugMap, ok := resp["suggest"].(map[string]any); ok {
				applyTypedKeysToSuggestions(sugMap, req.Suggest)
			}
		}
		hdrRestTotalHits, hasHdrRestTotalHits := parseOptionalBoolAny(hdr.RestTotalHitsAsInt)
		if (hasHdrRestTotalHits && hdrRestTotalHits) || (!hasHdrRestTotalHits && isTruthyBoolQueryParam(r, "rest_total_hits_as_int")) {
			applyRestTotalHitsAsInt(resp, &req)
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
		targets = []string{s.resolveIndexName(rawIndexPattern)}
	}

	if req != nil {
		if len(req.SearchAfter) > 0 && len(req.Sort) > 0 && len(req.SearchAfter) < len(req.Sort) {
			return nil, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("search_after has %d value(s) but sort has %d field(s)", len(req.SearchAfter), len(req.Sort))
		}
		if errMsg := validatePipelineAggs(req.EffectiveAggs()); errMsg != "" {
			return nil, http.StatusBadRequest, "illegal_argument_exception", errMsg
		}
		if hasTermsLookupInSearchRequest(req) {
			req = s.resolveTermsLookupsInSearchRequest(ctx, req)
		}
	}
	aliasFilters = s.resolveTermsLookupsInAliasFilters(ctx, aliasFilters)
	var reqRouting string
	if req != nil {
		reqRouting = strings.TrimSpace(req.Routing)
	}
	aliasFilters = s.applySearchRoutingToAliasFilters(rawIndexPattern, targets, reqRouting, aliasFilters)

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
	if req.From != nil && *req.From > 0 && len(req.SearchAfter) == 0 {
		from = *req.From
	}
	size := 10
	if req.Size != nil {
		size = *req.Size
	} else if len(req.KNN) > 0 && req.KNN[0].K > 0 {
		size = req.KNN[0].K
	}
	reqHasRuntimeMappings := len(req.RuntimeMappings) > 0
	if !reqHasRuntimeMappings {
		for _, indexName := range targets {
			if sc := s.getOrCompileReadOnlySchema(ctx, indexName); sc != nil && sc.RawMapping != nil && len(sc.RawMapping.Runtime) > 0 {
				reqHasRuntimeMappings = true
				break
			}
		}
	}
	needsRuntimeScriptEval := reqHasRuntimeMappings || queryHasRuntimeScript(req.Query) || aliasFiltersHaveRuntimeScript(aliasFilters) || queryHasRuntimeScript(req.PostFilter) || sortsHaveScript(req.Sort) || aggsHaveRuntimeScript(req.EffectiveAggs()) || queryHasMinScore(req.Query) || aliasFiltersHaveMinScore(aliasFilters) || (req.MinScore != nil && (queryHasRuntimeScript(req.Query) || aliasFiltersHaveRuntimeScript(aliasFilters) || queryHasNestedScoring(req.Query) || len(req.IndicesBoost) > 0)) || (queryHasNestedScoring(req.Query) && (req.Collapse != nil || len(req.SearchAfter) > 0))

	var allHits []HitRow
	var allFetchedHits []HitRow
	var allPostFilterHits []HitRow
	var allAggRows []AggRow
	var totalHitsSum int64
	var totalQueryHitsSum int64
	var terminatedEarly bool
	var primarySchema *schema.IndexSchema
	schemasByIndex := make(map[string]*schema.IndexSchema, len(targets))
	var allUnindexedFields []string
	seenUnindexed := make(map[string]struct{})
	rescoreWin := maxRescoreWindow(req, from+size)

	for _, indexName := range targets {
		rawIdxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
		idxSchema := s.augmentSchemaWithRuntimeMappings(rawIdxSchema, req.RuntimeMappings)
		hasRuntimeMappings := len(effectiveRuntimeMappings(rawIdxSchema, req.RuntimeMappings)) > 0
		schemasByIndex[indexName] = idxSchema
		if primarySchema == nil {
			primarySchema = idxSchema
		}
		subReq := *req
		if needsRuntimeScriptEval {
			zero := 0
			fetchAll := 10000
			subReq.From = &zero
			subReq.Size = &fetchAll
			subReq.SearchAfter = nil
			subReq.Collapse = nil
			subReq.PostFilter = nil
			subReq.MinScore = nil
			if hasRuntimeMappings {
				subReq.Query = nil
				subReq.Sort = nil
				subReq.Aggs = nil
				subReq.Aggregations = nil
			}
		} else if len(targets) > 1 && size > 0 {
			zero := 0
			fetchSize := from + size
			if rescoreWin > fetchSize {
				fetchSize = rescoreWin
			}
			if queryHasNestedScoring(req.Query) && (len(req.Sort) == 0 || sortSpecsUseScore(req.Sort)) && fetchSize < 1000 {
				fetchSize = 1000
			}
			if rescoreWin > 0 {
				subReq.SearchAfter = nil
			}
			if req.Collapse != nil && req.Collapse.Field != "" {
				if rescoreWin > 0 {
					if fetchSize < 10000 {
						fetchSize = 10000
					}
					subReq.Collapse = nil
				} else if fetchSize < from+size+100 {
					fetchSize = from + size + 100
				}
				subReq.SearchAfter = nil
			}
			subReq.From = &zero
			subReq.Size = &fetchSize
		} else if len(targets) == 1 && rescoreWin > 0 && size > 0 {
			zero := 0
			fetchSize := from + size
			if rescoreWin > fetchSize {
				fetchSize = rescoreWin
			}
			if queryHasNestedScoring(req.Query) && (len(req.Sort) == 0 || sortSpecsUseScore(req.Sort)) && fetchSize < 1000 {
				fetchSize = 1000
			}
			if req.Collapse != nil && req.Collapse.Field != "" {
				if fetchSize < 10000 {
					fetchSize = 10000
				}
				subReq.Collapse = nil
			}
			subReq.SearchAfter = nil
			subReq.From = &zero
			subReq.Size = &fetchSize
		} else if len(targets) == 1 && (from > 0 || queryHasNestedScoring(req.Query)) && size > 0 && len(req.SearchAfter) == 0 && req.TerminateAfter == nil {
			zero := 0
			fetchSize := from + size
			if queryHasNestedScoring(req.Query) && (len(req.Sort) == 0 || sortSpecsUseScore(req.Sort)) && fetchSize < 1000 {
				fetchSize = 1000
			}
			subReq.From = &zero
			subReq.Size = &fetchSize
		}
		var subReqPtr *esast.SearchRequest
		if hasRuntimeMappings {
			subReqPtr = &subReq
		} else {
			subReqPtr = applyIndexAliasFilter(&subReq, aliasFilters[indexName])
		}

		idxStart := time.Now()
		sqlSchema := idxSchema
		if hasRuntimeMappings {
			sqlSchema = rawIdxSchema
		}
		tr := transpiler.NewTranspiler(sqlSchema, s.transpileOpts)
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

		if hitsErr != nil && !isTableNotFoundError(hitsErr) {
			return nil, http.StatusInternalServerError, "doris_query_exception", hitsErr.Error()
		}
		if aggsErr != nil && !isTableNotFoundError(aggsErr) {
			return nil, http.StatusInternalServerError, "doris_aggs_exception", aggsErr.Error()
		}

		var idxTotal int64
		for i := range hits {
			hits[i].Index = indexName
			hits[i].Routing = s.getDocRouting(indexName, hits[i].ID)
			if len(req.SearchAfter) == 0 && hits[i].TotalHits > idxTotal {
				idxTotal = hits[i].TotalHits
			}
		}
		if hasRuntimeMappings && len(hits) > 0 {
			s.evalRuntimeMappingsOnHitRows(idxSchema, req.RuntimeMappings, hits)
		}
		if ((len(hits) == 0 && from > 0) || len(req.SearchAfter) > 0) && plan.AggsSQL == "" && req.ShouldTrackTotalHits() && !hasRuntimeMappings {
			zero := 0
			cntReq := *subReqPtr
			cntReq.From = &zero
			cntReq.Size = &zero
			cntReq.SearchAfter = nil
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
		if needsRuntimeScriptEval {
			var matchedQueryHits []HitRow
			var postFilteredHits []HitRow
			var globalHits []HitRow
			if hasRuntimeMappings && aggsHaveGlobalAgg(req.EffectiveAggs()) {
				for _, gh := range hits {
					if aliasFilters[indexName] != nil {
						var gDoc map[string]any
						if len(gh.EffectiveSource()) > 0 {
							dec := json.NewDecoder(bytes.NewReader(gh.EffectiveSource()))
							dec.UseNumber()
							_ = dec.Decode(&gDoc)
						}
						if gDoc == nil {
							gDoc = make(map[string]any)
						}
						gDoc["__meta_id"] = gh.ID
						if !evalBranchMatchesDoc(idxSchema, gDoc, aliasFilters[indexName]) {
							continue
						}
					}
					globalHits = append(globalHits, gh)
				}
			} else if (req.Query != nil && globalAggsHaveRuntimeScript(req.EffectiveAggs())) || ((queryHasRuntimeScript(aliasFilters[indexName]) || queryHasMinScore(aliasFilters[indexName])) && aggsHaveGlobalAgg(req.EffectiveAggs())) {
				zero := 0
				fetchAll := 10000
				gReq := esast.SearchRequest{
					From:  &zero,
					Size:  &fetchAll,
					Query: aliasFilters[indexName],
				}
				if gPlan, gErr := tr.BuildSearchPlan(&gReq); gErr == nil && gPlan.HitsSQL != "" {
					if gRows, qErr := s.backend.QueryHits(ctx, gPlan.HitsSQL); qErr == nil {
						for i := range gRows {
							gRows[i].Index = indexName
							gRows[i].Routing = s.getDocRouting(indexName, gRows[i].ID)
						}
						if queryHasRuntimeScript(aliasFilters[indexName]) || queryHasMinScore(aliasFilters[indexName]) {
							for _, gh := range gRows {
								var gDoc map[string]any
								if len(gh.EffectiveSource()) > 0 {
									dec := json.NewDecoder(bytes.NewReader(gh.EffectiveSource()))
									dec.UseNumber()
									_ = dec.Decode(&gDoc)
								}
								if gDoc == nil {
									gDoc = make(map[string]any)
								}
								gDoc["__meta_id"] = gh.ID
								if evalQueryScriptFilterOnDocWithSchema(idxSchema, gDoc, aliasFilters[indexName]) {
									globalHits = append(globalHits, gh)
								}
							}
						} else {
							globalHits = gRows
						}
					}
				}
			}
			evalReq := applyIndexAliasFilter(req, aliasFilters[indexName])
			if idxBoost, hasIdxBoost := s.resolveIndexBoostFactor(indexName, req.IndicesBoost); hasIdxBoost {
				cp := *evalReq
				cp.IndicesBoost = map[string]float64{"__current_index__": idxBoost}
				evalReq = &cp
			}
			hits, aggRows, idxTotal, matchedQueryHits, postFilteredHits = applyRuntimeSearchScriptsWithMatchedAndGlobal(hits, globalHits, aggRows, idxTotal, evalReq, idxSchema, len(targets) > 1)
			allFetchedHits = append(allFetchedHits, matchedQueryHits...)
			allPostFilterHits = append(allPostFilterHits, postFilteredHits...)
			hasQueryLevelFilter := queryHasRuntimeScript(req.Query) || queryHasRuntimeScript(aliasFilters[indexName]) || req.MinScore != nil || queryHasMinScore(req.Query) || queryHasMinScore(aliasFilters[indexName])
			if hasQueryLevelFilter && !hasRuntimeMappings && plan.AggsSQL != "" && len(req.EffectiveAggs()) > 0 {
				matchedIDs := make([]string, 0, len(matchedQueryHits))
				for _, mh := range matchedQueryHits {
					matchedIDs = append(matchedIDs, mh.ID)
				}
				if len(matchedIDs) == 0 {
					matchedIDs = []string{"__NO_MATCHING_DOCS_AFTER_RUNTIME_SCRIPT__"}
				}
				aggSubReq := *subReqPtr
				aggSubReq.MinScore = nil
				aggSubReq.Query = combineQueryWithAliasFilter(&esast.Query{Ids: &esast.IdsQuery{Values: matchedIDs}}, aliasFilters[indexName])
				if (queryHasRuntimeScript(aliasFilters[indexName]) || queryHasMinScore(aliasFilters[indexName])) && aggsHaveGlobalAgg(req.EffectiveAggs()) {
					globalIDs := make([]string, 0, len(globalHits))
					for _, gh := range globalHits {
						globalIDs = append(globalIDs, gh.ID)
					}
					if len(globalIDs) == 0 {
						globalIDs = []string{"__NO_MATCHING_DOCS_AFTER_RUNTIME_SCRIPT__"}
					}
					aggSubReq.AliasFilter = &esast.Query{Ids: &esast.IdsQuery{Values: globalIDs}}
				}
				if aggPlan, aErr := tr.BuildSearchPlan(&aggSubReq); aErr == nil && aggPlan.AggsSQL != "" {
					if reAggRows, rErr := s.backend.QueryAggs(ctx, aggPlan.AggsSQL); rErr == nil {
						aggRows = applyRuntimeScriptAggsOnlyWithGlobal(matchedQueryHits, globalHits, reAggRows, idxTotal, evalReq, idxSchema)
					}
				}
			}
		} else {
			if req != nil && queryHasNestedScoring(req.Query) {
				for i := range hits {
					var docMap map[string]any
					if len(hits[i].EffectiveSource()) > 0 {
						dec := json.NewDecoder(bytes.NewReader(hits[i].EffectiveSource()))
						dec.UseNumber()
						_ = dec.Decode(&docMap)
					}
					if docMap == nil {
						docMap = make(map[string]any)
					}
					docMap["__meta_id"] = hits[i].ID
					hits[i].Score = evalQueryScriptScoreOnDocWithSchema(idxSchema, docMap, req.Query, hits[i].Score)
				}
				if len(targets) == 1 && len(req.SearchAfter) == 0 && (len(req.Sort) == 0 || sortSpecsUseScore(req.Sort)) && len(hits) > 1 {
					sort.SliceStable(hits, func(i, j int) bool {
						if len(req.Sort) > 0 {
							if cmp := compareHitRowsBySort(hits[i], hits[j], req.Sort, idxSchema); cmp != 0 {
								return cmp < 0
							}
						}
						if hits[i].Score != hits[j].Score {
							return hits[i].Score > hits[j].Score
						}
						return hits[i].ID < hits[j].ID
					})
				}
			}
			if idxBoost, hasIdxBoost := s.resolveIndexBoostFactor(indexName, req.IndicesBoost); hasIdxBoost {
				for i := range hits {
					hits[i].Score *= idxBoost
				}
			}
			allFetchedHits = append(allFetchedHits, hits...)
			allPostFilterHits = append(allPostFilterHits, hits...)
		}
		var hasNonZeroAggRow bool
		var idxQueryTotal int64
		bucketCounts := make(map[string]int64, len(aggRows))
		for _, r := range aggRows {
			if r.AggName == "__meta_total" {
				if idxTotal == 0 {
					idxTotal = r.effectiveCount()
				}
				continue
			}
			if r.AggName == "__meta_query_total" {
				idxQueryTotal = r.effectiveCount()
				continue
			}
			if r.effectiveCount() != 0 || r.effectiveValue() != 0 || strings.Contains(r.BucketKey, "\x00") {
				hasNonZeroAggRow = true
			}
			bucketCounts[r.AggName+"\x00"+r.BucketKey] = r.effectiveCount()
		}
		if !req.ShouldTrackTotalHits() && idxTotal == 0 && len(hits) > 0 {
			idxTotal = int64(len(hits))
		}
		if idxQueryTotal == 0 {
			idxQueryTotal = idxTotal
		}
		if req != nil && req.TerminateAfter != nil && *req.TerminateAfter > 0 {
			ta := int64(*req.TerminateAfter)
			if idxTotal > ta {
				idxTotal = ta
				terminatedEarly = true
			}
			if idxQueryTotal > ta {
				idxQueryTotal = ta
			}
			if !needsRuntimeScriptEval && len(targets) == 1 && from > 0 && len(req.SearchAfter) == 0 && rescoreWin == 0 {
				if from >= *req.TerminateAfter {
					hits = nil
					terminatedEarly = true
				} else if from+len(hits) > *req.TerminateAfter {
					hits = hits[:*req.TerminateAfter-from]
					terminatedEarly = true
				}
			} else if int64(len(hits)) > ta {
				hits = hits[:*req.TerminateAfter]
				terminatedEarly = true
			}
			for i := range hits {
				if hits[i].TotalHits > ta {
					hits[i].TotalHits = ta
				}
			}
			for i := range aggRows {
				if aggRows[i].AggName == "__meta_total" && aggRows[i].effectiveCount() > ta {
					aggRows[i].DocCount = ta
					aggRows[i].Value = float64(ta)
					terminatedEarly = true
				}
			}
		}
		allHits = append(allHits, hits...)
		effAggs := req.EffectiveAggs()
		var hasGlobalAggRow bool
		if idxQueryTotal == 0 && len(effAggs) > 0 {
			for _, r := range aggRows {
				if isUnderGlobalAgg(effAggs, r.AggName) {
					hasGlobalAggRow = true
					break
				}
			}
		}
		if len(targets) > 1 && idxQueryTotal == 0 && !hasGlobalAggRow && (req.PostFilter == nil || !hasNonZeroAggRow) {
			for _, r := range aggRows {
				if r.AggName == "__meta_total" || r.AggName == "__meta_query_total" {
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
				} else if strings.HasSuffix(r.AggName, "._stats_count") || strings.HasSuffix(r.AggName, "._sstats_count") {
					baseAgg := strings.TrimSuffix(strings.TrimSuffix(r.AggName, "._stats_count"), "._sstats_count")
					statsCounts[baseAgg+"\x00"+r.BucketKey] = r.effectiveCount()
					if r.effectiveCount() == 0 {
						emptySubStatsBuckets[baseAgg+"\x00"+r.BucketKey] = true
					}
				}
			}
			for _, r := range aggRows {
				if idxQueryTotal == 0 && r.AggName != "__meta_total" && r.AggName != "__meta_query_total" && req.PostFilter == nil && !isUnderGlobalAgg(effAggs, r.AggName) {
					continue
				}
				if emptyStatsAggs[r.AggName] && r.BucketKey != "_stats_count" && r.BucketKey != "_sstats_count" {
					continue
				}
				if dot := strings.LastIndexByte(r.AggName, '.'); dot > 0 &&
					(strings.HasPrefix(r.AggName[dot+1:], "_stats_") || strings.HasPrefix(r.AggName[dot+1:], "_sstats_")) &&
					r.AggName[dot+1:] != "_stats_count" && r.AggName[dot+1:] != "_sstats_count" {
					if emptySubStatsBuckets[r.AggName[:dot]+"\x00"+r.BucketKey] {
						continue
					}
				}
				if r.BucketKey == "_stats_avg" || r.BucketKey == "_sstats_avg" || r.BucketKey == "_stats_entropy" || r.BucketKey == "_sstats_entropy" {
					if cnt := statsCounts[r.AggName]; cnt > 0 {
						r.Weight = cnt
					}
				} else if strings.HasSuffix(r.AggName, "._stats_avg") || strings.HasSuffix(r.AggName, "._sstats_avg") ||
					strings.HasSuffix(r.AggName, "._stats_entropy") || strings.HasSuffix(r.AggName, "._sstats_entropy") {
					baseAgg := r.AggName[:strings.LastIndexByte(r.AggName, '.')]
					if cnt := statsCounts[baseAgg+"\x00"+r.BucketKey]; cnt > 0 {
						r.Weight = cnt
					}
				}
				if r.AggName != "__meta_total" && r.AggName != "__meta_query_total" {
					spec := resolveAggSpecByPath(effAggs, r.AggName)
					if spec.TopHits != nil || spec.TopMetrics != nil {
						if sep := strings.LastIndex(r.BucketKey, "\x1f"); sep >= 0 {
							if !strings.Contains(r.BucketKey[sep+1:], "\x00") {
								r.BucketKey = r.BucketKey[:sep+1] + indexName + "\x00" + r.BucketKey[sep+1:]
							}
						} else if sep := strings.LastIndex(r.BucketKey, "\\x1f"); sep >= 0 {
							if !strings.Contains(r.BucketKey[sep+4:], "\x00") {
								r.BucketKey = r.BucketKey[:sep+4] + indexName + "\x00" + r.BucketKey[sep+4:]
							}
						} else if !strings.Contains(r.BucketKey, "\x00") {
							r.BucketKey = indexName + "\x00" + r.BucketKey
						}
					}
				}
				if r.AggName != "__meta_total" && r.AggName != "__meta_query_total" && r.Weight >= 0 {
					spec := resolveAggSpecByPath(effAggs, r.AggName)
					metricField := singleValueMetricField(spec)
					if metricField != "" || aggSpecHasDirectRuntimeScript(spec) {
						if metricField != "" && r.effectiveValue() == 0 && !metricAggHasMissing(spec) && !indexSchemaHasField(idxSchema, metricField) {
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
							if w == 0 && r.Weight == 0 && (spec.Min != nil || spec.Max != nil || spec.Avg != nil || spec.Percentiles != nil || spec.PercentileRanks != nil || spec.Boxplot != nil) {
								continue
							}
						} else if idxQueryTotal > 0 {
							w = idxQueryTotal
						} else if !isUnderGlobalAgg(effAggs, r.AggName) && r.Weight == 0 && (spec.Min != nil || spec.Max != nil || spec.Avg != nil || spec.Percentiles != nil || spec.PercentileRanks != nil || spec.Boxplot != nil) {
							continue
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
		totalQueryHitsSum += idxQueryTotal
	}

	effSorts := transpiler.EffectiveSortsForRequest(req)
	if len(targets) > 1 {
		sort.SliceStable(allHits, func(i, j int) bool {
			if len(effSorts) > 0 {
				sI := schemasByIndex[allHits[i].Index]
				if sI == nil {
					sI = primarySchema
				}
				sJ := schemasByIndex[allHits[j].Index]
				if sJ == nil {
					sJ = primarySchema
				}
				if cmp := compareHitRowsBySortWithSchemas(allHits[i], allHits[j], effSorts, sI, sJ); cmp != 0 {
					return cmp < 0
				}
			}
			if allHits[i].Score != allHits[j].Score {
				return allHits[i].Score > allHits[j].Score
			}
			return allHits[i].ID < allHits[j].ID
		})
		if rescoreWin > 0 && len(allHits) > 0 {
			allHits = s.applyRescoreToHits(req, allHits, schemasByIndex, primarySchema, from+size)
			allPostFilterHits = append([]HitRow(nil), allHits...)
			if req.PostFilter == nil {
				allFetchedHits = append([]HitRow(nil), allHits...)
			}
		}
		if req.Collapse != nil && req.Collapse.Field != "" && len(allHits) > 0 {
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
					ck := normalizeCollapseGroupKey(vals[0], req.Collapse.Field, primarySchema, hSchema)
					if _, exists := seenCollapse[ck]; exists {
						continue
					}
					seenCollapse[ck] = struct{}{}
				}
				if len(req.SearchAfter) > 0 && !hitIsAfterSearchAfter(h, effSorts, req.SearchAfter, hSchema) {
					continue
				}
				deduped = append(deduped, h)
			}
			allHits = deduped
		} else if len(req.SearchAfter) > 0 && (needsRuntimeScriptEval || rescoreWin > 0) && len(allHits) > 0 {
			afterFiltered := make([]HitRow, 0, len(allHits))
			for _, h := range allHits {
				hSchema := schemasByIndex[h.Index]
				if hSchema == nil {
					hSchema = primarySchema
				}
				if hitIsAfterSearchAfter(h, effSorts, req.SearchAfter, hSchema) {
					afterFiltered = append(afterFiltered, h)
				}
			}
			allHits = afterFiltered
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
		allAggRows = mergeMultiIndexAggRows(allAggRows, totalHitsSum, totalQueryHitsSum, req.EffectiveAggs())
	} else if rescoreWin > 0 && len(allHits) > 0 {
		allHits = s.applyRescoreToHits(req, allHits, schemasByIndex, primarySchema, from+size)
		allPostFilterHits = append([]HitRow(nil), allHits...)
		if req.PostFilter == nil {
			allFetchedHits = append([]HitRow(nil), allHits...)
		}
		if req.Collapse != nil && req.Collapse.Field != "" && len(allHits) > 0 {
			seenCollapse := make(map[string]struct{}, len(allHits))
			deduped := make([]HitRow, 0, len(allHits))
			collapseSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: req.Collapse.Field}}}
			for _, h := range allHits {
				vals := extractHitSortValues(h, collapseSort, primarySchema)
				if len(vals) > 0 && vals[0] != nil {
					ck := normalizeCollapseGroupKey(vals[0], req.Collapse.Field, primarySchema, primarySchema)
					if _, exists := seenCollapse[ck]; exists {
						continue
					}
					seenCollapse[ck] = struct{}{}
				}
				if len(req.SearchAfter) > 0 && !hitIsAfterSearchAfter(h, effSorts, req.SearchAfter, primarySchema) {
					continue
				}
				deduped = append(deduped, h)
			}
			allHits = deduped
		} else if len(req.SearchAfter) > 0 && len(allHits) > 0 {
			afterFiltered := make([]HitRow, 0, len(allHits))
			for _, h := range allHits {
				if hitIsAfterSearchAfter(h, effSorts, req.SearchAfter, primarySchema) {
					afterFiltered = append(afterFiltered, h)
				}
			}
			allHits = afterFiltered
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
	} else if len(targets) == 1 && !needsRuntimeScriptEval && (from > 0 || queryHasNestedScoring(req.Query)) && size > 0 && len(req.SearchAfter) == 0 && req.TerminateAfter == nil {
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
	} else if len(req.SearchAfter) > 0 && totalHitsSum > 0 {
		for i := range allHits {
			allHits[i].TotalHits = totalHitsSum
		}
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
	enrichHitRow := func(h *HitRow) *HitRow {
		if h == nil {
			return nil
		}
		if h.Schema == nil {
			if s, ok := schemasByIndex[h.Index]; ok && s != nil {
				h.Schema = s
			} else {
				h.Schema = primarySchema
			}
		}
		if h.Query == nil && req != nil {
			h.Query = req.Query
		}
		if h.Routing == "" && h.Index != "" && h.ID != "" {
			h.Routing = s.getDocRouting(h.Index, h.ID)
		}
		return h
	}
	docLookup := func(id string) *HitRow {
		var targetIdx string
		docID := id
		if nul := strings.IndexByte(id, '\x00'); nul >= 0 {
			targetIdx = id[:nul]
			docID = id[nul+1:]
		}
		for i := range allHits {
			if allHits[i].ID == docID && (targetIdx == "" || allHits[i].Index == targetIdx) {
				return enrichHitRow(&allHits[i])
			}
		}
		for i := range allFetchedHits {
			if allFetchedHits[i].ID == docID && (targetIdx == "" || allFetchedHits[i].Index == targetIdx) {
				return enrichHitRow(&allFetchedHits[i])
			}
		}
		for _, tName := range targets {
			if targetIdx != "" && tName != targetIdx {
				continue
			}
			tSchema := s.getOrCompileReadOnlySchema(ctx, tName)
			if tSchema != nil {
				if h, found, err := s.backend.GetDocByID(ctx, tSchema.DorisDB, tSchema.DorisTable, docID); err == nil && found && h != nil {
					if af := aliasFilters[tName]; af != nil && !s.docMatchesAliasFilter(ctx, tName, docID, h.Source, af) {
						continue
					}
					if req != nil && req.Query != nil {
						var docMap map[string]any
						dec := json.NewDecoder(bytes.NewReader(h.Source))
						dec.UseNumber()
						_ = dec.Decode(&docMap)
						if docMap == nil {
							docMap = make(map[string]any)
						}
						docMap["__meta_id"] = h.ID
						if queryHasRuntimeScript(req.Query) || queryHasNestedScoring(req.Query) || req.Query.FunctionScore != nil {
							baseScore := scoreNonScriptClauseOnDoc(tSchema, docMap, req.Query)
							h.Score = evalQueryScriptScoreOnDocWithSchema(tSchema, docMap, req.Query, baseScore)
						} else {
							h.Score = scoreNonScriptClauseOnDoc(tSchema, docMap, req.Query)
						}
					} else {
						h.Score = 1.0
					}
					h.Index = tName
					h.Schema = tSchema
					h.Routing = s.getDocRouting(tName, h.ID)
					return enrichHitRow(h)
				}
			}
		}
		return nil
	}
	resp := buildESResponseWithSchemas(primaryIndex, primarySchema, schemasByIndex, req, allHits, allAggRows, tookMs, docLookup)
	if size > 0 && req != nil {
		var maxFetchedScore float64
		for _, fh := range allPostFilterHits {
			if fh.Score > maxFetchedScore {
				maxFetchedScore = fh.Score
			}
		}
		if hitsEnv, ok := resp["hits"].(map[string]any); ok {
			if curMax, _ := toFloat64(hitsEnv["max_score"]); maxFetchedScore > curMax {
				hitsEnv["max_score"] = maxFetchedScore
			}
		}
	}
	if req != nil && req.TerminateAfter != nil && *req.TerminateAfter > 0 {
		resp["terminated_early"] = terminatedEarly
	}
	if req != nil && req.Collapse != nil && req.Collapse.Field != "" && len(req.Collapse.InnerHits) > 0 && len(allHits) > 0 {
		s.populateCollapseInnerHits(ctx, targets, aliasFilters, schemasByIndex, primarySchema, req, allHits, resp)
	}
	if req != nil && len(req.Suggest) > 0 {
		resp["suggest"] = s.evaluateSearchSuggest(ctx, targets, aliasFilters, schemasByIndex, primarySchema, req, req.Suggest, allFetchedHits)
	}
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
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil && hasTermsLookupInQuery(req.Rescore[i].Query.RescoreQuery) {
			return true
		}
	}
	if req.Highlight != nil {
		if hasTermsLookupInQuery(req.Highlight.HighlightQuery) {
			return true
		}
		for fname := range req.Highlight.Fields {
			fSpec := req.Highlight.FieldSpec(fname)
			if hasTermsLookupInQuery(fSpec.HighlightQuery) {
				return true
			}
		}
	}
	for i := range req.Sort {
		if req.Sort[i].Entry.Nested != nil && hasTermsLookupInQuery(req.Sort[i].Entry.Nested.Filter) {
			return true
		}
	}
	if req.Collapse != nil {
		for i := range req.Collapse.InnerHits {
			if hasTermsLookupInInnerHits(&req.Collapse.InnerHits[i]) {
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

func hasTermsLookupInInnerHits(ih *esast.InnerHitsSpec) bool {
	if ih == nil {
		return false
	}
	for i := range ih.Sort {
		if ih.Sort[i].Entry.Nested != nil && hasTermsLookupInQuery(ih.Sort[i].Entry.Nested.Filter) {
			return true
		}
	}
	if ih.Highlight != nil {
		if hasTermsLookupInQuery(ih.Highlight.HighlightQuery) {
			return true
		}
		for fname := range ih.Highlight.Fields {
			fSpec := ih.Highlight.FieldSpec(fname)
			if hasTermsLookupInQuery(fSpec.HighlightQuery) {
				return true
			}
		}
	}
	return false
}

func hasTermsLookupInAggSpec(spec esast.AggSpec) bool {
	if spec.Filter != nil && hasTermsLookupInQuery(spec.Filter) {
		return true
	}
	if tSpec := spec.EffectiveTerms(); tSpec != nil && tSpec.BackgroundFilter != nil && hasTermsLookupInQuery(tSpec.BackgroundFilter) {
		return true
	}
	if spec.Composite != nil {
		for _, srcMap := range spec.Composite.Sources {
			for _, srcSpec := range srcMap {
				if hasTermsLookupInAggSpec(srcSpec) {
					return true
				}
			}
		}
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
	if spec.TopHits != nil {
		for i := range spec.TopHits.Sort {
			if spec.TopHits.Sort[i].Entry.Nested != nil && hasTermsLookupInQuery(spec.TopHits.Sort[i].Entry.Nested.Filter) {
				return true
			}
		}
		if spec.TopHits.Highlight != nil {
			if hasTermsLookupInQuery(spec.TopHits.Highlight.HighlightQuery) {
				return true
			}
			for fname := range spec.TopHits.Highlight.Fields {
				fSpec := spec.TopHits.Highlight.FieldSpec(fname)
				if hasTermsLookupInQuery(fSpec.HighlightQuery) {
					return true
				}
			}
		}
	}
	if spec.TopMetrics != nil {
		for i := range spec.TopMetrics.Sort {
			if spec.TopMetrics.Sort[i].Entry.Nested != nil && hasTermsLookupInQuery(spec.TopMetrics.Sort[i].Entry.Nested.Filter) {
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
	if q.Nested != nil {
		if hasTermsLookupInQuery(&q.Nested.Query) || hasTermsLookupInInnerHits(q.Nested.InnerHits) {
			return true
		}
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
	origRouting := req.Routing
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
			cloned.Routing = origRouting
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
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil {
			s.resolveTermsLookupsInQuery(ctx, req.Rescore[i].Query.RescoreQuery)
		}
	}
	if req.Highlight != nil {
		s.resolveTermsLookupsInQuery(ctx, req.Highlight.HighlightQuery)
		for fname := range req.Highlight.Fields {
			fSpec := req.Highlight.FieldSpec(fname)
			if fSpec.HighlightQuery != nil && hasTermsLookupInQuery(fSpec.HighlightQuery) {
				s.resolveTermsLookupsInQuery(ctx, fSpec.HighlightQuery)
				req.Highlight.Fields[fname] = fSpec
			}
		}
	}
	for i := range req.Sort {
		if req.Sort[i].Entry.Nested != nil && req.Sort[i].Entry.Nested.Filter != nil {
			s.resolveTermsLookupsInQuery(ctx, req.Sort[i].Entry.Nested.Filter)
		}
	}
	if req.Collapse != nil {
		for i := range req.Collapse.InnerHits {
			s.resolveTermsLookupsInInnerHits(ctx, &req.Collapse.InnerHits[i])
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

func (s *Server) resolveTermsLookupsInInnerHits(ctx context.Context, ih *esast.InnerHitsSpec) {
	if ih == nil {
		return
	}
	for i := range ih.Sort {
		if ih.Sort[i].Entry.Nested != nil && ih.Sort[i].Entry.Nested.Filter != nil {
			s.resolveTermsLookupsInQuery(ctx, ih.Sort[i].Entry.Nested.Filter)
		}
	}
	if ih.Highlight != nil {
		s.resolveTermsLookupsInQuery(ctx, ih.Highlight.HighlightQuery)
		for fname := range ih.Highlight.Fields {
			fSpec := ih.Highlight.FieldSpec(fname)
			if fSpec.HighlightQuery != nil && hasTermsLookupInQuery(fSpec.HighlightQuery) {
				s.resolveTermsLookupsInQuery(ctx, fSpec.HighlightQuery)
				ih.Highlight.Fields[fname] = fSpec
			}
		}
	}
}

func (s *Server) resolveTermsLookupsInAggSpec(ctx context.Context, spec *esast.AggSpec) {
	if spec == nil {
		return
	}
	if spec.Filter != nil {
		s.resolveTermsLookupsInQuery(ctx, spec.Filter)
	}
	if tSpec := spec.EffectiveTerms(); tSpec != nil && tSpec.BackgroundFilter != nil {
		s.resolveTermsLookupsInQuery(ctx, tSpec.BackgroundFilter)
	}
	if spec.Composite != nil {
		for i, srcMap := range spec.Composite.Sources {
			for k, srcSpec := range srcMap {
				s.resolveTermsLookupsInAggSpec(ctx, &srcSpec)
				spec.Composite.Sources[i][k] = srcSpec
			}
		}
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
	if spec.TopHits != nil {
		for i := range spec.TopHits.Sort {
			if spec.TopHits.Sort[i].Entry.Nested != nil && spec.TopHits.Sort[i].Entry.Nested.Filter != nil {
				s.resolveTermsLookupsInQuery(ctx, spec.TopHits.Sort[i].Entry.Nested.Filter)
			}
		}
		if spec.TopHits.Highlight != nil {
			s.resolveTermsLookupsInQuery(ctx, spec.TopHits.Highlight.HighlightQuery)
			for fname := range spec.TopHits.Highlight.Fields {
				fSpec := spec.TopHits.Highlight.FieldSpec(fname)
				if fSpec.HighlightQuery != nil && hasTermsLookupInQuery(fSpec.HighlightQuery) {
					s.resolveTermsLookupsInQuery(ctx, fSpec.HighlightQuery)
					spec.TopHits.Highlight.Fields[fname] = fSpec
				}
			}
		}
	}
	if spec.TopMetrics != nil {
		for i := range spec.TopMetrics.Sort {
			if spec.TopMetrics.Sort[i].Entry.Nested != nil && spec.TopMetrics.Sort[i].Entry.Nested.Filter != nil {
				s.resolveTermsLookupsInQuery(ctx, spec.TopMetrics.Sort[i].Entry.Nested.Filter)
			}
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
					if hit, found, err := s.backend.GetDocByID(ctx, lookupSchema.DorisDB, lookupSchema.DorisTable, lookup.ID); err == nil && found && hit != nil && len(hit.Source) > 0 && s.docMatchesAliasFilter(ctx, lookupIdx, lookup.ID, hit.Source, aliasFilter) && (lookup.Routing == "" || s.docMatchesRequestRouting(lookupIdx, lookup.ID, lookup.Routing)) {
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
		s.resolveTermsLookupsInInnerHits(ctx, q.Nested.InnerHits)
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

func extractDocFieldFromScriptAny(script any) string {
	src, _ := extractScriptSourceAndParams(script)
	if src == "" {
		return ""
	}
	idx := strings.Index(src, "doc[")
	if idx < 0 {
		return ""
	}
	rest := src[idx+4:]
	if len(rest) < 2 {
		return ""
	}
	quote := rest[0]
	if quote != '\'' && quote != '"' {
		return ""
	}
	end := strings.IndexByte(rest[1:], quote)
	if end <= 0 {
		return ""
	}
	return rest[1 : 1+end]
}

func singleValueMetricField(spec esast.AggSpec) string {
	fieldOrScript := func(f string, script any) string {
		if f != "" {
			return f
		}
		return extractDocFieldFromScriptAny(script)
	}
	switch {
	case spec.Min != nil:
		return fieldOrScript(spec.Min.Field, spec.Min.Script)
	case spec.Max != nil:
		return fieldOrScript(spec.Max.Field, spec.Max.Script)
	case spec.Avg != nil:
		return fieldOrScript(spec.Avg.Field, spec.Avg.Script)
	case spec.Sum != nil:
		return fieldOrScript(spec.Sum.Field, spec.Sum.Script)
	case spec.Percentiles != nil:
		return fieldOrScript(spec.Percentiles.Field, spec.Percentiles.Script)
	case spec.PercentileRanks != nil:
		return fieldOrScript(spec.PercentileRanks.Field, spec.PercentileRanks.Script)
	case spec.Boxplot != nil:
		return fieldOrScript(spec.Boxplot.Field, spec.Boxplot.Script)
	default:
		return ""
	}
}

func metricAggHasMissing(spec esast.AggSpec) bool {
	switch {
	case spec.Min != nil:
		return spec.Min.Missing != nil
	case spec.Max != nil:
		return spec.Max.Missing != nil
	case spec.Avg != nil:
		return spec.Avg.Missing != nil
	case spec.Sum != nil:
		return spec.Sum.Missing != nil
	case spec.ValueCount != nil:
		return spec.ValueCount.Missing != nil
	case spec.Cardinality != nil:
		return spec.Cardinality.Missing != nil
	case spec.Percentiles != nil:
		return spec.Percentiles.Missing != nil
	case spec.PercentileRanks != nil:
		return spec.PercentileRanks.Missing != nil
	case spec.Boxplot != nil:
		return spec.Boxplot.Missing != nil
	case spec.EffectiveStats() != nil:
		return spec.EffectiveStats().Missing != nil
	default:
		return false
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

func hitIsAfterSearchAfter(h HitRow, sorts []esast.SortSpec, searchAfter []any, idxSchema *schema.IndexSchema) bool {
	if len(searchAfter) == 0 {
		return true
	}
	effSorts := append([]esast.SortSpec(nil), sorts...)
	if len(effSorts) == 0 {
		effSorts = []esast.SortSpec{{Entry: esast.SortEntry{Field: "_score", Order: "desc"}}}
	}
	if len(searchAfter) > len(effSorts) {
		hasTiebreaker := false
		for _, sp := range effSorts {
			if sp.Entry.Field == "_id" || sp.Entry.Field == "_doc" {
				hasTiebreaker = true
				break
			}
		}
		if !hasTiebreaker {
			effSorts = append(effSorts, esast.SortSpec{Entry: esast.SortEntry{Field: "_id", Order: "asc"}})
		}
	}
	valsA := extractHitSortValues(h, effSorts, idxSchema)
	for idx, s := range effSorts {
		if idx >= len(valsA) || idx >= len(searchAfter) {
			break
		}
		va := valsA[idx]
		vb := searchAfter[idx]
		if jsonNum, ok := vb.(json.Number); ok {
			if iv, err := jsonNum.Int64(); err == nil {
				vb = iv
			} else if fv, err := jsonNum.Float64(); err == nil {
				vb = fv
			}
		}
		if strVal, ok := vb.(string); ok {
			if strings.EqualFold(s.Entry.Type, "boolean") {
				switch strings.ToLower(strings.TrimSpace(strVal)) {
				case "true", "1":
					vb = true
				case "false", "0":
					vb = false
				}
			}
			if idxSchema != nil {
				resolvedSortField := resolveSortEntryField(s, idxSchema)
				b := idxSchema.ResolveField(resolvedSortField)
				if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
					switch strings.ToLower(strings.TrimSpace(strVal)) {
					case "true", "1":
						vb = true
					case "false", "0":
						vb = false
					}
				} else if b.EffectiveLowercase(true) {
					vb = strings.ToLower(strVal)
				} else if b.ESType == "date" || b.ESType == "date_nanos" || b.DorisType == schema.DorisBigInt {
					if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
						vb = ms
					}
				}
			}
		} else if iv, ok := vb.(int64); ok && idxSchema != nil {
			resolvedSortField := resolveSortEntryField(s, idxSchema)
			b := idxSchema.ResolveField(resolvedSortField)
			if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean || strings.EqualFold(s.Entry.Type, "boolean") {
				vb = iv != 0
			}
		}
		if idxSchema != nil {
			resolvedSortField := resolveSortEntryField(s, idxSchema)
			b := idxSchema.ResolveField(resolvedSortField)
			if b.ESType == "date_nanos" {
				if fa, ok := toFloat64(va); ok && math.Abs(fa) > 1e15 {
					va = math.Trunc(fa / 1e6)
				}
				if fb, ok := toFloat64(vb); ok && math.Abs(fb) > 1e15 {
					vb = math.Trunc(fb / 1e6)
				}
			}
		}
		if va == nil && vb == nil {
			continue
		}
		missingFirst := s.Entry.Missing != "" && strings.EqualFold(s.Entry.Missing, "_first")
		if va == nil {
			return !missingFirst
		}
		if vb == nil {
			return missingFirst
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
			cmp = -cmp
		}
		return cmp > 0
	}
	return false
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
			if i > 0 && (strings.HasPrefix(part, "_stats_") || strings.HasPrefix(part, "_sstats_") || isSignedASCIIDigits(part)) {
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

func mergeMultiIndexAggRows(rows []AggRow, totalHits int64, totalQueryHits int64, aggs map[string]esast.AggSpec) []AggRow {
	type key struct {
		agg    string
		bucket string
	}
	type mergeAcc struct {
		row            AggRow
		count          int
		weightSum      int64
		weightedVal    float64
		combinedStates []any
	}
	merged := make(map[key]*mergeAcc)
	var order []key
	lastStatCount := make(map[key]int64)
	lastStatSum := make(map[key]float64)
	hasExplicitSumSq := make(map[key]bool)
	for _, r := range rows {
		if r.BucketKey == "_stats_sum_sq" {
			hasExplicitSumSq[key{agg: r.AggName, bucket: ""}] = true
		} else if strings.HasSuffix(r.AggName, "._stats_sum_sq") {
			hasExplicitSumSq[key{agg: strings.TrimSuffix(r.AggName, "._stats_sum_sq"), bucket: r.BucketKey}] = true
		}
	}
	accumulateRow := func(r AggRow) {
		spec := resolveAggSpecByPath(aggs, r.AggName)
		k := key{agg: r.AggName, bucket: r.BucketKey}
		var hasSM bool
		var smCombVal any
		if spec.ScriptedMetric != nil {
			if lb, _, combVal, ok := parseScriptedMetricBucketKey(r.BucketKey); ok {
				k.bucket = lb
				hasSM = true
				smCombVal = combVal
			}
		}
		val := r.effectiveValue()
		if r.Weight < 0 {
			if _, ok := merged[k]; !ok {
				cp := r
				cp.DocCount = r.effectiveCount()
				cp.Value = val
				merged[k] = &mergeAcc{
					row:         cp,
					count:       0,
					weightSum:   0,
					weightedVal: 0,
				}
				order = append(order, k)
			}
			return
		}
		wasPlaceholder := false
		if existing, ok := merged[k]; ok && existing.row.Weight < 0 {
			delete(merged, k)
			wasPlaceholder = true
		}
		w := r.Weight
		if w <= 0 {
			w = 1
		}
		isMin := r.BucketKey == "_stats_min" || r.BucketKey == "_sstats_min" ||
			strings.HasSuffix(r.AggName, "._stats_min") || strings.HasSuffix(r.AggName, "._sstats_min") || spec.Min != nil ||
			(spec.Boxplot != nil && (r.BucketKey == "0.0" || strings.HasSuffix(r.AggName, ".0.0")))
		isMax := r.BucketKey == "_stats_max" || r.BucketKey == "_sstats_max" ||
			strings.HasSuffix(r.AggName, "._stats_max") || strings.HasSuffix(r.AggName, "._sstats_max") || spec.Max != nil ||
			(spec.Boxplot != nil && (r.BucketKey == "100.0" || strings.HasSuffix(r.AggName, ".100.0")))
		if existing, ok := merged[k]; ok {
			existing.count++
			existing.weightSum += w
			existing.weightedVal += val * float64(w)
			if hasSM {
				existing.combinedStates = append(existing.combinedStates, smCombVal)
			}
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
			acc := &mergeAcc{
				row:         cp,
				count:       1,
				weightSum:   w,
				weightedVal: val * float64(w),
			}
			if hasSM {
				acc.combinedStates = []any{smCombVal}
			}
			merged[k] = acc
			if !wasPlaceholder {
				order = append(order, k)
			}
		}
	}
	for _, r := range rows {
		if r.AggName == "__meta_total" || r.AggName == "__meta_query_total" {
			continue
		}
		switch {
		case r.BucketKey == "_stats_count" || r.BucketKey == "_sstats_count":
			lastStatCount[key{agg: r.AggName, bucket: ""}] = r.effectiveCount()
		case strings.HasSuffix(r.AggName, "._stats_count"):
			lastStatCount[key{agg: strings.TrimSuffix(r.AggName, "._stats_count"), bucket: r.BucketKey}] = r.effectiveCount()
		case strings.HasSuffix(r.AggName, "._sstats_count"):
			lastStatCount[key{agg: strings.TrimSuffix(r.AggName, "._sstats_count"), bucket: r.BucketKey}] = r.effectiveCount()
		case r.BucketKey == "_stats_min" || r.BucketKey == "_stats_max" || r.BucketKey == "_stats_avg" ||
			r.BucketKey == "_sstats_min" || r.BucketKey == "_sstats_max" || r.BucketKey == "_sstats_avg" || r.BucketKey == "_sstats_entropy":
			cnt := lastStatCount[key{agg: r.AggName, bucket: ""}]
			if cnt == 0 {
				r.Weight = -1
			} else if r.Weight <= 0 {
				r.Weight = cnt
			}
		case strings.HasSuffix(r.AggName, "._stats_min") || strings.HasSuffix(r.AggName, "._stats_max") || strings.HasSuffix(r.AggName, "._stats_avg") ||
			strings.HasSuffix(r.AggName, "._sstats_min") || strings.HasSuffix(r.AggName, "._sstats_max") || strings.HasSuffix(r.AggName, "._sstats_avg") || strings.HasSuffix(r.AggName, "._sstats_entropy"):
			dotIdx := strings.LastIndex(r.AggName, ".")
			baseAgg := r.AggName[:dotIdx]
			cnt := lastStatCount[key{agg: baseAgg, bucket: r.BucketKey}]
			if cnt == 0 {
				r.Weight = -1
			} else if r.Weight <= 0 {
				r.Weight = cnt
			}
		case r.BucketKey == "_stats_sum":
			lastStatSum[key{agg: r.AggName, bucket: ""}] = r.effectiveValue()
		case strings.HasSuffix(r.AggName, "._stats_sum"):
			lastStatSum[key{agg: strings.TrimSuffix(r.AggName, "._stats_sum"), bucket: r.BucketKey}] = r.effectiveValue()
		case r.BucketKey == "_stats_std":
			sk := key{agg: r.AggName, bucket: ""}
			cnt := lastStatCount[sk]
			if cnt == 0 {
				r.Weight = -1
			} else if r.Weight <= 0 {
				r.Weight = cnt
			}
			if !hasExplicitSumSq[sk] && cnt > 0 {
				avg := lastStatSum[sk] / float64(cnt)
				std := r.effectiveValue()
				sq := float64(cnt) * (std*std + avg*avg)
				accumulateRow(AggRow{AggName: r.AggName, BucketKey: "_stats_sum_sq", DocCount: int64(sq), Value: sq})
			}
		case strings.HasSuffix(r.AggName, "._stats_std"):
			baseAgg := strings.TrimSuffix(r.AggName, "._stats_std")
			sk := key{agg: baseAgg, bucket: r.BucketKey}
			cnt := lastStatCount[sk]
			if cnt == 0 {
				r.Weight = -1
			} else if r.Weight <= 0 {
				r.Weight = cnt
			}
			if !hasExplicitSumSq[sk] && cnt > 0 {
				avg := lastStatSum[sk] / float64(cnt)
				std := r.effectiveValue()
				sq := float64(cnt) * (std*std + avg*avg)
				accumulateRow(AggRow{AggName: baseAgg + "._stats_sum_sq", BucketKey: r.BucketKey, DocCount: int64(sq), Value: sq})
			}
		}
		accumulateRow(r)
	}
	out := []AggRow{{AggName: "__meta_total", BucketKey: "_count", DocCount: totalHits, Value: float64(totalHits)}}
	if totalQueryHits > 0 && totalQueryHits != totalHits {
		out = append(out, AggRow{AggName: "__meta_query_total", BucketKey: "_count", DocCount: totalQueryHits, Value: float64(totalQueryHits)})
	}
	for _, k := range order {
		acc := merged[k]
		spec := resolveAggSpecByPath(aggs, k.agg)
		if spec.ScriptedMetric != nil && len(acc.combinedStates) > 0 {
			smRes := evalScriptedMetricReduce(spec.ScriptedMetric, acc.combinedStates)
			rawReduced, _ := json.Marshal(smRes)
			acc.row.BucketKey = k.bucket + "\x00" + string(rawReduced)
			if fv, ok := toFloat64(smRes); ok {
				acc.row.Value = fv
				acc.row.DocCount = int64(fv)
			}
			out = append(out, acc.row)
			continue
		}
		if k.bucket == "_stats_avg" || strings.HasSuffix(k.agg, "._stats_avg") {
			cntKey := key{agg: k.agg, bucket: "_stats_count"}
			sumKey := key{agg: k.agg, bucket: "_stats_sum"}
			if strings.HasSuffix(k.agg, "._stats_avg") {
				baseAgg := strings.TrimSuffix(k.agg, "._stats_avg")
				cntKey = key{agg: baseAgg + "._stats_count", bucket: k.bucket}
				sumKey = key{agg: baseAgg + "._stats_sum", bucket: k.bucket}
			}
			if cntAcc, okC := merged[cntKey]; okC {
				if sumAcc, okS := merged[sumKey]; okS {
					if cnt := cntAcc.row.effectiveCount(); cnt > 0 {
						acc.row.Value = sumAcc.row.Value / float64(cnt)
						acc.row.DocCount = int64(acc.row.Value)
						out = append(out, acc.row)
						continue
					}
				}
			}
		}
		if k.bucket == "_stats_std" || strings.HasSuffix(k.agg, "._stats_std") {
			cntKey := key{agg: k.agg, bucket: "_stats_count"}
			sumKey := key{agg: k.agg, bucket: "_stats_sum"}
			sqKey := key{agg: k.agg, bucket: "_stats_sum_sq"}
			if strings.HasSuffix(k.agg, "._stats_std") {
				baseAgg := strings.TrimSuffix(k.agg, "._stats_std")
				cntKey = key{agg: baseAgg + "._stats_count", bucket: k.bucket}
				sumKey = key{agg: baseAgg + "._stats_sum", bucket: k.bucket}
				sqKey = key{agg: baseAgg + "._stats_sum_sq", bucket: k.bucket}
			}
			if cntAcc, okC := merged[cntKey]; okC {
				if sumAcc, okS := merged[sumKey]; okS {
					if sqAcc, okQ := merged[sqKey]; okQ {
						if cnt := cntAcc.row.effectiveCount(); cnt > 0 {
							avg := sumAcc.row.Value / float64(cnt)
							variance := (sqAcc.row.Value / float64(cnt)) - (avg * avg)
							if variance < 0 {
								variance = 0
							}
							acc.row.Value = math.Sqrt(variance)
							acc.row.DocCount = int64(acc.row.Value)
							out = append(out, acc.row)
							continue
						}
					}
				}
			}
		}
		isBoxplotQuartile := spec.Boxplot != nil && k.bucket != "0.0" && k.bucket != "100.0" &&
			!strings.HasSuffix(k.agg, ".0.0") && !strings.HasSuffix(k.agg, ".100.0")
		isAvgLike := k.bucket == "_stats_avg" || k.bucket == "_sstats_avg" ||
			k.bucket == "_stats_std" || k.bucket == "_stats_entropy" || k.bucket == "_sstats_entropy" ||
			strings.HasSuffix(k.agg, "._stats_avg") || strings.HasSuffix(k.agg, "._sstats_avg") ||
			strings.HasSuffix(k.agg, "._stats_std") || strings.HasSuffix(k.agg, "._stats_entropy") || strings.HasSuffix(k.agg, "._sstats_entropy") ||
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
	countResp := map[string]any{
		"count":   count,
		"_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
	}
	if termEarly, ok := resp["terminated_early"].(bool); ok {
		countResp["terminated_early"] = termEarly
	}
	writeJSON(w, http.StatusOK, countResp)
}

func (s *Server) resolveIndexBoostFactor(indexName string, boosts map[string]float64) (float64, bool) {
	if len(boosts) == 0 || indexName == "" {
		return 1.0, false
	}
	if b, ok := boosts[indexName]; ok {
		return b, true
	}
	s.mu.RLock()
	for alias, targets := range s.aliases {
		if b, ok := boosts[alias]; ok {
			for _, t := range targets {
				if t == indexName {
					s.mu.RUnlock()
					return b, true
				}
			}
		}
	}
	s.mu.RUnlock()
	for pat, b := range boosts {
		if strings.ContainsAny(pat, "*?,") || strings.HasPrefix(pat, "-") || pat == "_all" {
			if matchMultiWildcardWithExclusions(pat, indexName) {
				return b, true
			}
		}
	}
	return 1.0, false
}

func applyURISearchParams(r *http.Request, req *esast.SearchRequest) {
	q := r.URL.Query()
	if qStr := q.Get("q"); qStr != "" && req.Query == nil {
		qs := &esast.QueryStringQuery{
			Query:            qStr,
			DefaultField:     q.Get("df"),
			DefaultOperator:  q.Get("default_operator"),
			QuoteFieldSuffix: q.Get("quote_field_suffix"),
		}
		if q.Has("analyze_wildcard") {
			aw := isTruthyBoolQueryParam(r, "analyze_wildcard")
			qs.AnalyzeWildcard = &aw
		}
		if q.Has("lenient") {
			ln := isTruthyBoolQueryParam(r, "lenient")
			qs.Lenient = &ln
		}
		req.Query = &esast.Query{
			QueryString: qs,
		}
	}
	if q.Has("version") {
		req.Version = isTruthyBoolQueryParam(r, "version")
	}
	if q.Has("seq_no_primary_term") {
		req.SeqNoPrimaryTerm = isTruthyBoolQueryParam(r, "seq_no_primary_term")
	}
	if q.Has("explain") {
		req.Explain = isTruthyBoolQueryParam(r, "explain")
	}
	if msStr := q.Get("min_score"); msStr != "" && req.MinScore == nil {
		if ms, err := strconv.ParseFloat(msStr, 64); err == nil {
			req.MinScore = &ms
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
	if taStr := q.Get("terminate_after"); taStr != "" && req.TerminateAfter == nil {
		if ta, err := strconv.Atoi(taStr); err == nil && ta > 0 {
			req.TerminateAfter = &ta
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
	if ts := q.Get("track_scores"); ts != "" && req.TrackScores == nil {
		b := strings.EqualFold(ts, "true") || ts == "1"
		req.TrackScores = &b
	}
	if sortVals := q["sort"]; len(sortVals) > 0 && len(req.Sort) == 0 {
		for _, sortParam := range sortVals {
			for _, part := range strings.Split(sortParam, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
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
	}
	if srcVals := q["_source"]; len(srcVals) > 0 && req.Source == nil {
		for _, srcParam := range srcVals {
			if srcParam == "false" {
				req.Source = &esast.SourceFilter{Disabled: true}
			} else if srcParam != "true" && srcParam != "" {
				if req.Source == nil {
					req.Source = &esast.SourceFilter{}
				}
				req.Source.Disabled = false
				req.Source.Includes = append(req.Source.Includes, strings.Split(srcParam, ",")...)
			}
		}
	}
	for _, key := range []string{"_source_includes", "_source_include"} {
		for _, inc := range q[key] {
			if inc != "" {
				if req.Source == nil {
					req.Source = &esast.SourceFilter{}
				}
				req.Source.Disabled = false
				req.Source.Includes = append(req.Source.Includes, strings.Split(inc, ",")...)
			}
		}
	}
	for _, key := range []string{"_source_excludes", "_source_exclude"} {
		for _, exc := range q[key] {
			if exc != "" {
				if req.Source == nil {
					req.Source = &esast.SourceFilter{}
				}
				req.Source.Disabled = false
				req.Source.Excludes = append(req.Source.Excludes, strings.Split(exc, ",")...)
			}
		}
	}
	if sfVals := q["stored_fields"]; len(sfVals) > 0 && req.StoredFields == nil {
		req.StoredFields = strings.Join(sfVals, ",")
	}
	if fVals := q["fields"]; len(fVals) > 0 && len(req.Fields) == 0 {
		for _, fv := range fVals {
			for _, part := range strings.Split(fv, ",") {
				if p := strings.TrimSpace(part); p != "" {
					req.Fields = append(req.Fields, esast.FieldRequestSpec{Field: p})
				}
			}
		}
	}
	if dvVals := q["docvalue_fields"]; len(dvVals) > 0 && len(req.DocvalueFields) == 0 {
		for _, dvv := range dvVals {
			for _, part := range strings.Split(dvv, ",") {
				if p := strings.TrimSpace(part); p != "" {
					req.DocvalueFields = append(req.DocvalueFields, esast.FieldRequestSpec{Field: p})
				}
			}
		}
	}
	if strings.EqualFold(q.Get("search_type"), "count") {
		zero := 0
		req.Size = &zero
		if req.TrackTotalHits == nil {
			req.TrackTotalHits = true
		}
	}
	if rtVals := q["routing"]; len(rtVals) > 0 {
		var rts []string
		for _, rv := range rtVals {
			if t := strings.TrimSpace(rv); t != "" {
				rts = append(rts, t)
			}
		}
		if len(rts) > 0 {
			req.Routing = strings.Join(rts, ",")
		}
	}
}

func aggTypePrefix(spec esast.AggSpec) string {
	switch {
	case spec.SignificantText != nil:
		return "significant_text"
	case spec.IsSignificantTerms():
		return "sterms"
	case spec.EffectiveTerms() != nil:
		return "sterms"
	case spec.DateHistogram != nil:
		return "date_histogram"
	case spec.Histogram != nil:
		return "histogram"
	case spec.DateRange != nil:
		return "date_range"
	case spec.IPRange != nil:
		return "ip_range"
	case spec.Range != nil:
		return "range"
	case spec.Filters != nil:
		return "filters"
	case spec.Filter != nil:
		return "filter"
	case spec.Missing != nil:
		return "missing"
	case spec.Nested != nil:
		return "nested"
	case spec.ReverseNested != nil:
		return "reverse_nested"
	case spec.Global != nil:
		return "global"
	case spec.DiversifiedSampler != nil:
		return "diversified_sampler"
	case spec.Sampler != nil:
		return "sampler"
	case spec.Composite != nil:
		return "composite"
	case spec.Avg != nil:
		return "avg"
	case spec.Sum != nil:
		return "sum"
	case spec.Min != nil:
		return "min"
	case spec.Max != nil:
		return "max"
	case spec.ValueCount != nil:
		return "value_count"
	case spec.Cardinality != nil:
		return "cardinality"
	case spec.ExtendedStats != nil:
		return "extended_stats"
	case spec.Stats != nil:
		return "stats"
	case spec.StringStats != nil:
		return "string_stats"
	case spec.Percentiles != nil:
		return "tdigest_percentiles"
	case spec.PercentileRanks != nil:
		return "tdigest_percentile_ranks"
	case spec.Boxplot != nil:
		return "boxplot"
	case spec.TopHits != nil:
		return "top_hits"
	case spec.TopMetrics != nil:
		return "top_metrics"
	case spec.ScriptedMetric != nil:
		return "scripted_metric"
	case spec.Rate != nil:
		return "rate"
	case spec.AvgBucket != nil:
		return "avg_bucket"
	case spec.SumBucket != nil:
		return "sum_bucket"
	case spec.MinBucket != nil:
		return "min_bucket"
	case spec.MaxBucket != nil:
		return "max_bucket"
	case spec.StatsBucket != nil:
		return "stats_bucket"
	case spec.ExtendedStatsBucket != nil:
		return "extended_stats_bucket"
	case spec.PercentilesBucket != nil:
		return "percentiles_bucket"
	case spec.Derivative != nil:
		return "derivative"
	case spec.CumulativeCardinality != nil:
		return "cumulative_cardinality"
	case spec.EffectiveCumulative() != nil:
		return "cumulative_sum"
	case spec.MovingAvg != nil:
		return "moving_avg"
	case spec.EffectiveMovingAvg() != nil:
		return "moving_fn"
	case spec.SerialDiff != nil:
		return "serial_diff"
	case spec.Normalize != nil:
		return "normalize"
	case spec.BucketScript != nil:
		return "bucket_script"
	case spec.BucketSort != nil:
		return "bucket_sort"
	case spec.BucketSelector != nil:
		return "bucket_selector"
	case spec.RareTerms != nil:
		return "rare_terms"
	case spec.MultiTerms != nil:
		return "multi_terms"
	case spec.AutoDateHistogram != nil:
		return "auto_date_histogram"
	case spec.VariableWidthHistogram != nil:
		return "variable_width_histogram"
	case spec.WeightedAvg != nil:
		return "weighted_avg"
	case spec.MedianAbsoluteDeviation != nil:
		return "median_absolute_deviation"
	case spec.GeoBounds != nil:
		return "geo_bounds"
	case spec.GeoCentroid != nil:
		return "geo_centroid"
	case spec.GeoDistance != nil:
		return "geo_distance"
	case spec.GeohashGrid != nil:
		return "geohash_grid"
	case spec.GeotileGrid != nil:
		return "geotile_grid"
	case spec.AdjacencyMatrix != nil:
		return "adjacency_matrix"
	case spec.MatrixStats != nil:
		return "matrix_stats"
	case spec.TTest != nil:
		return "t_test"
	default:
		return "agg"
	}
}

func applyTypedKeysToAggregations(aggsOut map[string]any, aggs map[string]esast.AggSpec) {
	if len(aggsOut) == 0 || len(aggs) == 0 {
		return
	}
	for aggName, spec := range aggs {
		val, exists := aggsOut[aggName]
		if !exists {
			continue
		}
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			if aggObj, ok := val.(map[string]any); ok {
				if buckets, ok := aggObj["buckets"].([]map[string]any); ok {
					for _, b := range buckets {
						applyTypedKeysToAggregations(b, subAggs)
					}
				} else if bucketsAny, ok := aggObj["buckets"].([]any); ok {
					for _, item := range bucketsAny {
						if b, ok := item.(map[string]any); ok {
							applyTypedKeysToAggregations(b, subAggs)
						}
					}
				} else if bucketsMap, ok := aggObj["buckets"].(map[string]any); ok {
					for _, bv := range bucketsMap {
						if bm, ok := bv.(map[string]any); ok {
							applyTypedKeysToAggregations(bm, subAggs)
						}
					}
				} else {
					applyTypedKeysToAggregations(aggObj, subAggs)
				}
			}
		}
		prefix := aggTypePrefix(spec)
		delete(aggsOut, aggName)
		aggsOut[prefix+"#"+aggName] = val
	}
}

func applyTypedKeysToSuggestions(suggestOut map[string]any, specs map[string]esast.SuggestSpec) {
	if len(suggestOut) == 0 || len(specs) == 0 {
		return
	}
	for name, spec := range specs {
		if name == "text" && spec.Term == nil && spec.Phrase == nil && spec.Completion == nil {
			continue
		}
		val, exists := suggestOut[name]
		if !exists {
			continue
		}
		prefix := "term"
		switch {
		case spec.Completion != nil:
			prefix = "completion"
		case spec.Phrase != nil:
			prefix = "phrase"
		case spec.Term != nil:
			prefix = "term"
		}
		delete(suggestOut, name)
		suggestOut[prefix+"#"+name] = val
	}
}

func (s *Server) evaluateSearchSuggest(
	ctx context.Context,
	targets []string,
	aliasFilters map[string]*esast.Query,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
	req *esast.SearchRequest,
	specs map[string]esast.SuggestSpec,
	fetchedHits []HitRow,
) map[string]any {
	candHits := fetchedHits
	if len(candHits) == 0 || (req != nil && (req.Query != nil || req.Size != nil)) {
		candHits = nil
		zero := 0
		fetchLimit := 1000
		for _, idxName := range targets {
			idxSchema := schemasByIndex[idxName]
			if idxSchema == nil {
				idxSchema = s.ensureIndexSchema(ctx, idxName)
			}
			tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
			sReq := esast.SearchRequest{
				From:  &zero,
				Size:  &fetchLimit,
				Query: aliasFilters[idxName],
			}
			if plan, err := tr.BuildSearchPlan(&sReq); err == nil && plan.HitsSQL != "" {
				if rows, qErr := s.backend.QueryHits(ctx, plan.HitsSQL); qErr == nil {
					for i := range rows {
						rows[i].Index = idxName
					}
					candHits = append(candHits, rows...)
				}
			}
		}
	}
	globalText := ""
	if gt, ok := specs["text"]; ok && gt.Term == nil && gt.Phrase == nil && gt.Completion == nil {
		globalText = gt.Text
	}
	type docParsed struct {
		hit    HitRow
		doc    map[string]any
		schema *schema.IndexSchema
	}
	parsedDocs := make([]docParsed, 0, len(candHits))
	for _, h := range candHits {
		var dm map[string]any
		if raw := h.EffectiveSource(); len(raw) > 0 {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			_ = dec.Decode(&dm)
		}
		if dm == nil {
			continue
		}
		hs := schemasByIndex[h.Index]
		if hs == nil {
			hs = primarySchema
		}
		if af := aliasFilters[h.Index]; af != nil && queryHasRuntimeScript(af) {
			dm["__meta_id"] = h.ID
			if !evalQueryScriptFilterOnDocWithSchema(hs, dm, af) {
				continue
			}
		}
		parsedDocs = append(parsedDocs, docParsed{hit: h, doc: dm, schema: hs})
	}
	extractFieldStrings := func(dp docParsed, field string) []string {
		clean := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
		segs := strings.Split(clean, ".")
		if dp.schema != nil {
			if b := dp.schema.ResolveField(field); len(b.SourceJSONPath) > 0 {
				segs = b.SourceJSONPath
			}
		}
		vals := collectSchemaAwareScalarValues(dp.doc, field, segs, dp.schema)
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			if str, ok := v.(string); ok && strings.TrimSpace(str) != "" {
				out = append(out, str)
			} else if m, ok := v.(map[string]any); ok {
				if inp, exists := m["input"]; exists {
					switch tv := inp.(type) {
					case string:
						out = append(out, tv)
					case []any:
						for _, el := range tv {
							if s, okS := el.(string); okS {
								out = append(out, s)
							}
						}
					}
				}
			}
		}
		return out
	}
	tokenizeWords := func(text string) []string {
		return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_'
		})
	}
	levenshtein := func(a, b string) int {
		ra, rb := []rune(a), []rune(b)
		la, lb := len(ra), len(rb)
		if la == 0 {
			return lb
		}
		if lb == 0 {
			return la
		}
		dp := make([]int, lb+1)
		for j := 0; j <= lb; j++ {
			dp[j] = j
		}
		for i := 1; i <= la; i++ {
			prev := dp[0]
			dp[0] = i
			for j := 1; j <= lb; j++ {
				temp := dp[j]
				cost := 0
				if ra[i-1] != rb[j-1] {
					cost = 1
				}
				del := dp[j] + 1
				ins := dp[j-1] + 1
				sub := prev + cost
				m := del
				if ins < m {
					m = ins
				}
				if sub < m {
					m = sub
				}
				dp[j] = m
				prev = temp
			}
		}
		return dp[lb]
	}
	out := make(map[string]any, len(specs))
	for name, spec := range specs {
		if name == "text" && spec.Term == nil && spec.Phrase == nil && spec.Completion == nil {
			continue
		}
		text := spec.Text
		if text == "" {
			text = spec.Prefix
		}
		if text == "" {
			text = spec.Regex
		}
		if text == "" {
			text = globalText
		}
		switch {
		case spec.Completion != nil:
			cs := spec.Completion
			limit := cs.Size
			if limit <= 0 {
				limit = 5
			}
			regexPat := strings.TrimSpace(spec.Regex)
			if regexPat == "" && cs.Regex != nil {
				if p, ok := cs.Regex["pattern"].(string); ok {
					regexPat = strings.TrimSpace(p)
				}
			}
			var completionRE *regexp.Regexp
			if regexPat != "" {
				if re, err := regexp.Compile("(?i)" + regexPat); err == nil {
					completionRE = re
				} else if re2, err2 := regexp.Compile(regexPat); err2 == nil {
					completionRE = re2
				}
			}
			prefixLower := strings.ToLower(strings.TrimSpace(text))
			maxFuzzy := 0
			if cs.Fuzzy != nil {
				if fv, ok := cs.Fuzzy["fuzziness"]; ok {
					if iv, okI := toInt64(fv); okI && iv > 0 {
						maxFuzzy = int(iv)
					} else {
						maxFuzzy = 1
					}
				} else {
					maxFuzzy = 1
				}
			}
			var opts []map[string]any
			seenText := make(map[string]bool)
			for _, dp := range parsedDocs {
				for _, str := range extractFieldStrings(dp, cs.Field) {
					strLower := strings.ToLower(str)
					var matched bool
					score := 1.0
					if regexPat != "" {
						matched = completionRE != nil && (completionRE.MatchString(str) || completionRE.MatchString(strLower))
					} else {
						matched = strings.HasPrefix(strLower, prefixLower)
						if !matched && maxFuzzy > 0 && len(prefixLower) > 0 {
							prefixRunes := []rune(prefixLower)
							strRunes := []rune(strLower)
							candPrefix := strLower
							if len(strRunes) > len(prefixRunes) {
								candPrefix = string(strRunes[:len(prefixRunes)])
							}
							if d := levenshtein(prefixLower, candPrefix); d <= maxFuzzy {
								matched = true
								score = 1.0 / float64(1+d)
							}
						}
					}
					if matched {
						if cs.SkipDuplicates && seenText[str] {
							continue
						}
						seenText[str] = true
						opt := map[string]any{
							"text":   str,
							"_index": dp.hit.Index,
							"_id":    dp.hit.ID,
							"_score": score,
						}
						if req == nil || req.Source == nil || !req.Source.Disabled {
							var reqSF *esast.SourceFilter
							if req != nil {
								reqSF = req.Source
							}
							opt["_source"] = filterSourceJSON(dp.hit.Source, reqSF)
						}
						opts = append(opts, opt)
					}
				}
			}
			if len(opts) > limit {
				opts = opts[:limit]
			}
			if opts == nil {
				opts = []map[string]any{}
			}
			out[name] = []map[string]any{
				{
					"text":    text,
					"offset":  0,
					"length":  utf8.RuneCountInString(text),
					"options": opts,
				},
			}
		case spec.Phrase != nil:
			ps := spec.Phrase
			limit := ps.Size
			if limit <= 0 {
				limit = 5
			}
			vocabFreq := make(map[string]int)
			for _, dp := range parsedDocs {
				for _, str := range extractFieldStrings(dp, ps.Field) {
					for _, w := range tokenizeWords(str) {
						vocabFreq[w]++
					}
				}
			}
			words := tokenizeWords(text)
			bestWords := make([]string, len(words))
			changed := false
			preTag, postTag := "<em>", "</em>"
			if ps.Highlight != nil {
				if ps.Highlight.PreTag != "" {
					preTag = ps.Highlight.PreTag
				}
				if ps.Highlight.PostTag != "" {
					postTag = ps.Highlight.PostTag
				}
			}
			hlWords := make([]string, len(words))
			for i, w := range words {
				bestW := w
				bestDist := 3
				bestFreq := vocabFreq[w]
				if bestFreq == 0 {
					for cand, freq := range vocabFreq {
						d := levenshtein(w, cand)
						if d > 0 && d <= 2 && (d < bestDist || (d == bestDist && freq > bestFreq)) {
							bestW = cand
							bestDist = d
							bestFreq = freq
						}
					}
				}
				bestWords[i] = bestW
				if bestW != w {
					changed = true
					hlWords[i] = preTag + bestW + postTag
				} else {
					hlWords[i] = bestW
				}
			}
			var opts []map[string]any
			if changed && len(bestWords) <= limit {
				opt := map[string]any{
					"text":  strings.Join(bestWords, " "),
					"score": 1.0,
				}
				if ps.Highlight != nil {
					opt["highlighted"] = strings.Join(hlWords, " ")
				}
				opts = append(opts, opt)
			}
			if opts == nil {
				opts = []map[string]any{}
			}
			out[name] = []map[string]any{
				{
					"text":    text,
					"offset":  0,
					"length":  utf8.RuneCountInString(text),
					"options": opts,
				},
			}
		default: // Term suggester
			ts := spec.Term
			field := ""
			limit := 5
			maxEdits := 2
			mode := "missing"
			if ts != nil {
				field = ts.Field
				if ts.Size > 0 {
					limit = ts.Size
				}
				if ts.MaxEdits > 0 {
					maxEdits = ts.MaxEdits
				}
				if ts.SuggestMode != "" {
					mode = strings.ToLower(ts.SuggestMode)
				}
			}
			vocabFreq := make(map[string]int)
			for _, dp := range parsedDocs {
				seenInDoc := make(map[string]bool)
				for _, str := range extractFieldStrings(dp, field) {
					for _, w := range tokenizeWords(str) {
						if !seenInDoc[w] {
							seenInDoc[w] = true
							vocabFreq[w]++
						}
					}
				}
			}
			tokens := tokenizeWords(text)
			entries := make([]map[string]any, 0, len(tokens))
			searchOffset := 0
			lowerText := strings.ToLower(text)
			for _, tok := range tokens {
				idx := strings.Index(lowerText[searchOffset:], tok)
				tokOffset := searchOffset
				if idx >= 0 {
					tokOffset = searchOffset + idx
					searchOffset = tokOffset + len(tok)
				}
				origFreq := vocabFreq[tok]
				type candOpt struct {
					word  string
					score float64
					freq  int
				}
				var cands []candOpt
				if mode != "missing" || origFreq == 0 {
					for cand, freq := range vocabFreq {
						if cand == tok {
							continue
						}
						if mode == "popular" && freq <= origFreq {
							continue
						}
						d := levenshtein(tok, cand)
						if d > 0 && d <= maxEdits {
							maxLen := utf8.RuneCountInString(tok)
							if candLen := utf8.RuneCountInString(cand); candLen > maxLen {
								maxLen = candLen
							}
							sc := 1.0 - float64(d)/float64(maxLen)
							cands = append(cands, candOpt{word: cand, score: math.Round(sc*100) / 100, freq: freq})
						}
					}
				}
				sort.SliceStable(cands, func(i, j int) bool {
					if cands[i].score != cands[j].score {
						return cands[i].score > cands[j].score
					}
					if cands[i].freq != cands[j].freq {
						return cands[i].freq > cands[j].freq
					}
					return cands[i].word < cands[j].word
				})
				if len(cands) > limit {
					cands = cands[:limit]
				}
				opts := make([]map[string]any, 0, len(cands))
				for _, c := range cands {
					opts = append(opts, map[string]any{
						"text":  c.word,
						"score": c.score,
						"freq":  c.freq,
					})
				}
				entries = append(entries, map[string]any{
					"text":    tok,
					"offset":  utf8.RuneCountInString(lowerText[:tokOffset]),
					"length":  utf8.RuneCountInString(tok),
					"options": opts,
				})
			}
			out[name] = entries
		}
	}
	return out
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
		if h.Routing != "" {
			hitMap["_routing"] = h.Routing
		}
		if req != nil && req.Version {
			ver := h.Version
			if ver <= 0 {
				ver = 1
			}
			hitMap["_version"] = ver
		}
		if req != nil && req.SeqNoPrimaryTerm {
			ver := h.Version
			if ver <= 0 {
				ver = 1
			}
			hitMap["_seq_no"] = ver
			hitMap["_primary_term"] = 1
		}
		if req != nil && req.Explain {
			hitMap["_explanation"] = map[string]any{
				"value":       h.Score,
				"description": "score computed by Doris ES Proxy",
				"details":     []any{},
			}
		}
		if (req.Source == nil || !req.Source.Disabled) && (!req.HasStoredFieldsNone() || req.Source != nil) {
			hitMap["_source"] = filterSourceJSON(h.Source, req.Source)
		}
		if req.Highlight != nil && len(req.Highlight.Fields) > 0 {
			if hl := buildHighlightMapWithSchema(h.EffectiveSource(), req, hitSchema); len(hl) > 0 {
				hitMap["highlight"] = hl
			}
		}
		if effSorts := transpiler.EffectiveSortsForRequest(req); len(effSorts) > 0 {
			hitMap["sort"] = extractHitSortValues(h, effSorts, hitSchema)
		}
		if len(req.EffectiveFieldSpecs()) > 0 {
			if fm := extractHitFieldsMap(h, hitIdx, req, hitSchema); len(fm) > 0 {
				hitMap["fields"] = fm
			}
		}
		if req != nil && len(req.ScriptFields) > 0 {
			if sfm := evalHitScriptFields(h, req.ScriptFields, hitSchema); len(sfm) > 0 {
				fm, _ := hitMap["fields"].(map[string][]any)
				if fm == nil {
					fm = make(map[string][]any, len(sfm))
				}
				for k, v := range sfm {
					fm[k] = v
				}
				hitMap["fields"] = fm
			}
		}
		if req != nil && req.Collapse != nil && req.Collapse.Field != "" {
			collapseSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: req.Collapse.Field}}}
			cVals := extractHitSortValues(h, collapseSort, hitSchema)
			if len(cVals) > 0 && cVals[0] != nil {
				fm, _ := hitMap["fields"].(map[string][]any)
				if fm == nil {
					fm = make(map[string][]any)
				}
				if _, exists := fm[req.Collapse.Field]; !exists {
					fm[req.Collapse.Field] = []any{cVals[0]}
				}
				hitMap["fields"] = fm
			}
		}
		if req != nil {
			var docForIH map[string]any
			var decodeOnce sync.Once
			getDoc := func() map[string]any {
				decodeOnce.Do(func() {
					rawSrc := h.EffectiveSource()
					if len(rawSrc) > 0 {
						dec := json.NewDecoder(bytes.NewReader(rawSrc))
						dec.UseNumber()
						_ = dec.Decode(&docForIH)
					}
					if docForIH == nil {
						docForIH = make(map[string]any)
					}
					docForIH["__meta_id"] = h.ID
				})
				return docForIH
			}
			var nestedWithIH []*esast.NestedQuery
			collectMatchingNestedQueriesWithInnerHits(hitSchema, getDoc, req.Query, &nestedWithIH)
			collectMatchingNestedQueriesWithInnerHits(hitSchema, getDoc, req.PostFilter, &nestedWithIH)
			if len(nestedWithIH) > 0 {
				ihMap, _ := hitMap["inner_hits"].(map[string]any)
				if ihMap == nil {
					ihMap = make(map[string]any, len(nestedWithIH))
				}
				ihNameCounts := make(map[string]int, len(nestedWithIH))
				ihSpecByName := make(map[string]*esast.InnerHitsSpec, len(nestedWithIH))
				ihPathByName := make(map[string]string, len(nestedWithIH))
				for _, nq := range nestedWithIH {
					ihName := nq.Path
					if nq.InnerHits.Name != "" {
						ihName = nq.InnerHits.Name
					}
					ihNameCounts[ihName]++
					nextSpec := nq.InnerHits
					if req.TrackScores != nil && *req.TrackScores && nextSpec != nil && nextSpec.TrackScores == nil {
						ihCopy := *nextSpec
						ihCopy.TrackScores = req.TrackScores
						nextSpec = &ihCopy
					}
					if prevSpec := ihSpecByName[ihName]; prevSpec != nil && nextSpec != nil {
						mergedSpec := *prevSpec
						if len(mergedSpec.Sort) == 0 && len(nextSpec.Sort) > 0 {
							mergedSpec.Sort = nextSpec.Sort
						}
						if mergedSpec.Size == nil && nextSpec.Size != nil {
							mergedSpec.Size = nextSpec.Size
						}
						if mergedSpec.From == 0 && nextSpec.From > 0 {
							mergedSpec.From = nextSpec.From
						}
						if mergedSpec.Source == nil && nextSpec.Source != nil {
							mergedSpec.Source = nextSpec.Source
						}
						if mergedSpec.StoredFields == nil && nextSpec.StoredFields != nil {
							mergedSpec.StoredFields = nextSpec.StoredFields
						}
						if len(mergedSpec.Fields) == 0 && len(nextSpec.Fields) > 0 {
							mergedSpec.Fields = nextSpec.Fields
						}
						if len(mergedSpec.DocvalueFields) == 0 && len(nextSpec.DocvalueFields) > 0 {
							mergedSpec.DocvalueFields = nextSpec.DocvalueFields
						}
						if len(mergedSpec.ScriptFields) == 0 && len(nextSpec.ScriptFields) > 0 {
							mergedSpec.ScriptFields = nextSpec.ScriptFields
						}
						if mergedSpec.Highlight == nil && nextSpec.Highlight != nil {
							mergedSpec.Highlight = nextSpec.Highlight
						}
						if mergedSpec.TrackScores == nil && nextSpec.TrackScores != nil {
							mergedSpec.TrackScores = nextSpec.TrackScores
						}
						ihSpecByName[ihName] = &mergedSpec
					} else {
						ihSpecByName[ihName] = nextSpec
					}
				}
				for _, nq := range nestedWithIH {
					ihName := nq.Path
					if nq.InnerHits.Name != "" {
						ihName = nq.InnerHits.Name
					}
					nqCopy := *nq
					if merged := ihSpecByName[ihName]; merged != nil {
						ihCopy := *merged
						if nq.InnerHits != nil && nq.InnerHits.Highlight != nil {
							ihCopy.Highlight = nq.InnerHits.Highlight
						}
						nqCopy.InnerHits = &ihCopy
					}
					ihPathByName[ihName] = nqCopy.Path
					skipPaging := ihNameCounts[ihName] > 1
					nextIH := buildNestedInnerHitsForHitWithOpts(h, hitIdx, hitSchema, &nqCopy, skipPaging)
					if prevIH, exists := ihMap[ihName].(map[string]any); exists {
						prevCnt := innerHitsTotalCount(prevIH)
						nextCnt := innerHitsTotalCount(nextIH)
						if prevCnt > 0 && nextCnt == 0 {
							continue
						}
						if prevCnt > 0 && nextCnt > 0 {
							ihMap[ihName] = mergeNestedInnerHitsEnvelopes(prevIH, nextIH, nqCopy.InnerHits)
							continue
						}
					}
					ihMap[ihName] = nextIH
				}
				for ihName, count := range ihNameCounts {
					if count > 1 {
						if curIH, ok := ihMap[ihName].(map[string]any); ok {
							ihMap[ihName] = finalizeMergedNestedInnerHits(curIH, ihSpecByName[ihName], hitSchema, ihPathByName[ihName])
						}
					}
				}
				hitMap["inner_hits"] = ihMap
			}
		}
		esHits = append(esHits, hitMap)
	}

	bucketsByAgg := make(map[string][]AggRow)
	var aggTotalHits int64
	for _, row := range aggRows {
		if row.AggName == "__meta_total" {
			if totalHits == 0 {
				totalHits = row.effectiveCount()
			}
			continue
		}
		if row.AggName == "__meta_query_total" {
			aggTotalHits = row.effectiveCount()
			continue
		}
		bucketsByAgg[row.AggName] = append(bucketsByAgg[row.AggName], row)
	}
	if aggTotalHits == 0 {
		aggTotalHits = totalHits
	}

	aggsOut := buildAggsMapWithSchema(indexName, "", req.EffectiveAggs(), bucketsByAgg, aggTotalHits, docLookup, idxSchema)

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

type nestedElemCandidate struct {
	offset int
	obj    map[string]any
}

func collectMatchingNestedQueriesWithInnerHits(idxSchema *schema.IndexSchema, getDoc func() map[string]any, q *esast.Query, out *[]*esast.NestedQuery) {
	if q == nil {
		return
	}
	if q.Nested != nil {
		if q.Nested.InnerHits != nil {
			*out = append(*out, q.Nested)
		}
		collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.Nested.Query, out)
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if !evalBranchMatchesDoc(idxSchema, getDoc(), &q.Bool.Must[i]) {
				return
			}
		}
		for i := range q.Bool.Filter {
			if !evalBranchMatchesDoc(idxSchema, getDoc(), &q.Bool.Filter[i]) {
				return
			}
		}
		for i := range q.Bool.MustNot {
			if evalBranchMatchesDoc(idxSchema, getDoc(), &q.Bool.MustNot[i]) {
				return
			}
		}
		var matchedShouldIdx []int
		if len(q.Bool.Should) > 0 {
			for i := range q.Bool.Should {
				if evalBranchMatchesDoc(idxSchema, getDoc(), &q.Bool.Should[i]) {
					matchedShouldIdx = append(matchedShouldIdx, i)
				}
			}
			reqMin := resolveMinimumShouldMatch(q.Bool.MinimumShouldMatch, len(q.Bool.Should), len(q.Bool.Must) == 0 && len(q.Bool.Filter) == 0)
			if len(matchedShouldIdx) < reqMin {
				return
			}
		}
		for i := range q.Bool.Must {
			collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.Bool.Must[i], out)
		}
		for i := range q.Bool.Filter {
			collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.Bool.Filter[i], out)
		}
		for _, i := range matchedShouldIdx {
			collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.Bool.Should[i], out)
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if evalBranchMatchesDoc(idxSchema, getDoc(), &q.DisMax.Queries[i]) {
				collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.DisMax.Queries[i], out)
			}
		}
	}
	if q.Boosting != nil {
		if evalBranchMatchesDoc(idxSchema, getDoc(), &q.Boosting.Positive) {
			collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.Boosting.Positive, out)
		}
	}
	if q.ConstantScore != nil {
		if evalBranchMatchesDoc(idxSchema, getDoc(), &q.ConstantScore.Filter) {
			collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, &q.ConstantScore.Filter, out)
		}
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil {
			collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, q.FunctionScore.Query, out)
		}
		for i := range q.FunctionScore.Functions {
			if q.FunctionScore.Functions[i].Filter == nil || evalBranchMatchesDoc(idxSchema, getDoc(), q.FunctionScore.Functions[i].Filter) {
				collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, q.FunctionScore.Functions[i].Filter, out)
			}
		}
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectMatchingNestedQueriesWithInnerHits(idxSchema, getDoc, q.ScriptScore.Query, out)
	}
}

func mergeNestedInnerHitsEnvelopes(prevIH, nextIH map[string]any, ihSpec *esast.InnerHitsSpec) map[string]any {
	prevHitsEnv, _ := prevIH["hits"].(map[string]any)
	nextHitsEnv, _ := nextIH["hits"].(map[string]any)
	if prevHitsEnv == nil {
		return nextIH
	}
	if nextHitsEnv == nil {
		return prevIH
	}
	prevList, _ := prevHitsEnv["hits"].([]map[string]any)
	nextList, _ := nextHitsEnv["hits"].([]map[string]any)
	seenOffset := make(map[int]int, len(prevList)+len(nextList))
	merged := make([]map[string]any, 0, len(prevList)+len(nextList))
	extractOffset := func(hm map[string]any) (int, bool) {
		if nm, ok := hm["_nested"].(map[string]any); ok {
			if off, okO := nm["offset"].(int); okO {
				return off, true
			}
			if f, okF := toFloat64(nm["offset"]); okF {
				return int(f), true
			}
		}
		return -1, false
	}
	for _, hm := range prevList {
		if off, ok := extractOffset(hm); ok {
			seenOffset[off] = len(merged)
		}
		merged = append(merged, hm)
	}
	for _, hm := range nextList {
		if off, ok := extractOffset(hm); ok {
			if idx, dup := seenOffset[off]; dup {
				hl1, _ := merged[idx]["highlight"].(map[string][]string)
				hl2, _ := hm["highlight"].(map[string][]string)
				var mergedHL map[string][]string
				if len(hl1) > 0 || len(hl2) > 0 {
					mergedHL = make(map[string][]string, len(hl1)+len(hl2))
					appendUniqueSnippets := func(f string, snips []string) {
						existing := mergedHL[f]
						for _, sn := range snips {
							found := false
							for _, ex := range existing {
								if ex == sn {
									found = true
									break
								}
							}
							if !found {
								existing = append(existing, sn)
							}
						}
						if len(existing) > 0 {
							mergedHL[f] = existing
						}
					}
					for f, snips := range hl1 {
						appendUniqueSnippets(f, snips)
					}
					for f, snips := range hl2 {
						appendUniqueSnippets(f, snips)
					}
				}
				s1, ok1 := toFloat64(merged[idx]["_score"])
				s2, ok2 := toFloat64(hm["_score"])
				if ok2 && (!ok1 || s2 > s1) {
					merged[idx] = hm
				}
				if len(mergedHL) > 0 {
					merged[idx]["highlight"] = mergedHL
				}
				continue
			}
			seenOffset[off] = len(merged)
		}
		merged = append(merged, hm)
	}
	totalVal := int64(len(merged))
	var maxScoreAny any
	var maxScore float64
	hasScore := false
	for _, hm := range merged {
		if sc, ok := toFloat64(hm["_score"]); ok {
			if !hasScore || sc > maxScore {
				maxScore = sc
				hasScore = true
			}
		}
	}
	if hasScore {
		maxScoreAny = maxScore
	}
	return map[string]any{
		"hits": map[string]any{
			"total":     map[string]any{"value": totalVal, "relation": "eq"},
			"max_score": maxScoreAny,
			"hits":      merged,
		},
	}
}

func finalizeMergedNestedInnerHits(ihEnv map[string]any, ihSpec *esast.InnerHitsSpec, idxSchema *schema.IndexSchema, nestedPath string) map[string]any {
	hitsEnv, _ := ihEnv["hits"].(map[string]any)
	if hitsEnv == nil {
		return ihEnv
	}
	hitList, _ := hitsEnv["hits"].([]map[string]any)
	extractOffset := func(hm map[string]any) int {
		if nm, ok := hm["_nested"].(map[string]any); ok {
			if off, okO := nm["offset"].(int); okO {
				return off
			}
			if f, okF := toFloat64(nm["offset"]); okF {
				return int(f)
			}
		}
		return 0
	}
	nestedSchema := deriveNestedEvalSchema(idxSchema, nestedPath)
	var elemSorts []esast.SortSpec
	if ihSpec != nil && len(ihSpec.Sort) > 0 {
		elemSorts = make([]esast.SortSpec, len(ihSpec.Sort))
		for i, s := range ihSpec.Sort {
			sc := s
			sc.Entry.Field = strings.TrimPrefix(sc.Entry.Field, nestedPath+".")
			elemSorts[i] = sc
		}
	}
	if len(hitList) > 1 {
		sort.SliceStable(hitList, func(i, j int) bool {
			if len(elemSorts) > 0 {
				ri, okI := hitList[i]["__raw_elem"].(HitRow)
				rj, okJ := hitList[j]["__raw_elem"].(HitRow)
				if okI && okJ {
					if cmp := compareHitRowsBySort(ri, rj, elemSorts, nestedSchema); cmp != 0 {
						return cmp < 0
					}
				}
			} else {
				s1, ok1 := toFloat64(hitList[i]["_score"])
				s2, ok2 := toFloat64(hitList[j]["_score"])
				if ok1 && ok2 && s1 != s2 {
					return s1 > s2
				}
			}
			return extractOffset(hitList[i]) < extractOffset(hitList[j])
		})
	}
	for _, hm := range hitList {
		delete(hm, "__raw_elem")
	}
	totalVal := int64(len(hitList))
	from := 0
	size := 3
	if ihSpec != nil {
		if ihSpec.From > 0 {
			from = ihSpec.From
		}
		size = ihSpec.EffectiveSize()
	}
	if from >= len(hitList) {
		hitList = []map[string]any{}
	} else {
		end := from + size
		if end > len(hitList) {
			end = len(hitList)
		}
		hitList = hitList[from:end]
	}
	hitsEnv["total"] = map[string]any{"value": totalVal, "relation": "eq"}
	hitsEnv["hits"] = hitList
	return ihEnv
}

func extractNestedElementsAtPath(node any, path []string) []nestedElemCandidate {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		switch tv := node.(type) {
		case []any:
			var out []nestedElemCandidate
			for idx, item := range tv {
				if m, ok := item.(map[string]any); ok {
					out = append(out, nestedElemCandidate{offset: idx, obj: m})
				}
			}
			return out
		case map[string]any:
			return []nestedElemCandidate{{offset: 0, obj: tv}}
		}
		return nil
	}
	switch tv := node.(type) {
	case map[string]any:
		return extractNestedElementsAtPath(tv[path[0]], path[1:])
	case []any:
		var out []nestedElemCandidate
		for _, item := range tv {
			out = append(out, extractNestedElementsAtPath(item, path)...)
		}
		return out
	}
	return nil
}

func buildSingleNestedElementDoc(pathSegs []string, elem map[string]any) map[string]any {
	root := make(map[string]any, len(elem)+1)
	for k, v := range elem {
		root[k] = v
	}
	curr := root
	for i := 0; i < len(pathSegs)-1; i++ {
		next := make(map[string]any)
		curr[pathSegs[i]] = next
		curr = next
	}
	if len(pathSegs) > 0 {
		curr[pathSegs[len(pathSegs)-1]] = []any{elem}
	}
	return root
}

func normalizeInnerHitsSourceFilter(sf *esast.SourceFilter, nestedPath string) *esast.SourceFilter {
	if sf == nil || nestedPath == "" {
		return sf
	}
	prefix := nestedPath + "."
	cp := *sf
	if len(sf.Includes) > 0 {
		cp.Includes = make([]string, 0, len(sf.Includes)*2)
		for _, inc := range sf.Includes {
			cp.Includes = append(cp.Includes, inc)
			if strings.HasPrefix(inc, prefix) {
				cp.Includes = append(cp.Includes, strings.TrimPrefix(inc, prefix))
			}
		}
	}
	if len(sf.Excludes) > 0 {
		cp.Excludes = make([]string, 0, len(sf.Excludes)*2)
		for _, exc := range sf.Excludes {
			cp.Excludes = append(cp.Excludes, exc)
			if strings.HasPrefix(exc, prefix) {
				cp.Excludes = append(cp.Excludes, strings.TrimPrefix(exc, prefix))
			}
		}
	}
	return &cp
}

func deriveNestedEvalSchema(base *schema.IndexSchema, nestedPath string) *schema.IndexSchema {
	if base == nil || nestedPath == "" {
		return base
	}
	cp := *base
	cp.Fields = make(map[string]schema.FieldBinding, len(base.Fields)*2)
	prefix := nestedPath + "."
	for k, b := range base.Fields {
		if b.NestedPath != nestedPath && !strings.HasPrefix(k, prefix) {
			b.NullValue = nil
		}
		cp.Fields[k] = b
	}
	for k, b := range base.Fields {
		if strings.HasPrefix(k, prefix) {
			relKey := strings.TrimPrefix(k, prefix)
			if _, exists := cp.Fields[relKey]; !exists {
				relB := b
				if len(b.RelativeJSONPath) > 0 {
					relB.SourceJSONPath = b.RelativeJSONPath
				}
				cp.Fields[relKey] = relB
			}
		}
	}
	return &cp
}

func deriveNestedScalarScoreSchema(base *schema.IndexSchema, nestedPath string) *schema.IndexSchema {
	if base == nil || nestedPath == "" {
		return base
	}
	cp := *base
	cp.Fields = make(map[string]schema.FieldBinding, len(base.Fields)*2)
	prefix := nestedPath + "."
	for k, b := range base.Fields {
		if b.NestedPath == nestedPath || strings.HasPrefix(k, prefix) {
			sb := b
			sb.Kind = schema.StorageDynamicVariant
			if len(b.RelativeJSONPath) > 0 {
				sb.SourceJSONPath = b.RelativeJSONPath
			}
			cp.Fields[k] = sb
			if strings.HasPrefix(k, prefix) {
				relKey := strings.TrimPrefix(k, prefix)
				if _, exists := cp.Fields[relKey]; !exists {
					cp.Fields[relKey] = sb
				}
			}
		} else {
			cp.Fields[k] = b
		}
	}
	return &cp
}

func innerHitsTotalCount(ihEnvelope map[string]any) int64 {
	if ihEnvelope == nil {
		return 0
	}
	hitsMap, _ := ihEnvelope["hits"].(map[string]any)
	if hitsMap == nil {
		return 0
	}
	totMap, _ := hitsMap["total"].(map[string]any)
	if totMap == nil {
		return 0
	}
	if v, ok := toFloat64(totMap["value"]); ok {
		return int64(v)
	}
	return 0
}

func collectCollapseCandidateValues(h HitRow, field string, idxSchema *schema.IndexSchema) []any {
	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	cleanField := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	pathSegs := strings.Split(cleanField, ".")
	if idxSchema != nil {
		b := idxSchema.ResolveField(field)
		if len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
		}
	}
	rawVals := collectSchemaAwareScalarValues(doc, field, pathSegs, idxSchema)
	out := make([]any, 0, len(rawVals))
	for _, v := range rawVals {
		if jsonNum, ok := v.(json.Number); ok {
			if iv, err := jsonNum.Int64(); err == nil {
				v = iv
			} else if fv, err := jsonNum.Float64(); err == nil {
				v = fv
			}
		}
		if idxSchema != nil {
			b := idxSchema.ResolveField(field)
			if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
				switch tv := v.(type) {
				case string:
					switch strings.ToLower(strings.TrimSpace(tv)) {
					case "true", "1":
						v = true
					case "false", "0":
						v = false
					}
				case int64:
					v = tv != 0
				case float64:
					v = tv != 0
				}
			} else if strVal, ok := v.(string); ok {
				if b.EffectiveLowercase(true) {
					v = strings.ToLower(strVal)
				} else if b.ESType == "date" || b.ESType == "date_nanos" || b.DorisType == schema.DorisBigInt {
					if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
						v = ms
					}
				}
			}
		}
		out = append(out, v)
	}
	return out
}

func sortSpecsUseScore(sorts []esast.SortSpec) bool {
	for _, s := range sorts {
		if s.Entry.Field == "_score" {
			return true
		}
	}
	return false
}

func normalizeCollapseGroupKey(val any, field string, primarySchema, hitSchema *schema.IndexSchema) string {
	if val == nil {
		return ""
	}
	isDate := false
	isLower := false
	isBool := false
	for _, sc := range []*schema.IndexSchema{hitSchema, primarySchema} {
		if sc == nil {
			continue
		}
		b := sc.ResolveField(field)
		if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
			isBool = true
		}
		if b.ESType == "date" || b.ESType == "date_nanos" || b.DorisType == schema.DorisBigInt {
			isDate = true
		}
		if b.EffectiveLowercase(true) {
			isLower = true
		}
	}
	if isBool {
		switch tv := val.(type) {
		case bool:
			if tv {
				return "true"
			}
			return "false"
		case string:
			switch strings.ToLower(strings.TrimSpace(tv)) {
			case "true", "1":
				return "true"
			case "false", "0":
				return "false"
			}
		default:
			if f, ok := toFloat64(val); ok {
				if f != 0 {
					return "true"
				}
				return "false"
			}
		}
	}
	if strVal, ok := val.(string); ok {
		if isDate {
			if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
				return strconv.FormatInt(ms, 10)
			}
		}
		if isLower {
			return strings.ToLower(strVal)
		}
		return strVal
	}
	return fmt.Sprintf("%v", val)
}

func buildNestedInnerHitsForHitWithOpts(h HitRow, hitIdx string, hitSchema *schema.IndexSchema, nq *esast.NestedQuery, skipPaging bool) map[string]any {
	emptyEnvelope := func() map[string]any {
		return map[string]any{
			"hits": map[string]any{
				"total":     map[string]any{"value": int64(0), "relation": "eq"},
				"max_score": nil,
				"hits":      []map[string]any{},
			},
		}
	}
	if nq == nil || nq.InnerHits == nil {
		return emptyEnvelope()
	}
	rawSrc := h.EffectiveSource()
	if len(rawSrc) == 0 {
		return emptyEnvelope()
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawSrc))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return emptyEnvelope()
	}
	pathSegs := strings.Split(nq.Path, ".")
	cands := extractNestedElementsAtPath(doc, pathSegs)
	if len(cands) == 0 {
		return emptyEnvelope()
	}

	evalSchema := hitSchema
	if evalSchema == nil || evalSchema.NestedRoots[nq.Path] == "" {
		var elemSamples []json.RawMessage
		for _, c := range cands {
			if b, err := json.Marshal(c.obj); err == nil {
				elemSamples = append(elemSamples, b)
			}
		}
		var elemProps map[string]esast.FieldProperty
		if inf := schema.InferMappingFromSampleDocs(elemSamples); inf != nil {
			elemProps = inf.Properties
		}
		nestedSpec := &esast.MappingSpec{
			Properties: buildNestedMappingProps(pathSegs, esast.FieldProperty{
				Type:       "nested",
				Properties: elemProps,
			}),
		}
		var baseRaw *esast.MappingSpec
		if hitSchema != nil {
			baseRaw = hitSchema.RawMapping
		}
		evalSchema = schema.CompileIndexSchema("es_compat", hitIdx, schema.MergeMappingSpecs(baseRaw, nestedSpec))
	}
	nestedEvalSchema := deriveNestedEvalSchema(evalSchema, nq.Path)
	elemScoreSchema := deriveNestedScalarScoreSchema(evalSchema, nq.Path)

	tr := transpiler.NewTranspiler(nestedEvalSchema, transpiler.TranspilerOptions{})
	cq := tr.CompileQuery(&esast.Query{Nested: nq}, true, nil)
	scoreTr := transpiler.NewTranspiler(elemScoreSchema, transpiler.TranspilerOptions{})
	innerScoreCQ := scoreTr.CompileQuery(&nq.Query, true, nil)

	type matchedNestedElem struct {
		offset int
		hit    HitRow
	}
	var matched []matchedNestedElem
	for _, c := range cands {
		singleDoc := buildSingleNestedElementDoc(pathSegs, c.obj)
		singleBytes, err := json.Marshal(singleDoc)
		if err != nil {
			continue
		}
		shreddedBytes, err := schema.ShredDocument(evalSchema, h.ID, 1, false, singleBytes)
		if err != nil {
			continue
		}
		var row map[string]any
		rDec := json.NewDecoder(bytes.NewReader(shreddedBytes))
		rDec.UseNumber()
		if err := rDec.Decode(&row); err != nil {
			continue
		}
		singleDoc["__meta_id"] = h.ID
		row["_doc"] = singleDoc
		if !evalWhereExpr(row, cq.WhereSQL) {
			continue
		}
		if queryHasRuntimeScript(&nq.Query) && !evalQueryScriptFilterOnDocWithSchema(nestedEvalSchema, singleDoc, &nq.Query) {
			continue
		}
		score := evalNumericExpr(row, innerScoreCQ.ScoreSQL)
		if score == 0 && (innerScoreCQ.ScoreSQL == "1.0" || cq.ScoreSQL == "1.0") {
			score = 1.0
		}
		if queryHasRuntimeScript(&nq.Query) {
			score = evalQueryScriptScoreOnDocWithSchema(nestedEvalSchema, singleDoc, &nq.Query, score)
		}
		elemBytes, _ := json.Marshal(c.obj)
		matched = append(matched, matchedNestedElem{
			offset: c.offset,
			hit: HitRow{
				Index:     hitIdx,
				ID:        h.ID,
				Source:    elemBytes,
				RawSource: singleBytes,
				Score:     score,
			},
		})
	}
	if len(matched) == 0 {
		return emptyEnvelope()
	}

	ih := nq.InnerHits
	if len(ih.Sort) > 0 && len(matched) > 1 {
		sort.SliceStable(matched, func(i, j int) bool {
			if cmp := compareHitRowsBySort(matched[i].hit, matched[j].hit, ih.Sort, nestedEvalSchema); cmp != 0 {
				return cmp < 0
			}
			return matched[i].offset < matched[j].offset
		})
	} else if len(matched) > 1 {
		sort.SliceStable(matched, func(i, j int) bool {
			if matched[i].hit.Score != matched[j].hit.Score {
				return matched[i].hit.Score > matched[j].hit.Score
			}
			return matched[i].offset < matched[j].offset
		})
	}

	var maxElemScore float64
	for _, m := range matched {
		if m.hit.Score > maxElemScore {
			maxElemScore = m.hit.Score
		}
	}
	totalMatched := int64(len(matched))
	if !skipPaging {
		from := ih.From
		if from < 0 {
			from = 0
		}
		size := ih.EffectiveSize()
		if from >= len(matched) {
			matched = nil
		} else {
			end := from + size
			if end > len(matched) {
				end = len(matched)
			}
			matched = matched[from:end]
		}
	}

	normSF := normalizeInnerHitsSourceFilter(ih.Source, nq.Path)
	ihFieldSpecs := ih.EffectiveFieldSpecs()
	var explicitFieldSpecs, bareWildcardFieldSpecs []esast.FieldRequestSpec
	for _, fs := range ihFieldSpecs {
		clean := strings.TrimSuffix(strings.TrimSuffix(fs.Field, ".keyword"), ".ngram")
		if strings.ContainsAny(clean, "*?") && !strings.HasPrefix(clean, nq.Path+".") {
			bareWildcardFieldSpecs = append(bareWildcardFieldSpecs, fs)
		} else {
			explicitFieldSpecs = append(explicitFieldSpecs, fs)
		}
	}
	trackScores := ih.TrackScores != nil && *ih.TrackScores
	outHits := make([]map[string]any, 0, len(matched))
	for _, m := range matched {
		var hitScore any = m.hit.Score
		if len(ih.Sort) > 0 && !sortSpecsUseScore(ih.Sort) && !trackScores {
			hitScore = nil
		}
		ihHitMap := map[string]any{
			"_index": hitIdx,
			"_id":    h.ID,
			"_nested": map[string]any{
				"field":  nq.Path,
				"offset": m.offset,
			},
			"_score": hitScore,
		}
		if skipPaging {
			ihHitMap["__raw_elem"] = m.hit
		}
		if (normSF == nil || !normSF.Disabled) && (!ih.HasStoredFieldsNone() || ih.Source != nil) {
			var srcObj any
			sDec := json.NewDecoder(bytes.NewReader(filterSourceJSON(m.hit.Source, normSF)))
			sDec.UseNumber()
			if err := sDec.Decode(&srcObj); err == nil {
				ihHitMap["_source"] = srcObj
			} else {
				ihHitMap["_source"] = filterSourceJSON(m.hit.Source, normSF)
			}
		}
		if len(ih.Sort) > 0 {
			ihHitMap["sort"] = extractHitSortValues(m.hit, ih.Sort, nestedEvalSchema)
		}
		if len(ihFieldSpecs) > 0 {
			fm := make(map[string][]any)
			if len(bareWildcardFieldSpecs) > 0 {
				elemOnlyHit := m.hit
				elemOnlyHit.RawSource = nil
				for fk, fv := range extractHitFieldsMap(elemOnlyHit, hitIdx, &esast.SearchRequest{Fields: bareWildcardFieldSpecs}, nestedEvalSchema) {
					fm[fk] = fv
				}
			}
			if len(explicitFieldSpecs) > 0 {
				for fk, fv := range extractHitFieldsMap(m.hit, hitIdx, &esast.SearchRequest{Fields: explicitFieldSpecs}, nestedEvalSchema) {
					fm[fk] = fv
				}
			}
			if len(fm) > 0 {
				ihHitMap["fields"] = fm
			}
		}
		if len(ih.ScriptFields) > 0 {
			if sfm := evalHitScriptFields(m.hit, ih.ScriptFields, nestedEvalSchema); len(sfm) > 0 {
				fm, _ := ihHitMap["fields"].(map[string][]any)
				if fm == nil {
					fm = make(map[string][]any, len(sfm))
				}
				for k, v := range sfm {
					fm[k] = v
				}
				ihHitMap["fields"] = fm
			}
		}
		if ih.Highlight != nil && len(ih.Highlight.Fields) > 0 {
			hlSrc := m.hit.RawSource
			for hf := range ih.Highlight.Fields {
				if strings.Contains(hf, "*") && !strings.HasPrefix(hf, nq.Path+".") {
					hlSrc = m.hit.Source
					break
				}
			}
			if hl := buildHighlightMapWithSchema(hlSrc, &esast.SearchRequest{Query: &nq.Query, Highlight: ih.Highlight}, nestedEvalSchema); len(hl) > 0 {
				ihHitMap["highlight"] = hl
			}
		}
		outHits = append(outHits, ihHitMap)
	}

	var maxScoreAny any = maxElemScore
	if len(ih.Sort) > 0 && !sortSpecsUseScore(ih.Sort) && !trackScores {
		maxScoreAny = nil
	}
	return map[string]any{
		"hits": map[string]any{
			"total":     map[string]any{"value": totalMatched, "relation": "eq"},
			"max_score": maxScoreAny,
			"hits":      outHits,
		},
	}
}

func (s *Server) populateCollapseInnerHits(
	ctx context.Context,
	targets []string,
	aliasFilters map[string]*esast.Query,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
	req *esast.SearchRequest,
	collapsedHits []HitRow,
	resp map[string]any,
) {
	hitsEnvelope, ok := resp["hits"].(map[string]any)
	if !ok {
		return
	}
	esHits, ok := hitsEnvelope["hits"].([]map[string]any)
	if !ok || len(esHits) == 0 {
		return
	}

	var uncollapsed []HitRow
	zero := 0
	fetchLimit := 10000
	for _, indexName := range targets {
		rawIdxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
		idxSchema := schemasByIndex[indexName]
		if idxSchema == nil {
			idxSchema = s.augmentSchemaWithRuntimeMappings(s.ensureIndexSchema(ctx, indexName), req.RuntimeMappings)
		} else {
			idxSchema = s.augmentSchemaWithRuntimeMappings(idxSchema, req.RuntimeMappings)
		}
		hasRuntimeMappings := len(effectiveRuntimeMappings(rawIdxSchema, req.RuntimeMappings)) > 0
		subReq := *req
		subReq.Collapse = nil
		subReq.Aggs = nil
		subReq.Aggregations = nil
		subReq.SearchAfter = nil
		subReq.TerminateAfter = nil
		subReq.From = &zero
		subReq.Size = &fetchLimit
		subReqPtr := applyIndexAliasFilter(&subReq, aliasFilters[indexName])
		needsScript := hasRuntimeMappings ||
			queryHasRuntimeScript(subReqPtr.Query) ||
			queryHasNestedScoring(subReqPtr.Query) ||
			queryHasRuntimeScript(subReqPtr.PostFilter) ||
			(subReqPtr.AliasFilter != nil && (queryHasRuntimeScript((*esast.Query)(subReqPtr.AliasFilter)) || queryHasMinScore((*esast.Query)(subReqPtr.AliasFilter)))) ||
			queryHasMinScore(subReqPtr.Query) ||
			req.MinScore != nil ||
			sortsHaveScript(subReqPtr.Sort)
		if needsScript {
			subReqPtr.PostFilter = nil
			subReqPtr.MinScore = nil
			if hasRuntimeMappings {
				subReqPtr.Query = nil
				subReqPtr.Sort = nil
				subReqPtr.AliasFilter = nil
			}
		}
		sqlSchema := idxSchema
		if hasRuntimeMappings && rawIdxSchema != nil {
			sqlSchema = rawIdxSchema
		}
		tr := transpiler.NewTranspiler(sqlSchema, s.transpileOpts)
		plan, err := tr.BuildSearchPlan(subReqPtr)
		if err != nil || plan.HitsSQL == "" {
			continue
		}
		rows, err := s.backend.QueryHits(ctx, plan.HitsSQL)
		if err != nil {
			continue
		}
		for i := range rows {
			rows[i].Index = indexName
			rows[i].Routing = s.getDocRouting(indexName, rows[i].ID)
		}
		if hasRuntimeMappings && len(rows) > 0 {
			s.evalRuntimeMappingsOnHitRows(idxSchema, req.RuntimeMappings, rows)
		}
		if needsScript {
			evalReq := *applyIndexAliasFilter(req, aliasFilters[indexName])
			evalReq.Collapse = nil
			evalReq.Aggs = nil
			evalReq.Aggregations = nil
			evalReq.SearchAfter = nil
			evalReq.TerminateAfter = nil
			evalReq.From = &zero
			evalReq.Size = &fetchLimit
			rows, _, _ = applyRuntimeSearchScripts(rows, nil, int64(len(rows)), &evalReq, idxSchema, true)
		}
		uncollapsed = append(uncollapsed, rows...)
	}
	if len(targets) > 1 && len(uncollapsed) > 1 {
		effSorts := transpiler.EffectiveSortsForRequest(req)
		sort.SliceStable(uncollapsed, func(i, j int) bool {
			if len(effSorts) > 0 {
				sI := schemasByIndex[uncollapsed[i].Index]
				if sI == nil {
					sI = primarySchema
				}
				sJ := schemasByIndex[uncollapsed[j].Index]
				if sJ == nil {
					sJ = primarySchema
				}
				if cmp := compareHitRowsBySortWithSchemas(uncollapsed[i], uncollapsed[j], effSorts, sI, sJ); cmp != 0 {
					return cmp < 0
				}
			}
			if uncollapsed[i].Score != uncollapsed[j].Score {
				return uncollapsed[i].Score > uncollapsed[j].Score
			}
			return uncollapsed[i].ID < uncollapsed[j].ID
		})
	}
	if len(req.Rescore) > 0 && len(uncollapsed) > 0 {
		defaultWin := 10
		if req.Size != nil {
			from := 0
			if req.From != nil && *req.From > 0 {
				from = *req.From
			}
			defaultWin = from + *req.Size
		}
		uncollapsed = s.applyRescoreToHits(req, uncollapsed, schemasByIndex, primarySchema, defaultWin)
	}

	collapseSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: req.Collapse.Field}}}
	byGroup := make(map[string][]HitRow)
	for _, cand := range uncollapsed {
		cSchema := schemasByIndex[cand.Index]
		if cSchema == nil {
			cSchema = primarySchema
		}
		allVals := collectCollapseCandidateValues(cand, req.Collapse.Field, cSchema)
		seenGroup := make(map[string]struct{}, len(allVals))
		for _, v := range allVals {
			if v == nil {
				continue
			}
			gk := normalizeCollapseGroupKey(v, req.Collapse.Field, primarySchema, cSchema)
			if _, dup := seenGroup[gk]; dup {
				continue
			}
			seenGroup[gk] = struct{}{}
			byGroup[gk] = append(byGroup[gk], cand)
		}
	}

	for hitPos, h := range collapsedHits {
		if hitPos >= len(esHits) {
			break
		}
		hSchema := schemasByIndex[h.Index]
		if hSchema == nil {
			hSchema = primarySchema
		}
		cVals := extractHitSortValues(h, collapseSort, hSchema)
		var groupCands []HitRow
		if len(cVals) > 0 && cVals[0] != nil {
			gk := normalizeCollapseGroupKey(cVals[0], req.Collapse.Field, primarySchema, hSchema)
			groupCands = byGroup[gk]
		}
		ihMap, _ := esHits[hitPos]["inner_hits"].(map[string]any)
		if ihMap == nil {
			ihMap = make(map[string]any, len(req.Collapse.InnerHits))
		}
		for _, ihSpec := range req.Collapse.InnerHits {
			ihName := ihSpec.Name
			if ihName == "" {
				ihName = req.Collapse.Field
			}
			sortedGroup := append([]HitRow(nil), groupCands...)
			activeSort := ihSpec.Sort
			if len(activeSort) == 0 {
				activeSort = req.Sort
			}
			if len(sortedGroup) > 1 {
				sort.SliceStable(sortedGroup, func(i, j int) bool {
					if len(activeSort) > 0 {
						sI := schemasByIndex[sortedGroup[i].Index]
						if sI == nil {
							sI = primarySchema
						}
						sJ := schemasByIndex[sortedGroup[j].Index]
						if sJ == nil {
							sJ = primarySchema
						}
						if cmp := compareHitRowsBySortWithSchemas(sortedGroup[i], sortedGroup[j], activeSort, sI, sJ); cmp != 0 {
							return cmp < 0
						}
					}
					if sortedGroup[i].Score != sortedGroup[j].Score {
						return sortedGroup[i].Score > sortedGroup[j].Score
					}
					return sortedGroup[i].ID < sortedGroup[j].ID
				})
			}
			totalGroup := int64(len(sortedGroup))
			var maxGroupScore float64
			for _, g := range sortedGroup {
				if g.Score > maxGroupScore {
					maxGroupScore = g.Score
				}
			}
			subCollapseField := ""
			if ihSpec.Collapse != nil {
				subCollapseField = strings.TrimSpace(ihSpec.Collapse.Field)
			}
			subCollapseKeyByDoc := make(map[string]any)
			if subCollapseField != "" && len(sortedGroup) > 0 {
				deduped := make([]HitRow, 0, len(sortedGroup))
				seenSubKey := make(map[string]struct{}, len(sortedGroup))
				for _, cand := range sortedGroup {
					cSchema := schemasByIndex[cand.Index]
					if cSchema == nil {
						cSchema = primarySchema
					}
					vals := collectCollapseCandidateValues(cand, subCollapseField, cSchema)
					for _, v := range vals {
						if v == nil {
							continue
						}
						sk := normalizeCollapseGroupKey(v, subCollapseField, primarySchema, cSchema)
						if sk == "" {
							continue
						}
						if _, exists := seenSubKey[sk]; !exists {
							seenSubKey[sk] = struct{}{}
							subCollapseKeyByDoc[cand.Index+"\x00"+cand.ID] = v
							deduped = append(deduped, cand)
							break
						}
					}
				}
				sortedGroup = deduped
			}
			ihFrom := ihSpec.From
			if ihFrom < 0 {
				ihFrom = 0
			}
			ihSize := ihSpec.EffectiveSize()
			if ihFrom >= len(sortedGroup) {
				sortedGroup = nil
			} else {
				end := ihFrom + ihSize
				if end > len(sortedGroup) {
					end = len(sortedGroup)
				}
				sortedGroup = sortedGroup[ihFrom:end]
			}
			ihFieldSpecs := ihSpec.EffectiveFieldSpecs()
			ihSyntheticReq := &esast.SearchRequest{Fields: ihFieldSpecs}
			formattedHits := make([]map[string]any, 0, len(sortedGroup))
			ihTrackScores := (ihSpec.TrackScores != nil && *ihSpec.TrackScores) || (req.TrackScores != nil && *req.TrackScores)
			nullifyScore := len(activeSort) > 0 && !sortSpecsUseScore(activeSort) && !ihTrackScores
			for _, gh := range sortedGroup {
				gIdx := gh.Index
				if gIdx == "" {
					gIdx = h.Index
				}
				gSchema := schemasByIndex[gIdx]
				if gSchema == nil {
					gSchema = primarySchema
				}
				var ghScore any = gh.Score
				if nullifyScore {
					ghScore = nil
				}
				ghMap := map[string]any{
					"_index": gIdx,
					"_type":  "_doc",
					"_id":    gh.ID,
					"_score": ghScore,
				}
				if gh.Routing != "" {
					ghMap["_routing"] = gh.Routing
				}
				if (ihSpec.Source == nil || !ihSpec.Source.Disabled) && (!ihSpec.HasStoredFieldsNone() || ihSpec.Source != nil) {
					ghSrc := gh.Source
					if len(ghSrc) == 0 {
						ghSrc = gh.EffectiveSource()
					}
					ghMap["_source"] = filterSourceJSON(ghSrc, ihSpec.Source)
				}
				if len(activeSort) > 0 {
					ghMap["sort"] = extractHitSortValues(gh, activeSort, gSchema)
				}
				if len(ihFieldSpecs) > 0 {
					if fm := extractHitFieldsMap(gh, gIdx, ihSyntheticReq, gSchema); len(fm) > 0 {
						ghMap["fields"] = fm
					}
				}
				if subCollapseField != "" {
					subVal, hasSubVal := subCollapseKeyByDoc[gh.Index+"\x00"+gh.ID]
					if !hasSubVal {
						subSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: subCollapseField}}}
						if sVals := extractHitSortValues(gh, subSort, gSchema); len(sVals) > 0 && sVals[0] != nil {
							subVal = sVals[0]
							hasSubVal = true
						}
					}
					if hasSubVal && subVal != nil {
						fm, _ := ghMap["fields"].(map[string][]any)
						if fm == nil {
							fm = make(map[string][]any)
						}
						if _, exists := fm[subCollapseField]; !exists {
							fm[subCollapseField] = []any{subVal}
						}
						ghMap["fields"] = fm
					}
				}
				if len(ihSpec.ScriptFields) > 0 {
					if sfm := evalHitScriptFields(gh, ihSpec.ScriptFields, gSchema); len(sfm) > 0 {
						fm, _ := ghMap["fields"].(map[string][]any)
						if fm == nil {
							fm = make(map[string][]any, len(sfm))
						}
						for k, v := range sfm {
							fm[k] = v
						}
						ghMap["fields"] = fm
					}
				}
				if ihSpec.Highlight != nil && len(ihSpec.Highlight.Fields) > 0 {
					if hl := buildHighlightMapWithSchema(gh.EffectiveSource(), &esast.SearchRequest{Query: req.Query, Highlight: ihSpec.Highlight}, gSchema); len(hl) > 0 {
						ghMap["highlight"] = hl
					}
				}
				formattedHits = append(formattedHits, ghMap)
			}
			var maxGroupScoreAny any = maxGroupScore
			if nullifyScore || totalGroup == 0 {
				maxGroupScoreAny = nil
			}
			ihMap[ihName] = map[string]any{
				"hits": map[string]any{
					"total":     map[string]any{"value": totalGroup, "relation": "eq"},
					"max_score": maxGroupScoreAny,
					"hits":      formattedHits,
				},
			}
		}
		esHits[hitPos]["inner_hits"] = ihMap
	}
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

func preScaleRateAggRows(aggs map[string]esast.AggSpec, prefix string, histSpec *esast.AggSpec, bucketsByAgg map[string][]AggRow) {
	if len(aggs) == 0 || len(bucketsByAgg) == 0 {
		return
	}
	for aggName, spec := range aggs {
		fullKey := aggName
		if prefix != "" {
			fullKey = prefix + "." + aggName
		}
		curHist := histSpec
		if spec.DateHistogram != nil || spec.Histogram != nil {
			specCopy := spec
			curHist = &specCopy
		} else if spec.Composite != nil {
			for _, srcMap := range spec.Composite.Sources {
				for _, srcSpec := range srcMap {
					if srcSpec.DateHistogram != nil || srcSpec.Histogram != nil {
						srcCopy := srcSpec
						curHist = &srcCopy
						break
					}
				}
				if curHist != histSpec {
					break
				}
			}
		}
		if spec.Rate != nil && curHist != nil {
			scale := rateScaleFactor(spec.Rate, curHist)
			if scale != 1.0 && scale > 0 {
				if rows, ok := bucketsByAgg[fullKey]; ok {
					for i := range rows {
						rows[i].Value = rows[i].effectiveValue() * scale
					}
					bucketsByAgg[fullKey] = rows
				}
			}
			continue
		}
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			preScaleRateAggRows(subAggs, fullKey, curHist, bucketsByAgg)
		}
	}
}

func buildAggsMapWithSchema(
	indexName string,
	prefix string,
	aggs map[string]esast.AggSpec,
	bucketsByAgg map[string][]AggRow,
	totalHits int64,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
) map[string]any {
	if prefix == "" {
		preScaleRateAggRows(aggs, "", nil, bucketsByAgg)
	}
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
			subAggs := spec.SubAggs()
			var sumOtherDocCount int64
			rows, sumOtherDocCount = filterAndSortTermsRowsWithSubAggs(rows, termsSpec, fullKey, "", bucketsByAgg, subAggs, indexName, docLookup, idxSchema)
			b := make([]map[string]any, 0, len(rows))
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
				keyVal, keyAsStr, hasKeyAsStr := formatTermsBucketKeyAndString(r.BucketKey, termsSpec, idxSchema)
				bucketMap := map[string]any{
					"key":       keyVal,
					"doc_count": docCnt,
				}
				if hasKeyAsStr {
					bucketMap["key_as_string"] = keyAsStr
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
					attachSubAggsToBucketWithSchema(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup, idxSchema)
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
					"sum_other_doc_count":         sumOtherDocCount,
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
						ss.PercentileRanks != nil, ss.Boxplot != nil, ss.ReverseNested != nil,
						ss.ScriptedMetric != nil:
						directSubAggs[sn] = ss
					default:
						groupedSubAggs[sn] = ss
					}
				}
				if len(directSubAggs) > 0 {
					for sk, sv := range buildAggsMapWithSchema(indexName, fullKey, directSubAggs, bucketsByAgg, nestedCnt, docLookup, idxSchema) {
						nestedObj[sk] = sv
					}
				}
				if len(groupedSubAggs) > 0 {
					attachSubAggsToBucketWithSchema(indexName, nestedObj, fullKey, "_nested_doc_count", groupedSubAggs, bucketsByAgg, docLookup, idxSchema)
				}
				evaluateSiblingPipelineAggs(subAggs, nestedObj)
				_ = evaluateChildPipelineAggs([]map[string]any{nestedObj}, subAggs)
			}
			aggsOut[aggName] = nestedObj
		case spec.Global != nil || spec.ReverseNested != nil || spec.EffectiveSampler() != nil:
			cnt := totalHits
			if len(rows) > 0 {
				cnt = rows[0].effectiveCount()
			}
			containerObj := map[string]any{"doc_count": cnt}
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				var directSub, groupedNestedSub, groupedRNSub map[string]esast.AggSpec
				for k, v := range subAggs {
					subFull := fullKey + "." + k
					hasNestedPrefix := false
					hasRNPrefix := false
					for _, sr := range bucketsByAgg[subFull] {
						if sr.BucketKey == "_nested_doc_count" || strings.HasPrefix(sr.BucketKey, "_nested_doc_count\x1f") {
							hasNestedPrefix = true
							break
						}
						if sr.BucketKey == "_reverse_nested" || strings.HasPrefix(sr.BucketKey, "_reverse_nested\x1f") {
							hasRNPrefix = true
							break
						}
					}
					if hasNestedPrefix {
						if groupedNestedSub == nil {
							groupedNestedSub = make(map[string]esast.AggSpec)
						}
						groupedNestedSub[k] = v
					} else if hasRNPrefix {
						if groupedRNSub == nil {
							groupedRNSub = make(map[string]esast.AggSpec)
						}
						groupedRNSub[k] = v
					} else {
						if directSub == nil {
							directSub = make(map[string]esast.AggSpec)
						}
						directSub[k] = v
					}
				}
				if len(directSub) > 0 {
					for sk, sv := range buildAggsMapWithSchema(indexName, fullKey, directSub, bucketsByAgg, cnt, docLookup, idxSchema) {
						containerObj[sk] = sv
					}
				}
				if len(groupedNestedSub) > 0 {
					attachSubAggsToBucketWithSchema(indexName, containerObj, fullKey, "_nested_doc_count", groupedNestedSub, bucketsByAgg, docLookup, idxSchema)
				}
				if len(groupedRNSub) > 0 {
					attachSubAggsToBucketWithSchema(indexName, containerObj, fullKey, "_reverse_nested", groupedRNSub, bucketsByAgg, docLookup, idxSchema)
				}
				evaluateSiblingPipelineAggs(subAggs, containerObj)
				_ = evaluateChildPipelineAggs([]map[string]any{containerObj}, subAggs)
			}
			aggsOut[aggName] = containerObj
		case spec.Filter != nil || spec.Missing != nil:
			var cnt int64
			if len(rows) > 0 {
				cnt = rows[0].effectiveCount()
			}
			filterObj := map[string]any{"doc_count": cnt}
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				for sk, sv := range buildAggsMapWithSchema(indexName, fullKey, subAggs, bucketsByAgg, cnt, docLookup, idxSchema) {
					filterObj[sk] = sv
				}
				evaluateSiblingPipelineAggs(subAggs, filterObj)
				_ = evaluateChildPipelineAggs([]map[string]any{filterObj}, subAggs)
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
						attachSubAggsToBucketWithSchema(indexName, bMap, fullKey, fk, subAggs, bucketsByAgg, docLookup, idxSchema)
						evaluateSiblingPipelineAggs(subAggs, bMap)
					}
					ordered = append(ordered, bMap)
				}
				if spec.Filters.OtherBucket {
					otherKey := spec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{"doc_count": byKey[otherKey]}
					if len(subAggs) > 0 {
						attachSubAggsToBucketWithSchema(indexName, bMap, fullKey, otherKey, subAggs, bucketsByAgg, docLookup, idxSchema)
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
						attachSubAggsToBucketWithSchema(indexName, bMap, fullKey, fk, subAggs, bucketsByAgg, docLookup, idxSchema)
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
						attachSubAggsToBucketWithSchema(indexName, bMap, fullKey, otherKey, subAggs, bucketsByAgg, docLookup, idxSchema)
						evaluateSiblingPipelineAggs(subAggs, bMap)
					}
					bucketsMap[otherKey] = bMap
				}
				if len(subAggs) > 0 {
					keys := sortedFilterBucketKeys(spec.Filters, bucketsMap)
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
					keys := sortedFilterBucketKeys(spec.Filters, bucketsMap)
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
			if (len(rows) == 0 || rows[0].Weight < 0) && (spec.Avg != nil || spec.Min != nil || spec.Max != nil) {
				aggsOut[aggName] = map[string]any{"value": nil}
				continue
			}
			var val float64
			if len(rows) > 0 && rows[0].Weight >= 0 {
				val = rows[0].effectiveValue()
			}
			aggsOut[aggName] = map[string]any{"value": val}
		case spec.ScriptedMetric != nil:
			var smVal any
			if len(rows) > 0 {
				if _, rv, _, ok := parseScriptedMetricBucketKey(rows[0].BucketKey); ok {
					smVal = rv
				}
			} else {
				smVal, _ = evalScriptedMetricCombineAndReduce(spec.ScriptedMetric, nil)
			}
			aggsOut[aggName] = map[string]any{"value": smVal}
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
			if cntVal == 0 {
				aggsOut[aggName] = map[string]any{
					"count":      int64(0),
					"min_length": nil,
					"max_length": nil,
					"avg_length": nil,
					"entropy":    0.0,
				}
			} else {
				aggsOut[aggName] = map[string]any{
					"count":      cntVal,
					"min_length": int64(minLen),
					"max_length": int64(maxLen),
					"avg_length": avgLen,
					"entropy":    entropyVal,
				}
			}
		case spec.Boxplot != nil:
			hasValidBox := false
			var minVal, maxVal, q1, q2, q3 float64
			for _, r := range rows {
				if r.Weight >= 0 {
					hasValidBox = true
				}
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
			if !hasValidBox {
				aggsOut[aggName] = map[string]any{
					"min":   nil,
					"max":   nil,
					"q1":    nil,
					"q2":    nil,
					"q3":    nil,
					"lower": nil,
					"upper": nil,
				}
			} else {
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
			}
		case spec.Percentiles != nil:
			if len(rows) == 0 {
				for _, pct := range spec.Percentiles.EffectivePercents() {
					pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
					if !strings.Contains(pctKey, ".") {
						pctKey += ".0"
					}
					rows = append(rows, AggRow{BucketKey: pctKey, Weight: -1})
				}
			}
			if spec.Percentiles.Keyed != nil && !*spec.Percentiles.Keyed {
				valuesArr := make([]map[string]any, 0, len(rows))
				for _, r := range rows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					var valAny any
					if r.Weight >= 0 {
						valAny = r.effectiveValue()
					}
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": valAny,
					})
				}
				aggsOut[aggName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]any, len(rows))
				for _, r := range rows {
					if r.Weight >= 0 {
						valuesMap[r.BucketKey] = r.effectiveValue()
					} else {
						valuesMap[r.BucketKey] = nil
					}
				}
				aggsOut[aggName] = map[string]any{"values": valuesMap}
			}
		case spec.PercentileRanks != nil:
			if len(rows) == 0 {
				for _, v := range spec.PercentileRanks.Values {
					valKey := strconv.FormatFloat(v, 'f', -1, 64)
					if !strings.Contains(valKey, ".") {
						valKey += ".0"
					}
					rows = append(rows, AggRow{BucketKey: valKey, Weight: -1})
				}
			}
			if spec.PercentileRanks.Keyed != nil && !*spec.PercentileRanks.Keyed {
				valuesArr := make([]map[string]any, 0, len(rows))
				for _, r := range rows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					var valAny any
					if r.Weight >= 0 {
						valAny = r.effectiveValue()
					}
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": valAny,
					})
				}
				aggsOut[aggName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]any, len(rows))
				for _, r := range rows {
					if r.Weight >= 0 {
						valuesMap[r.BucketKey] = r.effectiveValue()
					} else {
						valuesMap[r.BucketKey] = nil
					}
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
				keyStr := formatDateHistogramKeyAsString(epochMs, spec.DateHistogram)
				bucketMap := map[string]any{
					"key_as_string": keyStr,
					"key":           epochMs,
					"doc_count":     r.effectiveCount(),
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucketWithSchema(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup, idxSchema)
					evaluateSiblingPipelineAggs(subAggs, bucketMap)
				}
				b = append(b, bucketMap)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggsWithoutBucketSort(b, subAggs)
			}
			if spec.DateHistogram.Order != nil && len(b) > 1 {
				b = sortHistogramBuckets(b, spec.DateHistogram.Order)
			}
			if len(subAggs) > 0 {
				b = evaluateBucketSortPipelineAggs(b, subAggs)
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
					attachSubAggsToBucketWithSchema(indexName, bucketMap, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup, idxSchema)
					evaluateSiblingPipelineAggs(subAggs, bucketMap)
				}
				b = append(b, bucketMap)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggsWithoutBucketSort(b, subAggs)
			}
			if spec.Histogram.Order != nil && len(b) > 1 {
				b = sortHistogramBuckets(b, spec.Histogram.Order)
			}
			if len(subAggs) > 0 {
				b = evaluateBucketSortPipelineAggs(b, subAggs)
			}
			aggsOut[aggName] = formatKeyedBuckets(b, spec.Histogram.Keyed, "key")
		case spec.EffectiveRange() != nil:
			rngSpec := spec.EffectiveRange()
			isDateRange := spec.DateRange != nil
			if !isDateRange && spec.Range != nil {
				fieldClean := strings.TrimSpace(rngSpec.Field)
				fieldIsDate := fieldClean == "@timestamp"
				if !fieldIsDate && idxSchema != nil && fieldClean != "" {
					if b, ok := idxSchema.Fields[fieldClean]; ok && (b.ESType == "date" || b.ESType == "date_nanos") {
						fieldIsDate = true
					} else if strings.HasSuffix(fieldClean, ".keyword") {
						if b, ok := idxSchema.Fields[strings.TrimSuffix(fieldClean, ".keyword")]; ok && (b.ESType == "date" || b.ESType == "date_nanos") {
							fieldIsDate = true
						}
					}
				}
				if fieldIsDate {
					if rngSpec.Format != "" {
						isDateRange = true
					} else {
						for _, r := range rngSpec.Ranges {
							if _, ok := r.From.(string); ok {
								isDateRange = true
								break
							}
							if _, ok := r.To.(string); ok {
								isDateRange = true
								break
							}
						}
					}
				}
			}
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
						if ms, ok := parseRuntimeDateRangeBoundMillis(rng.From, rngSpec, nowUTC); ok {
							entry["from"] = float64(ms)
							entry["from_as_string"] = formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{
								Format:   rngSpec.Format,
								TimeZone: rngSpec.TimeZone,
							})
						}
					} else if !isIPRange {
						if f, ok := toFloat(rng.From); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
							entry["from"] = f
						}
					}
				}
				if rng.To != nil {
					entry["to"] = rng.To
					if isDateRange {
						if ms, ok := parseRuntimeDateRangeBoundMillis(rng.To, rngSpec, nowUTC); ok {
							entry["to"] = float64(ms)
							entry["to_as_string"] = formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{
								Format:   rngSpec.Format,
								TimeZone: rngSpec.TimeZone,
							})
						}
					} else if !isIPRange {
						if f, ok := toFloat(rng.To); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
							entry["to"] = f
						}
					}
				}
				if isDateRange && rng.Key == "" {
					fromStr, _ := entry["from_as_string"].(string)
					if fromStr == "" {
						fromStr = "*"
					}
					toStr, _ := entry["to_as_string"].(string)
					if toStr == "" {
						toStr = "*"
					}
					entry["key"] = fromStr + "-" + toStr
				}
				if len(subAggs) > 0 {
					attachSubAggsToBucketWithSchema(indexName, entry, fullKey, ek, subAggs, bucketsByAgg, docLookup, idxSchema)
					evaluateSiblingPipelineAggs(subAggs, entry)
				}
				b = append(b, entry)
			}
			if len(subAggs) > 0 {
				b = evaluateChildPipelineAggs(b, subAggs)
			}
			aggsOut[aggName] = formatKeyedBuckets(b, rngSpec.Keyed, "key")
		case spec.TopHits != nil:
			aggsOut[aggName] = buildTopHitsEnvelope(indexName, rows, spec.TopHits, totalHits, docLookup)
		case spec.TopMetrics != nil:
			aggsOut[aggName] = buildTopMetricsObject(rows, spec.TopMetrics, docLookup)
		case spec.Composite != nil:
			aggsOut[aggName] = buildCompositeAggObjectWithSchema(indexName, fullKey, "", spec.Composite, spec.SubAggs(), rows, bucketsByAgg, docLookup, idxSchema)
		case spec.RareTerms != nil || spec.MultiTerms != nil || spec.AutoDateHistogram != nil || spec.VariableWidthHistogram != nil ||
			spec.GeoDistance != nil || spec.GeohashGrid != nil || spec.GeotileGrid != nil || spec.AdjacencyMatrix != nil:
			aggsOut[aggName] = formatRuntimeBucketAggObjectWithSchema(indexName, fullKey, "", spec, rows, bucketsByAgg, docLookup, idxSchema)
		case spec.WeightedAvg != nil || spec.MedianAbsoluteDeviation != nil || spec.GeoBounds != nil ||
			spec.GeoCentroid != nil || spec.MatrixStats != nil || spec.TTest != nil:
			aggsOut[aggName] = formatRuntimeJSONMetricAggObject("", spec, rows)
		}
	}
	evaluateSiblingPipelineAggs(aggs, aggsOut)
	_ = evaluateChildPipelineAggs([]map[string]any{aggsOut}, aggs)
	return aggsOut
}

func buildCompositeAggObjectWithSchema(
	indexName string,
	fullKey string,
	parentBucketKey string,
	comp *esast.CompositeAggSpec,
	subAggs map[string]esast.AggSpec,
	rows []AggRow,
	bucketsByAgg map[string][]AggRow,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
) map[string]any {
	type compSrcMeta struct {
		name  string
		entry esast.AggSpec
	}
	var srcMetas []compSrcMeta
	for _, srcMap := range comp.Sources {
		var ks []string
		for k := range srcMap {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			entry := srcMap[k]
			if entry.Terms != nil && strings.TrimSpace(entry.Terms.ValueType) == "" && idxSchema != nil {
				fName := strings.TrimSpace(entry.Terms.Field)
				b := idxSchema.ResolveField(fName)
				if b.Kind != schema.StorageDynamicVariant || b.ESType != "" {
					tCopy := *entry.Terms
					switch b.ESType {
					case "long", "integer", "short", "byte", "unsigned_long":
						tCopy.ValueType = "long"
					case "date", "date_nanos":
						tCopy.ValueType = "date"
					case "double", "float", "half_float", "scaled_float":
						tCopy.ValueType = "double"
					case "boolean":
						tCopy.ValueType = "boolean"
					case "ip":
						tCopy.ValueType = "ip"
					default:
						switch b.DorisType {
						case schema.DorisBigInt, schema.DorisInt:
							tCopy.ValueType = "long"
						case schema.DorisDouble:
							tCopy.ValueType = "double"
						case schema.DorisBoolean:
							tCopy.ValueType = "boolean"
						}
					}
					if tCopy.ValueType != "" {
						entry.Terms = &tCopy
					}
				}
			}
			srcMetas = append(srcMetas, compSrcMeta{name: k, entry: entry})
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
						if strings.TrimSpace(sm.entry.DateHistogram.Format) != "" {
							partVal = formatDateHistogramKeyAsString(iv, sm.entry.DateHistogram)
						} else {
							partVal = iv
						}
					}
				} else if sm.entry.Histogram != nil {
					if iv, err := strconv.ParseInt(parts[i], 10, 64); err == nil {
						partVal = iv
					} else if fv, ok := parseFiniteFloat(parts[i]); ok {
						partVal = fv
					}
				} else if sm.entry.Terms != nil && strings.TrimSpace(sm.entry.Terms.ValueType) != "" {
					switch strings.ToLower(strings.TrimSpace(sm.entry.Terms.ValueType)) {
					case "long", "integer", "short", "byte", "date":
						if iv, err := strconv.ParseInt(parts[i], 10, 64); err == nil {
							partVal = iv
						} else if fv, ok := parseFiniteFloat(parts[i]); ok {
							partVal = int64(fv)
						} else if strings.EqualFold(strings.TrimSpace(sm.entry.Terms.ValueType), "date") {
							if ms, ok := schema.ParseESDateToEpochMillis(strings.TrimSpace(parts[i]), time.Now().UTC()); ok {
								partVal = ms
							}
						}
					case "double", "float", "half_float", "scaled_float", "number":
						if fv, ok := parseFiniteFloat(parts[i]); ok {
							partVal = fv
						}
					case "boolean":
						switch strings.ToLower(strings.TrimSpace(parts[i])) {
						case "true", "1":
							partVal = true
						case "false", "0":
							partVal = false
						}
					}
				}
				keyObj[sm.name] = partVal
			}
		}
		if len(comp.After) > 0 {
			cmpAfter := 0
			for _, sm := range srcMetas {
				afterVal, ok := comp.After[sm.name]
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
	compLimit := comp.Size
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
	for _, d := range decoded {
		afterKey = d.keyObj
		bucketMap := map[string]any{
			"key":       d.keyObj,
			"doc_count": d.row.effectiveCount(),
		}
		if len(subAggs) > 0 {
			childParentKey := d.row.BucketKey
			if parentBucketKey != "" {
				childParentKey = parentBucketKey + "\x1f" + d.row.BucketKey
			}
			attachSubAggsToBucketWithSchema(indexName, bucketMap, fullKey, childParentKey, subAggs, bucketsByAgg, docLookup, idxSchema)
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
	return compObj
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
	if a == nil && b == nil {
		return 0
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
	if entry.DateHistogram != nil {
		rngSpec := &esast.RangeAggSpec{
			Format:   entry.DateHistogram.Format,
			TimeZone: entry.DateHistogram.TimeZone,
		}
		nowUTC := time.Now().UTC()
		if msA, okA := parseRuntimeDateRangeBoundMillis(a, rngSpec, nowUTC); okA {
			if msB, okB := parseRuntimeDateRangeBoundMillis(b, rngSpec, nowUTC); okB {
				a = msA
				b = msB
			}
		}
	} else if entry.Terms != nil && strings.EqualFold(strings.TrimSpace(entry.Terms.ValueType), "date") {
		nowUTC := time.Now().UTC()
		if sa, okA := a.(string); okA {
			if msA, ok := schema.ParseESDateToEpochMillis(strings.TrimSpace(sa), nowUTC); ok {
				a = msA
			}
		}
		if sb, okB := b.(string); okB {
			if msB, ok := schema.ParseESDateToEpochMillis(strings.TrimSpace(sb), nowUTC); ok {
				b = msB
			}
		}
	}
	if bv, isBool := b.(bool); isBool {
		if bv {
			b = "true"
		} else {
			b = "false"
		}
		if strA, okA := a.(string); okA {
			switch strings.ToLower(strings.TrimSpace(strA)) {
			case "true", "1":
				a = "true"
			case "false", "0":
				a = "false"
			}
		}
	} else if av, isBool := a.(bool); isBool {
		if av {
			a = "true"
		} else {
			a = "false"
		}
		if strB, okB := b.(string); okB {
			switch strings.ToLower(strings.TrimSpace(strB)) {
			case "true", "1":
				b = "true"
			case "false", "0":
				b = "false"
			}
		}
	}
	if strA, okA := a.(string); okA {
		if strB, okB := b.(string); okB {
			if (strA == "true" || strA == "false") && (strB == "1" || strB == "0") {
				if strB == "1" {
					strB = "true"
				} else {
					strB = "false"
				}
				b = strB
			} else if (strB == "true" || strB == "false") && (strA == "1" || strA == "0") {
				if strA == "1" {
					strA = "true"
				} else {
					strA = "false"
				}
				a = strA
			}
			if ipA, okIA := parseIPv4SortUint32(strA); okIA {
				if ipB, okIB := parseIPv4SortUint32(strB); okIB {
					var cmp int
					if ipA < ipB {
						cmp = -1
					} else if ipA > ipB {
						cmp = 1
					}
					if desc {
						return -cmp
					}
					return cmp
				}
			}
			if entry.Terms != nil && strings.TrimSpace(entry.Terms.ValueType) != "" {
				vt := strings.ToLower(strings.TrimSpace(entry.Terms.ValueType))
				if vt == "long" || vt == "integer" || vt == "short" || vt == "byte" || vt == "double" || vt == "float" || vt == "half_float" || vt == "scaled_float" || vt == "number" || vt == "date" {
					if fa, okFA := parseFiniteFloat(strA); okFA {
						if fb, okFB := parseFiniteFloat(strB); okFB {
							var cmp int
							if fa < fb {
								cmp = -1
							} else if fa > fb {
								cmp = 1
							}
							if desc {
								return -cmp
							}
							return cmp
						}
					}
				}
			}
		}
	}
	if _, aIsStr := a.(string); aIsStr != func() bool { _, ok := b.(string); return ok }() {
		if fa, okFA := toFloat64(a); okFA {
			if fb, okFB := toFloat64(b); okFB {
				var cmp int
				if fa < fb {
					cmp = -1
				} else if fa > fb {
					cmp = 1
				}
				if desc {
					return -cmp
				}
				return cmp
			}
		}
		if strA, okA := a.(string); okA {
			if fa, okFA := parseFiniteFloat(strA); okFA {
				if fb, okFB := toFloat64(b); okFB {
					var cmp int
					if fa < fb {
						cmp = -1
					} else if fa > fb {
						cmp = 1
					}
					if desc {
						return -cmp
					}
					return cmp
				}
			}
		} else if strB, okB := b.(string); okB {
			if fb, okFB := parseFiniteFloat(strB); okFB {
				if fa, okFA := toFloat64(a); okFA {
					var cmp int
					if fa < fb {
						cmp = -1
					} else if fa > fb {
						cmp = 1
					}
					if desc {
						return -cmp
					}
					return cmp
				}
			}
		}
	}
	cmp := compareAny(a, b)
	if desc {
		return -cmp
	}
	return cmp
}

func sortedFilterBucketKeys(fSpec *esast.FiltersAggSpec, bucketsMap map[string]any) []string {
	var otherKey string
	hasOther := false
	if fSpec != nil && fSpec.OtherBucket {
		otherKey = fSpec.EffectiveOtherBucketKey()
		_, hasOther = bucketsMap[otherKey]
	}
	keys := make([]string, 0, len(bucketsMap))
	for fk := range bucketsMap {
		if hasOther && fk == otherKey {
			continue
		}
		keys = append(keys, fk)
	}
	sort.Strings(keys)
	if hasOther {
		keys = append(keys, otherKey)
	}
	return keys
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
	seenDocID := make(map[string]bool, len(rows))
	for _, r := range rows {
		var h *HitRow
		if docLookup != nil {
			h = docLookup(r.BucketKey)
		}
		docID := r.BucketKey
		var hitIdx string
		if sep := strings.LastIndex(docID, "\x1f"); sep >= 0 {
			docID = docID[sep+1:]
		}
		if nul := strings.IndexByte(docID, '\x00'); nul >= 0 {
			hitIdx = docID[:nul]
			docID = docID[nul+1:]
		}
		if h != nil && h.Index != "" {
			hitIdx = h.Index
		}
		dedupKey := hitIdx + "\x00" + docID
		if seenDocID[dedupKey] {
			continue
		}
		seenDocID[dedupKey] = true
		candidates = append(candidates, candidate{docID: docID, hit: h})
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
			if cmp := compareHitRowsBySortWithSchemas(ha, hb, spec.Sort, ha.Schema, hb.Schema); cmp != 0 {
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
		if c.hit != nil && len(c.hit.EffectiveSource()) > 0 {
			var doc map[string]any
			dec := json.NewDecoder(bytes.NewReader(c.hit.EffectiveSource()))
			dec.UseNumber()
			if err := dec.Decode(&doc); err == nil {
				for _, mf := range metricFields {
					cleanF := strings.TrimSuffix(strings.TrimSuffix(mf, ".keyword"), ".ngram")
					pathSegs := strings.Split(cleanF, ".")
					if c.hit.Schema != nil {
						b := c.hit.Schema.ResolveField(mf)
						if len(b.SourceJSONPath) > 0 {
							pathSegs = b.SourceJSONPath
						}
					}
					vals := collectSchemaAwareScalarValues(doc, mf, pathSegs, c.hit.Schema)
					var v any
					if len(vals) > 0 {
						v = vals[0]
					}
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
				sortVals = extractHitSortValues(*c.hit, spec.Sort, c.hit.Schema)
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

func filterAndSortTermsRowsWithSubAggs(
	rows []AggRow,
	spec *esast.TermsAggSpec,
	fullKey string,
	parentBucketKey string,
	bucketsByAgg map[string][]AggRow,
	subAggs map[string]esast.AggSpec,
	indexName string,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
) ([]AggRow, int64) {
	if spec == nil {
		return rows, 0
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
			if r.BucketKey != "__ES_MISSING_BUCKET__" {
				if spec.Include != nil && !matchesTermsFilterPrecompiled(r.BucketKey, spec.Include, incRe) {
					continue
				}
				if spec.Exclude != nil && matchesTermsFilterPrecompiled(r.BucketKey, spec.Exclude, excRe) {
					continue
				}
			}
			filtered = append(filtered, r)
		}
		cpRows = filtered
	}
	if len(cpRows) > 1 {
		sort.SliceStable(cpRows, func(i, j int) bool {
			ci, cj := cpRows[i].effectiveCount(), cpRows[j].effectiveCount()
			if ci != cj {
				return ci > cj
			}
			return cpRows[i].BucketKey < cpRows[j].BucketKey
		})
	}
	type termsOrderCriterion struct {
		field       string
		desc        bool
		metricByKey map[string]float64
	}
	var criteria []termsOrderCriterion
	var lazyTmpBuckets []map[string]any
	addCriterion := func(field string, v any) {
		dirStr := extractCompositeSourceOrder(v)
		desc := !strings.EqualFold(dirStr, "asc")
		var metricByKey map[string]float64
		if field != "_count" && field != "_key" && field != "_term" {
			normField := strings.ReplaceAll(strings.TrimSpace(field), ">", ".")
			var keyedBucketKey string
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
				rem := normField[closeIdx+1:]
				if strings.HasPrefix(rem, ".") && keyedBucketKey == "" {
					keyedBucketKey = inner
					normField = normField[:openIdx] + rem
				} else {
					normField = normField[:openIdx] + "." + inner + rem
				}
			}
			subName := normField
			prop := "value"
			var rowKey string
			if _, ok := bucketsByAgg[fullKey+"."+normField]; ok {
				rowKey = fullKey + "." + normField
			} else if _, ok := bucketsByAgg[fullKey+"."+normField+".0"]; ok {
				rowKey = fullKey + "." + normField + ".0"
			} else {
				if strings.HasSuffix(normField, ".std_deviation_bounds.upper") || strings.HasSuffix(normField, ".std_deviation_bounds.upper_population") {
					subName = strings.TrimSuffix(strings.TrimSuffix(normField, ".std_deviation_bounds.upper_population"), ".std_deviation_bounds.upper")
					prop = "std_deviation_bounds.upper"
				} else if strings.HasSuffix(normField, ".std_deviation_bounds.lower") || strings.HasSuffix(normField, ".std_deviation_bounds.lower_population") {
					subName = strings.TrimSuffix(strings.TrimSuffix(normField, ".std_deviation_bounds.lower_population"), ".std_deviation_bounds.lower")
					prop = "std_deviation_bounds.lower"
				} else if strings.HasSuffix(normField, ".std_deviation_bounds.upper_sampling") {
					subName = strings.TrimSuffix(normField, ".std_deviation_bounds.upper_sampling")
					prop = "std_deviation_bounds.upper_sampling"
				} else if strings.HasSuffix(normField, ".std_deviation_bounds.lower_sampling") {
					subName = strings.TrimSuffix(normField, ".std_deviation_bounds.lower_sampling")
					prop = "std_deviation_bounds.lower_sampling"
				} else if dot := strings.LastIndexByte(normField, '.'); dot > 0 {
					if prevDot := strings.LastIndexByte(normField[:dot], '.'); prevDot > 0 && isSignedASCIIDigits(normField[prevDot+1:dot]) && isAllDigitsASCII(normField[dot+1:]) {
						subName = normField[:prevDot]
						prop = normField[prevDot+1:]
					} else {
						subName = normField[:dot]
						prop = normField[dot+1:]
					}
				}
				if keyedBucketKey == "" && strings.IndexByte(subName, '.') >= 0 {
					_, existsProp := bucketsByAgg[fullKey+"."+subName+"."+prop]
					_, existsDirect := bucketsByAgg[fullKey+"."+subName]
					if !existsProp && !existsDirect {
						if firstDot := strings.IndexByte(subName, '.'); firstDot > 0 {
							candAgg := subName[:firstDot]
							candKey := subName[firstDot+1:]
							if _, existsKeyed := bucketsByAgg[fullKey+"."+candAgg+"."+prop]; existsKeyed {
								subName = candAgg
								keyedBucketKey = candKey
							} else if (prop == "_count" || prop == "doc_count") && !strings.Contains(candKey, ".") {
								if _, existsCand := bucketsByAgg[fullKey+"."+candAgg]; existsCand {
									subName = candAgg
									keyedBucketKey = candKey
								}
							}
						}
					}
				}
				rowKey = fullKey + "." + subName
				isStringStatsSub := false
				if subSpec, ok := subAggs[subName]; ok && subSpec.StringStats != nil {
					isStringStatsSub = true
				}
				switch prop {
				case "", "value", "_count", "doc_count":
				case "count":
					if len(bucketsByAgg[fullKey+"."+subName+"._sstats_count"]) > 0 || (isStringStatsSub && len(bucketsByAgg[fullKey+"."+subName+"._stats_count"]) == 0) {
						rowKey = fullKey + "." + subName + "._sstats_count"
					} else {
						rowKey = fullKey + "." + subName + "._stats_count"
					}
				case "min", "min_length":
					if _, ok := bucketsByAgg[fullKey+"."+subName+".0.0"]; ok && len(bucketsByAgg[fullKey+"."+subName+"._stats_min"]) == 0 {
						rowKey = fullKey + "." + subName + ".0.0"
					} else if len(bucketsByAgg[fullKey+"."+subName+"._sstats_min"]) > 0 || (isStringStatsSub && len(bucketsByAgg[fullKey+"."+subName+"._stats_min"]) == 0) {
						rowKey = fullKey + "." + subName + "._sstats_min"
					} else {
						rowKey = fullKey + "." + subName + "._stats_min"
					}
				case "max", "max_length":
					if _, ok := bucketsByAgg[fullKey+"."+subName+".100.0"]; ok && len(bucketsByAgg[fullKey+"."+subName+"._stats_max"]) == 0 {
						rowKey = fullKey + "." + subName + ".100.0"
					} else if len(bucketsByAgg[fullKey+"."+subName+"._sstats_max"]) > 0 || (isStringStatsSub && len(bucketsByAgg[fullKey+"."+subName+"._stats_max"]) == 0) {
						rowKey = fullKey + "." + subName + "._sstats_max"
					} else {
						rowKey = fullKey + "." + subName + "._stats_max"
					}
				case "avg", "avg_length":
					if len(bucketsByAgg[fullKey+"."+subName+"._sstats_avg"]) > 0 || (isStringStatsSub && len(bucketsByAgg[fullKey+"."+subName+"._stats_avg"]) == 0) {
						rowKey = fullKey + "." + subName + "._sstats_avg"
					} else {
						rowKey = fullKey + "." + subName + "._stats_avg"
					}
				case "entropy":
					if len(bucketsByAgg[fullKey+"."+subName+"._sstats_entropy"]) > 0 || (isStringStatsSub && len(bucketsByAgg[fullKey+"."+subName+"._stats_entropy"]) == 0) {
						rowKey = fullKey + "." + subName + "._sstats_entropy"
					} else {
						rowKey = fullKey + "." + subName + "._stats_entropy"
					}
				case "sum":
					rowKey = fullKey + "." + subName + "._stats_sum"
				case "sum_of_squares":
					rowKey = fullKey + "." + subName + "._stats_sum_sq"
				case "std_deviation", "std_deviation_population", "variance", "variance_population", "variance_sampling", "std_deviation_sampling", "std_deviation_bounds.upper", "std_deviation_bounds.lower", "std_deviation_bounds.upper_sampling", "std_deviation_bounds.lower_sampling":
					rowKey = fullKey + "." + subName + "._stats_std"
				case "q1":
					rowKey = fullKey + "." + subName + ".25.0"
				case "q2", "median":
					rowKey = fullKey + "." + subName + ".50.0"
				case "q3":
					rowKey = fullKey + "." + subName + ".75.0"
				case "lower":
					rowKey = fullKey + "." + subName + ".0.0"
				case "upper":
					rowKey = fullKey + "." + subName + ".100.0"
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
			trimRowKey := func(raw string) (string, bool) {
				k := raw
				if parentBucketKey != "" {
					trimmed, ok := trimSubAggBucketPrefix(k, parentBucketKey)
					if !ok {
						return "", false
					}
					k = trimmed
				}
				if keyedBucketKey != "" {
					sepIdx := strings.LastIndex(k, "\x1f")
					if sepIdx < 0 || !bucketKeysEquivalent(k[sepIdx+1:], keyedBucketKey) {
						return "", false
					}
					k = k[:sepIdx]
				}
				return k, true
			}
			readSubSeries := func(rk string, asCount bool) map[string]float64 {
				rows := bucketsByAgg[rk]
				m := make(map[string]float64, len(rows))
				for _, sr := range rows {
					rawBK := sr.BucketKey
					if nulIdx := strings.IndexByte(rawBK, '\x00'); nulIdx >= 0 {
						rawBK = rawBK[:nulIdx]
					}
					k, ok := trimRowKey(rawBK)
					if !ok {
						continue
					}
					if asCount {
						m[k] = float64(sr.effectiveCount())
					} else if sr.Weight < 0 {
						continue
					} else if prop != "" && prop != "value" && prop != "_count" && prop != "doc_count" {
						if _, rv, _, okSM := parseScriptedMetricBucketKey(sr.BucketKey); okSM {
							if rvMap, okM := rv.(map[string]any); okM {
								if fv, okF := extractBucketMetricBySegs(rvMap, strings.Split(prop, ".")); okF {
									m[k] = fv
									continue
								}
							}
						}
						m[k] = sr.effectiveValue()
					} else {
						m[k] = sr.effectiveValue()
					}
				}
				return m
			}
			basePath := fullKey + "." + subName
			switch prop {
			case "variance", "variance_population":
				stds := readSubSeries(basePath+"._stats_std", false)
				metricByKey = make(map[string]float64, len(stds))
				for k, std := range stds {
					metricByKey[k] = std * std
				}
			case "variance_sampling", "std_deviation_sampling":
				stds := readSubSeries(basePath+"._stats_std", false)
				cnts := readSubSeries(basePath+"._stats_count", true)
				metricByKey = make(map[string]float64, len(stds))
				for k, std := range stds {
					if cnt := cnts[k]; cnt > 1 {
						vs := (std * std * cnt) / (cnt - 1.0)
						if prop == "std_deviation_sampling" {
							metricByKey[k] = math.Sqrt(vs)
						} else {
							metricByKey[k] = vs
						}
					}
				}
			case "std_deviation_bounds.upper", "std_deviation_bounds.lower", "std_deviation_bounds.upper_sampling", "std_deviation_bounds.lower_sampling":
				sigma := 2.0
				if subSpec, ok := subAggs[subName]; ok {
					if st := subSpec.EffectiveStats(); st != nil {
						sigma = st.EffectiveSigma()
					}
				}
				stds := readSubSeries(basePath+"._stats_std", false)
				avgs := readSubSeries(basePath+"._stats_avg", false)
				isSampling := strings.HasSuffix(prop, "_sampling")
				var cnts map[string]float64
				if isSampling {
					cnts = readSubSeries(basePath+"._stats_count", true)
				}
				isUpper := strings.Contains(prop, ".upper")
				metricByKey = make(map[string]float64, len(avgs))
				for k, avg := range avgs {
					std := stds[k]
					if isSampling {
						if cnt := cnts[k]; cnt > 1 {
							std = math.Sqrt((std * std * cnt) / (cnt - 1.0))
						} else {
							std = 0
						}
					}
					if isUpper {
						metricByKey[k] = avg + sigma*std
					} else {
						metricByKey[k] = avg - sigma*std
					}
				}
			case "sum_of_squares":
				metricByKey = readSubSeries(rowKey, false)
				if len(metricByKey) == 0 {
					stds := readSubSeries(basePath+"._stats_std", false)
					avgs := readSubSeries(basePath+"._stats_avg", false)
					cnts := readSubSeries(basePath+"._stats_count", true)
					metricByKey = make(map[string]float64, len(cnts))
					for k, cnt := range cnts {
						avg := avgs[k]
						std := stds[k]
						metricByKey[k] = cnt * (std*std + avg*avg)
					}
				}
			case "lower", "upper":
				mins := readSubSeries(basePath+".0.0", false)
				maxs := readSubSeries(basePath+".100.0", false)
				q1s := readSubSeries(basePath+".25.0", false)
				q3s := readSubSeries(basePath+".75.0", false)
				metricByKey = make(map[string]float64, len(q1s))
				for k, q1 := range q1s {
					q3 := q3s[k]
					iqr := q3 - q1
					if prop == "lower" {
						metricByKey[k] = math.Max(mins[k], q1-1.5*iqr)
					} else {
						metricByKey[k] = math.Min(maxs[k], q3+1.5*iqr)
					}
				}
			default:
				metricByKey = readSubSeries(rowKey, prop == "_count" || prop == "doc_count" || prop == "count")
			}
			if len(metricByKey) == 0 && len(subAggs) > 0 {
				if lazyTmpBuckets == nil {
					lazyTmpBuckets = make([]map[string]any, 0, len(cpRows))
					for _, r := range cpRows {
						tmpB := map[string]any{
							"key":       r.BucketKey,
							"doc_count": r.effectiveCount(),
						}
						childParentKey := r.BucketKey
						if parentBucketKey != "" {
							childParentKey = parentBucketKey + "\x1f" + r.BucketKey
						}
						attachSubAggsToBucketWithSchema(indexName, tmpB, fullKey, childParentKey, subAggs, bucketsByAgg, docLookup, idxSchema)
						evaluateSiblingPipelineAggs(subAggs, tmpB)
						lazyTmpBuckets = append(lazyTmpBuckets, tmpB)
					}
					lazyTmpBuckets = evaluateChildPipelineAggsWithoutBucketSort(lazyTmpBuckets, subAggs)
				}
				metricByKey = make(map[string]float64, len(cpRows))
				for i, r := range cpRows {
					if i < len(lazyTmpBuckets) {
						if fv, okF := extractBucketMetricByPath(lazyTmpBuckets[i], field); okF && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
							metricByKey[r.BucketKey] = fv
						}
					}
				}
			}
		}
		criteria = append(criteria, termsOrderCriterion{field: field, desc: desc, metricByKey: metricByKey})
	}
	if spec.Order != nil {
		switch ov := spec.Order.(type) {
		case map[string]any:
			for _, k := range sortedOrderMapKeys(ov) {
				addCriterion(k, ov[k])
			}
		case []any:
			for _, elem := range ov {
				if m, ok := elem.(map[string]any); ok {
					for _, k := range sortedOrderMapKeys(m) {
						addCriterion(k, m[k])
					}
				}
			}
		}
	}
	if len(criteria) == 0 {
		criteria = []termsOrderCriterion{{field: "_count", desc: true}}
	}
	vt := strings.ToLower(strings.TrimSpace(spec.ValueType))
	isNumericValueType := vt == "long" || vt == "integer" || vt == "short" || vt == "byte" ||
		vt == "double" || vt == "float" || vt == "half_float" || vt == "scaled_float" ||
		vt == "number" || vt == "date"
	if !isNumericValueType && vt == "" && idxSchema != nil && spec.Field != "" {
		b := idxSchema.ResolveField(spec.Field)
		switch b.ESType {
		case "long", "integer", "short", "byte", "unsigned_long",
			"double", "float", "half_float", "scaled_float",
			"date", "date_nanos":
			isNumericValueType = true
		}
		if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt || b.DorisType == schema.DorisDouble {
			isNumericValueType = true
		}
	}
	missOrd := strings.ToLower(strings.TrimSpace(spec.MissingOrder))
	if len(cpRows) > 1 {
		sort.SliceStable(cpRows, func(i, j int) bool {
			for _, c := range criteria {
				switch c.field {
				case "_key", "_term":
					if cpRows[i].BucketKey != cpRows[j].BucketKey {
						if cpRows[i].BucketKey == "__ES_MISSING_BUCKET__" || cpRows[j].BucketKey == "__ES_MISSING_BUCKET__" {
							missingFirst := !c.desc
							switch missOrd {
							case "first":
								missingFirst = true
							case "last":
								missingFirst = false
							}
							if cpRows[i].BucketKey == "__ES_MISSING_BUCKET__" {
								return missingFirst
							}
							return !missingFirst
						}
						if isNumericValueType {
							if fi, okI := parseFiniteFloat(cpRows[i].BucketKey); okI {
								if fj, okJ := parseFiniteFloat(cpRows[j].BucketKey); okJ && fi != fj {
									if c.desc {
										return fi > fj
									}
									return fi < fj
								}
							}
						}
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
					vi, okI := c.metricByKey[cpRows[i].BucketKey]
					vj, okJ := c.metricByKey[cpRows[j].BucketKey]
					if okI != okJ {
						return okI
					}
					if okI && vi != vj {
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
	var sumOtherDocCount int64
	if len(cpRows) > limit {
		for _, dropped := range cpRows[limit:] {
			sumOtherDocCount += dropped.effectiveCount()
		}
		cpRows = cpRows[:limit]
	}
	return cpRows, sumOtherDocCount
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
	case map[string]any:
		numPart, okNP := toInt64(fv["num_partitions"])
		part, okP := toInt64(fv["partition"])
		if okNP && okP && numPart > 0 && part >= 0 && part < numPart {
			var h uint32 = 2166136261
			for i := 0; i < len(key); i++ {
				h ^= uint32(key[i])
				h *= 16777619
			}
			return int64(h)%numPart == part
		}
		return false
	}
	return false
}

func isBucketAggSpec(spec esast.AggSpec) bool {
	return spec.EffectiveTerms() != nil || spec.RareTerms != nil || spec.MultiTerms != nil || spec.Histogram != nil ||
		spec.DateHistogram != nil || spec.AutoDateHistogram != nil || spec.VariableWidthHistogram != nil ||
		spec.Filters != nil || spec.AdjacencyMatrix != nil || spec.Range != nil || spec.DateRange != nil ||
		spec.IPRange != nil || spec.GeoDistance != nil || spec.GeohashGrid != nil || spec.GeotileGrid != nil ||
		spec.Composite != nil || spec.Filter != nil || spec.Missing != nil || spec.Nested != nil ||
		spec.ReverseNested != nil || spec.Global != nil || spec.EffectiveSampler() != nil
}

func isMultiBucketAggSpec(spec esast.AggSpec) bool {
	return spec.EffectiveTerms() != nil || spec.RareTerms != nil || spec.MultiTerms != nil || spec.Histogram != nil ||
		spec.DateHistogram != nil || spec.AutoDateHistogram != nil || spec.VariableWidthHistogram != nil ||
		spec.Filters != nil || spec.AdjacencyMatrix != nil || spec.Range != nil || spec.DateRange != nil ||
		spec.IPRange != nil || spec.GeoDistance != nil || spec.GeohashGrid != nil || spec.GeotileGrid != nil ||
		spec.Composite != nil
}

func isKeyedBucketAggSpec(spec esast.AggSpec) bool {
	if spec.Filters != nil {
		return spec.Filters.EffectiveKeyed()
	}
	if spec.Range != nil {
		return spec.Range.Keyed
	}
	if spec.DateRange != nil {
		return spec.DateRange.Keyed
	}
	if spec.IPRange != nil {
		return spec.IPRange.Keyed
	}
	if spec.GeoDistance != nil {
		return spec.GeoDistance.Keyed
	}
	if spec.AdjacencyMatrix != nil {
		return spec.AdjacencyMatrix.Keyed
	}
	if spec.Histogram != nil {
		return spec.Histogram.Keyed
	}
	if spec.DateHistogram != nil {
		return spec.DateHistogram.Keyed
	}
	return false
}

func isSiblingPipelineAggSpec(spec esast.AggSpec) bool {
	return spec.AvgBucket != nil || spec.SumBucket != nil || spec.MinBucket != nil ||
		spec.MaxBucket != nil || spec.StatsBucket != nil || spec.ExtendedStatsBucket != nil ||
		spec.PercentilesBucket != nil
}

func isAllASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isSignedASCIIDigits(s string) bool {
	return isAllASCIIDigits(strings.TrimPrefix(s, "-"))
}

// normalizeBucketsPath tokenizes an Elasticsearch pipeline aggregation `buckets_path`
// into canonical path segments, handling `>` and `.` separators, bracketed keys (`['95.0']`,
// `[avg]`), and unbracketed decimal percentile keys (`95.0`).
func normalizeBucketsPath(raw string) []string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	type rawToken struct {
		val       string
		bracketed bool
	}
	var tokens []rawToken
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tok := strings.TrimSpace(cur.String())
			if tok != "" {
				tokens = append(tokens, rawToken{val: tok})
			}
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '>' || ch == '.' {
			flush()
			continue
		}
		if ch == '[' {
			flush()
			closeIdx := strings.IndexByte(s[i+1:], ']')
			if closeIdx >= 0 {
				inner := strings.TrimSpace(s[i+1 : i+1+closeIdx])
				inner = strings.Trim(inner, "'\"")
				if inner != "" {
					tokens = append(tokens, rawToken{val: inner, bracketed: true})
				}
				i += closeIdx + 1
				continue
			}
		}
		cur.WriteByte(ch)
	}
	flush()

	out := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		if !tokens[i].bracketed && i+1 < len(tokens) && !tokens[i+1].bracketed &&
			isSignedASCIIDigits(tokens[i].val) && isAllASCIIDigits(tokens[i+1].val) {
			out = append(out, tokens[i].val+"."+tokens[i+1].val)
			i++
			continue
		}
		out = append(out, tokens[i].val)
	}
	return out
}

func firstBucketsPathSeg(raw string) string {
	segs := normalizeBucketsPath(raw)
	if len(segs) > 0 {
		return segs[0]
	}
	return ""
}

func isRuntimeBucketContainer(m map[string]any) bool {
	if m == nil {
		return false
	}
	if _, hasBuckets := m["buckets"]; hasBuckets {
		return true
	}
	if _, hasDocCount := m["doc_count"]; hasDocCount {
		return true
	}
	return false
}

func validateChildBucketMetricDep(parentAggName, childAggName, pathStr string, subAggs map[string]esast.AggSpec) string {
	segs := normalizeBucketsPath(pathStr)
	if len(segs) == 0 {
		return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s] under [%s]", childAggName, parentAggName)
	}
	if len(segs) == 1 && (segs[0] == "_count" || segs[0] == "doc_count" || segs[0] == "_key" || segs[0] == "key") {
		return ""
	}
	currMap := subAggs
	var lastSpec esast.AggSpec
	for i := 0; i < len(segs); i++ {
		seg := segs[i]
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
		if isMultiBucketAggSpec(targetSpec) {
			if i+1 >= len(segs) {
				return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must specify a bucket key for multi-bucket aggregation [%s]", pathStr, childAggName, seg)
			}
			nextSeg := segs[i+1]
			_, nextIsSub := targetSpec.SubAggs()[nextSeg]
			if !isKeyedBucketAggSpec(targetSpec) && !strings.Contains(pathStr, "[") && (nextIsSub || nextSeg == "_count" || nextSeg == "doc_count") {
				return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] cannot reference multi-bucket aggregation [%s] without a bucket key", pathStr, childAggName, seg)
			}
			i++ // consume bucket key segment
			for i+1 < len(segs) {
				candNext := segs[i+1]
				if _, isSub := targetSpec.SubAggs()[candNext]; isSub || candNext == "_count" || candNext == "doc_count" {
					break
				}
				i++
			}
			if i == len(segs)-1 {
				return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, childAggName)
			}
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
		case spec.EffectiveCumulative() != nil:
			if errMsg := validateChildBucketMetricDep("root", aggName, spec.EffectiveCumulative().EffectivePath(), aggs); errMsg != "" {
				return errMsg
			}
		case spec.Derivative != nil:
			if errMsg := validateChildBucketMetricDep("root", aggName, spec.Derivative.EffectivePath(), aggs); errMsg != "" {
				return errMsg
			}
		case spec.EffectiveMovingAvg() != nil:
			if errMsg := validateChildBucketMetricDep("root", aggName, spec.EffectiveMovingAvg().EffectivePath(), aggs); errMsg != "" {
				return errMsg
			}
		case spec.SerialDiff != nil:
			if errMsg := validateChildBucketMetricDep("root", aggName, spec.SerialDiff.EffectivePath(), aggs); errMsg != "" {
				return errMsg
			}
		case spec.Normalize != nil:
			if errMsg := validateChildBucketMetricDep("root", aggName, spec.Normalize.EffectivePath(), aggs); errMsg != "" {
				return errMsg
			}
		case spec.BucketScript != nil:
			if len(spec.BucketScript.BucketsPath) == 0 {
				return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s]", aggName)
			}
			for _, p := range spec.BucketScript.BucketsPath {
				if errMsg := validateChildBucketMetricDep("root", aggName, p, aggs); errMsg != "" {
					return errMsg
				}
			}
		case spec.BucketSelector != nil:
			if len(spec.BucketSelector.BucketsPath) == 0 {
				return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s]", aggName)
			}
			for _, p := range spec.BucketSelector.BucketsPath {
				if errMsg := validateChildBucketMetricDep("root", aggName, p, aggs); errMsg != "" {
					return errMsg
				}
			}
		}
		if pSpec != nil {
			pathStr := strings.TrimSpace(pSpec.EffectivePath())
			segs := normalizeBucketsPath(pathStr)
			if len(segs) == 0 {
				return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s]", aggName)
			}
			currMap := aggs
			var lastSpec esast.AggSpec
			hasBucket := false
			for i := 0; i < len(segs); i++ {
				seg := segs[i]
				if i == 0 && seg == aggName {
					return fmt.Sprintf("cyclic dependency in pipeline aggregation [%s]", aggName)
				}
				targetSpec, exists := currMap[seg]
				if !exists {
					if i > 0 && !isBucketAggSpec(lastSpec) {
						lastSpec = esast.AggSpec{}
						break
					}
					if i == len(segs)-1 && isBucketAggSpec(lastSpec) && (seg == "_count" || seg == "doc_count") {
						lastSpec = esast.AggSpec{}
						break
					}
					if i > 0 && isKeyedBucketAggSpec(lastSpec) {
						if i == len(segs)-1 {
							return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, aggName)
						}
						continue
					}
					if i == 0 {
						return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] references non-existent aggregation [%s]", pathStr, aggName, seg)
					}
					return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] references non-existent metric aggregation [%s]", pathStr, aggName, seg)
				}
				if isBucketAggSpec(targetSpec) || isSiblingPipelineAggSpec(targetSpec) {
					hasBucket = true
				}
				if isMultiBucketAggSpec(targetSpec) && (isKeyedBucketAggSpec(targetSpec) || strings.Contains(pathStr, "[")) {
					if i+1 < len(segs) {
						nextSeg := segs[i+1]
						_, nextIsSubAgg := targetSpec.SubAggs()[nextSeg]
						nextIsKeyCollision := false
						if nextIsSubAgg && i+2 < len(segs) {
							if _, afterIsSub := targetSpec.SubAggs()[segs[i+2]]; afterIsSub || segs[i+2] == "_count" || segs[i+2] == "doc_count" {
								nextIsKeyCollision = true
							}
						}
						if (!nextIsSubAgg && nextSeg != "_count" && nextSeg != "doc_count") || nextIsKeyCollision {
							i++ // consume keyed bucket key segment
							for i+1 < len(segs) {
								candNext := segs[i+1]
								if _, isSub := targetSpec.SubAggs()[candNext]; isSub || candNext == "_count" || candNext == "doc_count" {
									break
								}
								i++
							}
							if i == len(segs)-1 {
								return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, aggName)
							}
						}
					}
				}
				lastSpec = targetSpec
				currMap = targetSpec.SubAggs()
			}
			if !hasBucket || isBucketAggSpec(lastSpec) || lastSpec.StatsBucket != nil || lastSpec.ExtendedStatsBucket != nil || lastSpec.PercentilesBucket != nil {
				return fmt.Sprintf("buckets_path [%s] for pipeline aggregation [%s] must reference a numeric metric or _count, not a bucket aggregation directly", pathStr, aggName)
			}
		}
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			childDeps := make(map[string][]string)
			for subName, subSpec := range subAggs {
				switch {
				case subSpec.EffectiveCumulative() != nil:
					p := subSpec.EffectiveCumulative().EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{firstBucketsPathSeg(p)}
				case subSpec.Derivative != nil:
					p := subSpec.Derivative.EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{firstBucketsPathSeg(p)}
				case subSpec.EffectiveMovingAvg() != nil:
					p := subSpec.EffectiveMovingAvg().EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{firstBucketsPathSeg(p)}
				case subSpec.SerialDiff != nil:
					p := subSpec.SerialDiff.EffectivePath()
					if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
						return errMsg
					}
					childDeps[subName] = []string{firstBucketsPathSeg(p)}
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
					childDeps[subName] = []string{firstBucketsPathSeg(p)}
				case subSpec.BucketScript != nil:
					if len(subSpec.BucketScript.BucketsPath) == 0 {
						return fmt.Sprintf("buckets_path must be provided for pipeline aggregation [%s] under [%s]", subName, aggName)
					}
					var deps []string
					for _, p := range subSpec.BucketScript.BucketsPath {
						if errMsg := validateChildBucketMetricDep(aggName, subName, p, subAggs); errMsg != "" {
							return errMsg
						}
						deps = append(deps, firstBucketsPathSeg(p))
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
	return evaluateBucketSortPipelineAggs(evaluateChildPipelineAggsWithoutBucketSort(buckets, subAggs), subAggs)
}

func evaluateChildPipelineAggsWithoutBucketSort(buckets []map[string]any, subAggs map[string]esast.AggSpec) []map[string]any {
	if len(buckets) == 0 || len(subAggs) == 0 {
		return buckets
	}
	subNames := make([]string, 0, len(subAggs))
	for k := range subAggs {
		subNames = append(subNames, k)
	}
	sort.Strings(subNames)

	isChildMetricPipeline := func(spec esast.AggSpec) bool {
		return spec.EffectiveCumulative() != nil || spec.Derivative != nil || spec.EffectiveMovingAvg() != nil ||
			spec.SerialDiff != nil || spec.Normalize != nil || spec.BucketScript != nil
	}
	depsForSpec := func(spec esast.AggSpec) []string {
		switch {
		case spec.EffectiveCumulative() != nil:
			return []string{firstBucketsPathSeg(spec.EffectiveCumulative().EffectivePath())}
		case spec.Derivative != nil:
			return []string{firstBucketsPathSeg(spec.Derivative.EffectivePath())}
		case spec.EffectiveMovingAvg() != nil:
			return []string{firstBucketsPathSeg(spec.EffectiveMovingAvg().EffectivePath())}
		case spec.SerialDiff != nil:
			return []string{firstBucketsPathSeg(spec.SerialDiff.EffectivePath())}
		case spec.Normalize != nil:
			return []string{firstBucketsPathSeg(spec.Normalize.EffectivePath())}
		case spec.BucketScript != nil:
			var deps []string
			for _, p := range spec.BucketScript.BucketsPath {
				deps = append(deps, firstBucketsPathSeg(p))
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
			case spec.EffectiveCumulative() != nil:
				cumSpec := spec.EffectiveCumulative()
				pathStr := cumSpec.EffectivePath()
				insertZeros := strings.EqualFold(cumSpec.GapPolicy, "insert_zeros")
				var running float64
				for _, b := range buckets {
					v, ok := extractBucketMetricByPath(b, pathStr)
					if !ok && !insertZeros {
						continue
					}
					running += v
					b[subName] = makePipelineMetricObj(running, cumSpec.Format)
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
						b[subName] = makePipelineMetricObj(curr-prev, spec.Derivative.Format)
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
					b[subName] = makePipelineMetricObj(evalMovingWindow(slice, maSpec), maSpec.Format)
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
						b[subName] = makePipelineMetricObj(vals[i]-vals[i-lag], sdSpec.Format)
					}
				}
			case spec.Normalize != nil:
				evalNormalizeOnBuckets(buckets, subName, spec.Normalize)
			case spec.BucketScript != nil:
				for _, b := range buckets {
					if val, ok := evalBucketScript(b, spec.BucketScript); ok && !math.IsNaN(val) && !math.IsInf(val, 0) {
						b[subName] = makePipelineMetricObj(val, spec.BucketScript.Format)
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

	preSelectLen := len(buckets)
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
	if len(buckets) < preSelectLen && len(buckets) > 0 {
		for _, subName := range subNames {
			spec := subAggs[subName]
			if spec.Normalize != nil {
				evalNormalizeOnBuckets(buckets, subName, spec.Normalize)
			}
		}
	}
	return buckets
}

func evaluateBucketSortPipelineAggs(buckets []map[string]any, subAggs map[string]esast.AggSpec) []map[string]any {
	if len(buckets) == 0 || len(subAggs) == 0 {
		return buckets
	}
	subNames := make([]string, 0, len(subAggs))
	for k := range subAggs {
		subNames = append(subNames, k)
	}
	sort.Strings(subNames)
	for _, subName := range subNames {
		spec := subAggs[subName]
		if spec.BucketSort != nil {
			bs := spec.BucketSort
			if len(bs.Sort) > 0 && len(buckets) > 1 {
				sort.SliceStable(buckets, func(i, j int) bool {
					for _, sSpec := range bs.Sort {
						field := sSpec.Entry.Field
						desc := strings.EqualFold(sSpec.Entry.Order, "desc")
						if field == "_key" || field == "key" || strings.HasPrefix(field, "_key.") || strings.HasPrefix(field, "key.") {
							rawKI := buckets[i]["key"]
							rawKJ := buckets[j]["key"]
							if strings.HasPrefix(field, "_key.") || strings.HasPrefix(field, "key.") {
								subKey := strings.TrimPrefix(strings.TrimPrefix(field, "_key."), "key.")
								if kmI, okMI := rawKI.(map[string]any); okMI {
									rawKI = kmI[subKey]
								}
								if kmJ, okMJ := rawKJ.(map[string]any); okMJ {
									rawKJ = kmJ[subKey]
								}
							} else if kmI, okMI := rawKI.(map[string]any); okMI {
								if kmJ, okMJ := rawKJ.(map[string]any); okMJ {
									ks := make([]string, 0, len(kmI))
									for k := range kmI {
										ks = append(ks, k)
									}
									sort.Strings(ks)
									for _, k := range ks {
										if cmp := compareAny(kmI[k], kmJ[k]); cmp != 0 {
											if desc {
												return cmp > 0
											}
											return cmp < 0
										}
									}
									continue
								}
							}
							if cmp := compareAny(rawKI, rawKJ); cmp != 0 {
								if desc {
									return cmp > 0
								}
								return cmp < 0
							}
							continue
						}
						vi, okI := extractBucketMetricByPath(buckets[i], field)
						vj, okJ := extractBucketMetricByPath(buckets[j], field)
						if strings.EqualFold(bs.GapPolicy, "insert_zeros") {
							if !okI {
								vi, okI = 0, true
							}
							if !okJ {
								vj, okJ = 0, true
							}
						}
						if sSpec.Entry.Missing != "" && !strings.EqualFold(sSpec.Entry.Missing, "_first") && !strings.EqualFold(sSpec.Entry.Missing, "_last") {
							if mf, okM := parseFiniteFloat(sSpec.Entry.Missing); okM {
								if !okI {
									vi, okI = mf, true
								}
								if !okJ {
									vj, okJ = mf, true
								}
							}
						}
						if !okI && !okJ {
							if si, okSI := buckets[i][field]; okSI || buckets[j][field] != nil {
								if cmp := compareAny(si, buckets[j][field]); cmp != 0 {
									if desc {
										return cmp > 0
									}
									return cmp < 0
								}
							}
							continue
						}
						missingFirst := strings.EqualFold(sSpec.Entry.Missing, "_first")
						if !okI {
							return missingFirst
						}
						if !okJ {
							return !missingFirst
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
		alpha := 0.3
		if maSpec.Settings != nil {
			if aVal, ok := toFloat64(maSpec.Settings["alpha"]); ok && aVal > 0 && aVal <= 1 {
				alpha = aVal
			}
		}
		src, params := extractScriptSourceAndParams(maSpec.Script)
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
			if idx := strings.Index(src, "MovingFunctions.ewma("); idx >= 0 {
				rest := src[idx+len("MovingFunctions.ewma("):]
				if closeIdx := strings.IndexByte(rest, ')'); closeIdx >= 0 {
					args := strings.Split(rest[:closeIdx], ",")
					if len(args) >= 2 {
						argStr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(args[1]), "f"))
						argStr = strings.TrimSuffix(argStr, "d")
						if aVal, err := strconv.ParseFloat(argStr, 64); err == nil && aVal > 0 && aVal <= 1 {
							alpha = aVal
						} else if params != nil {
							pKey := strings.TrimPrefix(strings.TrimSpace(args[1]), "params.")
							if aVal, ok := toFloat64(params[pKey]); ok && aVal > 0 && aVal <= 1 {
								alpha = aVal
							}
						}
					}
				}
			}
			ewma := slice[0]
			for idx := 1; idx < len(slice); idx++ {
				ewma = alpha*slice[idx] + (1-alpha)*ewma
			}
			return ewma
		case strings.Contains(src, "MovingFunctions.unweightedAvg"):
			var sum float64
			for _, v := range slice {
				sum += v
			}
			return sum / float64(len(slice))
		case src != "":
			evalParams := make(map[string]any, len(params)+1)
			for k, v := range params {
				evalParams[k] = v
			}
			valsAny := make([]any, len(slice))
			for i, v := range slice {
				valsAny[i] = v
			}
			evalParams["values"] = valsAny
			if fv, ok, err := painless.EvalNumber(map[string]any{}, src, evalParams); err == nil && ok {
				return fv
			}
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
			case []any:
				for _, item := range rawBuckets {
					if b, okB := item.(map[string]any); okB {
						evaluateSiblingPipelineAggs(spec.SubAggs(), b)
					}
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
	var pipeNames []string
	for aggName, spec := range aggs {
		if spec.AvgBucket != nil || spec.SumBucket != nil || spec.MinBucket != nil || spec.MaxBucket != nil ||
			spec.StatsBucket != nil || spec.ExtendedStatsBucket != nil || spec.PercentilesBucket != nil {
			pipeNames = append(pipeNames, aggName)
		}
	}
	sort.Strings(pipeNames)
	// Order sibling pipeline aggs topologically so chained sibling pipeline aggs evaluate after their dependencies.
	orderedNames := make([]string, 0, len(pipeNames))
	placed := make(map[string]bool, len(pipeNames))
	for pass := 0; pass < len(pipeNames); pass++ {
		progress := false
		for _, aggName := range pipeNames {
			if placed[aggName] {
				continue
			}
			spec := aggs[aggName]
			var bp string
			switch {
			case spec.AvgBucket != nil:
				bp = spec.AvgBucket.EffectivePath()
			case spec.SumBucket != nil:
				bp = spec.SumBucket.EffectivePath()
			case spec.MinBucket != nil:
				bp = spec.MinBucket.EffectivePath()
			case spec.MaxBucket != nil:
				bp = spec.MaxBucket.EffectivePath()
			case spec.StatsBucket != nil:
				bp = spec.StatsBucket.EffectivePath()
			case spec.ExtendedStatsBucket != nil:
				bp = spec.ExtendedStatsBucket.EffectivePath()
			case spec.PercentilesBucket != nil:
				pTmp := esast.PipelineAggSpec{BucketsPath: spec.PercentilesBucket.BucketsPath}
				bp = pTmp.EffectivePath()
			}
			segs := normalizeBucketsPath(bp)
			depReady := true
			for _, other := range pipeNames {
				if other != aggName && !placed[other] {
					for _, seg := range segs {
						cleanSeg := seg
						if brIdx := strings.IndexByte(cleanSeg, '['); brIdx > 0 {
							cleanSeg = cleanSeg[:brIdx]
						}
						if cleanSeg == other {
							depReady = false
							break
						}
					}
					if !depReady {
						break
					}
				}
			}
			if depReady || pass == len(pipeNames)-1 {
				placed[aggName] = true
				orderedNames = append(orderedNames, aggName)
				progress = true
			}
		}
		if !progress || len(orderedNames) == len(pipeNames) {
			break
		}
	}
	for _, aggName := range orderedNames {
		spec := aggs[aggName]
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
		policy := pSpec.GapPolicy
		if (policy == "" || strings.EqualFold(policy, "skip")) && isChildPipelineTargetInAggs(aggs, pathStr) {
			policy = "allow_zero_doc_count"
		}
		vals := collectSiblingBucketValuesWithPolicy(aggsOut, pathStr, policy)
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
			if len(vals) == 0 {
				aggsOut[aggName] = map[string]any{"value": nil}
			} else {
				aggsOut[aggName] = makePipelineMetricObj(avgVal, pSpec.Format)
			}
		case "sum":
			aggsOut[aggName] = makePipelineMetricObj(sumVal, pSpec.Format)
		case "min":
			if len(vals) == 0 {
				aggsOut[aggName] = map[string]any{"value": nil}
			} else {
				aggsOut[aggName] = makePipelineMetricObj(minVal, pSpec.Format)
			}
		case "max":
			if len(vals) == 0 {
				aggsOut[aggName] = map[string]any{"value": nil}
			} else {
				aggsOut[aggName] = makePipelineMetricObj(maxVal, pSpec.Format)
			}
		case "stats":
			if len(vals) == 0 {
				aggsOut[aggName] = map[string]any{
					"count": int64(0),
					"min":   nil,
					"max":   nil,
					"avg":   nil,
					"sum":   0.0,
				}
			} else {
				statsObj := map[string]any{
					"count": int64(len(vals)),
					"min":   minVal,
					"max":   maxVal,
					"avg":   avgVal,
					"sum":   sumVal,
				}
				if pSpec.Format != "" {
					statsObj["min_as_string"] = formatPipelineMetricValue(minVal, pSpec.Format)
					statsObj["max_as_string"] = formatPipelineMetricValue(maxVal, pSpec.Format)
					statsObj["avg_as_string"] = formatPipelineMetricValue(avgVal, pSpec.Format)
					statsObj["sum_as_string"] = formatPipelineMetricValue(sumVal, pSpec.Format)
				}
				aggsOut[aggName] = statsObj
			}
		case "extended_stats":
			cnt := len(vals)
			if cnt == 0 {
				aggsOut[aggName] = map[string]any{
					"count":                    int64(0),
					"min":                      nil,
					"max":                      nil,
					"avg":                      nil,
					"sum":                      0.0,
					"sum_of_squares":           nil,
					"variance":                 nil,
					"variance_population":      nil,
					"variance_sampling":        nil,
					"std_deviation":            nil,
					"std_deviation_population": nil,
					"std_deviation_sampling":   nil,
					"std_deviation_bounds": map[string]any{
						"upper":            nil,
						"lower":            nil,
						"upper_population": nil,
						"lower_population": nil,
						"upper_sampling":   nil,
						"lower_sampling":   nil,
					},
				}
				continue
			}
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
			upperPop := avgVal + sigma*stdPop
			lowerPop := avgVal - sigma*stdPop
			upperSamp := avgVal + sigma*stdSampling
			lowerSamp := avgVal - sigma*stdSampling
			boundsObj := map[string]any{
				"upper":            upperPop,
				"lower":            lowerPop,
				"upper_population": upperPop,
				"lower_population": lowerPop,
				"upper_sampling":   upperSamp,
				"lower_sampling":   lowerSamp,
			}
			extObj := map[string]any{
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
				"std_deviation_bounds":     boundsObj,
			}
			if pSpec.Format != "" {
				extObj["min_as_string"] = formatPipelineMetricValue(minVal, pSpec.Format)
				extObj["max_as_string"] = formatPipelineMetricValue(maxVal, pSpec.Format)
				extObj["avg_as_string"] = formatPipelineMetricValue(avgVal, pSpec.Format)
				extObj["sum_as_string"] = formatPipelineMetricValue(sumVal, pSpec.Format)
				extObj["sum_of_squares_as_string"] = formatPipelineMetricValue(sumSqVal, pSpec.Format)
				extObj["variance_as_string"] = formatPipelineMetricValue(variancePop, pSpec.Format)
				extObj["variance_population_as_string"] = formatPipelineMetricValue(variancePop, pSpec.Format)
				extObj["variance_sampling_as_string"] = formatPipelineMetricValue(varianceSampling, pSpec.Format)
				extObj["std_deviation_as_string"] = formatPipelineMetricValue(stdPop, pSpec.Format)
				extObj["std_deviation_population_as_string"] = formatPipelineMetricValue(stdPop, pSpec.Format)
				extObj["std_deviation_sampling_as_string"] = formatPipelineMetricValue(stdSampling, pSpec.Format)
				boundsObj["upper_as_string"] = formatPipelineMetricValue(upperPop, pSpec.Format)
				boundsObj["lower_as_string"] = formatPipelineMetricValue(lowerPop, pSpec.Format)
				boundsObj["upper_population_as_string"] = formatPipelineMetricValue(upperPop, pSpec.Format)
				boundsObj["lower_population_as_string"] = formatPipelineMetricValue(lowerPop, pSpec.Format)
				boundsObj["upper_sampling_as_string"] = formatPipelineMetricValue(upperSamp, pSpec.Format)
				boundsObj["lower_sampling_as_string"] = formatPipelineMetricValue(lowerSamp, pSpec.Format)
			}
			aggsOut[aggName] = extObj
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
					if len(sortedVals) == 0 {
						arr = append(arr, map[string]any{
							"key":   p,
							"value": nil,
						})
						continue
					}
					pctVal := computePct(p)
					item := map[string]any{
						"key":   p,
						"value": pctVal,
					}
					if spec.PercentilesBucket.Format != "" {
						item["value_as_string"] = formatPipelineMetricValue(pctVal, spec.PercentilesBucket.Format)
					}
					arr = append(arr, item)
				}
				aggsOut[aggName] = map[string]any{"values": arr}
			} else {
				vMap := make(map[string]any, len(percents))
				var vStrMap map[string]string
				if spec.PercentilesBucket.Format != "" && len(sortedVals) > 0 {
					vStrMap = make(map[string]string, len(percents))
				}
				for _, p := range percents {
					kStr := strconv.FormatFloat(p, 'f', -1, 64)
					if !strings.Contains(kStr, ".") {
						kStr += ".0"
					}
					if len(sortedVals) == 0 {
						vMap[kStr] = nil
						continue
					}
					pctVal := computePct(p)
					vMap[kStr] = pctVal
					if vStrMap != nil {
						vStrMap[kStr] = formatPipelineMetricValue(pctVal, spec.PercentilesBucket.Format)
					}
				}
				pctObj := map[string]any{"values": vMap}
				if vStrMap != nil {
					pctObj["values_as_string"] = vStrMap
				}
				aggsOut[aggName] = pctObj
			}
		}
	}
}

func formatPipelineMetricValue(val float64, format string) string {
	format = strings.TrimSpace(format)
	if format == "" {
		return ""
	}
	if strings.HasSuffix(format, "%") {
		return fmt.Sprintf("%.2f%%", val)
	}
	if idx := strings.IndexByte(format, '.'); idx >= 0 {
		frac := format[idx+1:]
		decimals := 0
		for _, ch := range frac {
			if ch == '0' || ch == '#' {
				decimals++
			}
		}
		if decimals > 0 {
			return fmt.Sprintf("%.*f", decimals, val)
		}
	}
	return fmt.Sprintf("%.2f", val)
}

func makePipelineMetricObj(val float64, format string) map[string]any {
	out := map[string]any{"value": val}
	if s := formatPipelineMetricValue(val, format); s != "" {
		out["value_as_string"] = s
	}
	return out
}

func evalNormalizeOnBuckets(buckets []map[string]any, subName string, normSpec *esast.NormalizeAggSpec) {
	if normSpec == nil || len(buckets) == 0 {
		return
	}
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
	if validCount == 0 {
		return
	}
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
		b[subName] = makePipelineMetricObj(normVal, normSpec.Format)
	}
}

func isChildPipelineTargetInAggs(aggs map[string]esast.AggSpec, bucketsPath string) bool {
	segs := normalizeBucketsPath(bucketsPath)
	curr := aggs
	for _, seg := range segs {
		spec, ok := curr[seg]
		if !ok {
			continue
		}
		if spec.EffectiveCumulative() != nil || spec.Derivative != nil || spec.EffectiveMovingAvg() != nil ||
			spec.SerialDiff != nil || spec.Normalize != nil || spec.BucketScript != nil {
			return true
		}
		curr = spec.SubAggs()
	}
	return false
}

func bucketKeysEquivalent(a, b string) bool {
	if a == b {
		return true
	}
	if fa, okA := parseFiniteFloat(a); okA {
		if fb, okB := parseFiniteFloat(b); okB && math.Abs(fa-fb) < 1e-9 {
			return true
		}
	}
	nowUTC := time.Now().UTC()
	if msA, okA := schema.ParseESDateToEpochMillis(a, nowUTC); okA {
		if msB, okB := schema.ParseESDateToEpochMillis(b, nowUTC); okB && msA == msB {
			return true
		}
	}
	return false
}

func lookupKeyedBucketMap(rawBuckets map[string]any, candKey string) (map[string]any, bool) {
	if rawBuckets == nil {
		return nil, false
	}
	if b, ok := rawBuckets[candKey].(map[string]any); ok {
		return b, true
	}
	if strings.HasSuffix(candKey, ".0") {
		if b, ok := rawBuckets[strings.TrimSuffix(candKey, ".0")].(map[string]any); ok {
			return b, true
		}
	} else if !strings.Contains(candKey, ".") {
		if b, ok := rawBuckets[candKey+".0"].(map[string]any); ok {
			return b, true
		}
	}
	for k, v := range rawBuckets {
		b, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if bucketKeysEquivalent(k, candKey) {
			return b, true
		}
		if keyVal, hasK := b["key"]; hasK && keyVal != nil && bucketKeysEquivalent(fmt.Sprintf("%v", keyVal), candKey) {
			return b, true
		}
		if kas, okS := b["key_as_string"].(string); okS && kas != "" && bucketKeysEquivalent(kas, candKey) {
			return b, true
		}
	}
	return nil, false
}

func collectSiblingBucketValuesWithPolicy(aggsOut map[string]any, bucketsPath, gapPolicy string) []float64 {
	insertZeros := strings.EqualFold(gapPolicy, "insert_zeros")
	allowZeroDocCount := insertZeros || strings.EqualFold(gapPolicy, "allow_zero_doc_count")
	segs := normalizeBucketsPath(bucketsPath)
	if len(segs) == 0 {
		return nil
	}
	targetAgg, ok := aggsOut[segs[0]].(map[string]any)
	if !ok {
		return nil
	}
	rest := segs[1:]
	if len(rest) == 0 {
		if v, okV := toFloat64(targetAgg["value"]); okV {
			return []float64{v}
		}
		if _, hasVal := targetAgg["value"]; hasVal {
			return nil
		}
		rest = []string{"_count"}
	}
	var out []float64
	collectValuesFromAggContainerWithZeroPolicy(targetAgg, rest, insertZeros, allowZeroDocCount, &out)
	return out
}

func collectValuesFromAggContainerWithZeroPolicy(container map[string]any, segs []string, insertZeros, allowZeroDocCount bool, out *[]float64) {
	if container == nil || len(segs) == 0 {
		return
	}
	isCountTarget := len(segs) == 1 && (segs[0] == "_count" || segs[0] == "doc_count")

	traverseBucket := func(b map[string]any, rem []string) {
		if b == nil || len(rem) == 0 {
			return
		}
		remIsCount := len(rem) == 1 && (rem[0] == "_count" || rem[0] == "doc_count")
		if dc, hasDC := toFloat64(b["doc_count"]); hasDC && dc == 0 && !allowZeroDocCount && !remIsCount {
			return
		}
		if len(rem) > 1 {
			if sub, ok := b[rem[0]].(map[string]any); ok && isRuntimeBucketContainer(sub) {
				collectValuesFromAggContainerWithZeroPolicy(sub, rem[1:], insertZeros, allowZeroDocCount, out)
				return
			}
		}
		if v, ok := extractBucketMetricBySegs(b, rem); ok {
			*out = append(*out, v)
		} else if insertZeros {
			*out = append(*out, 0)
		}
	}

	rawBucketsVal := container["buckets"]
	if anySlice, okAny := rawBucketsVal.([]any); okAny {
		converted := make([]map[string]any, 0, len(anySlice))
		for _, item := range anySlice {
			if m, okM := item.(map[string]any); okM {
				converted = append(converted, m)
			}
		}
		rawBucketsVal = converted
	}
	switch rawBuckets := rawBucketsVal.(type) {
	case []map[string]any:
		if len(segs) >= 1 && segs[0] != "_count" && segs[0] != "doc_count" && segs[0] != "_key" && segs[0] != "key" {
			for k := 1; k <= len(segs); k++ {
				candKey := strings.Join(segs[:k], ".")
				for _, b := range rawBuckets {
					if _, isChildProp := b[candKey]; !isChildProp && (fmt.Sprintf("%v", b["key"]) == candKey || (b["key_as_string"] != nil && fmt.Sprintf("%v", b["key_as_string"]) == candKey)) {
						rem := segs[k:]
						if len(rem) == 0 {
							rem = []string{"_count"}
						}
						traverseBucket(b, rem)
						return
					}
				}
			}
		}
		for _, b := range rawBuckets {
			traverseBucket(b, segs)
		}
	case map[string]any:
		if len(segs) >= 1 {
			for k := 1; k <= len(segs); k++ {
				candKey := strings.Join(segs[:k], ".")
				if specificBucket, ok := lookupKeyedBucketMap(rawBuckets, candKey); ok {
					rem := segs[k:]
					if len(rem) == 0 {
						rem = []string{"_count"}
					}
					traverseBucket(specificBucket, rem)
					return
				}
			}
		}
		var ks []string
		for k := range rawBuckets {
			ks = append(ks, k)
		}
		sort.SliceStable(ks, func(i, j int) bool {
			bi, okI := rawBuckets[ks[i]].(map[string]any)
			bj, okJ := rawBuckets[ks[j]].(map[string]any)
			if okI && okJ {
				fi, okFI := toFloat64(bi["key"])
				fj, okFJ := toFloat64(bj["key"])
				if !okFI || !okFJ {
					fi, okFI = toFloat64(bi["from"])
					fj, okFJ = toFloat64(bj["from"])
					if okFI != okFJ {
						return !okFI
					}
					if !okFI && !okFJ {
						fi, okFI = toFloat64(bi["to"])
						fj, okFJ = toFloat64(bj["to"])
					}
				}
				if okFI && okFJ && fi != fj {
					return fi < fj
				}
			}
			return ks[i] < ks[j]
		})
		for _, k := range ks {
			if b, ok := rawBuckets[k].(map[string]any); ok {
				traverseBucket(b, segs)
			}
		}
	default:
		if dc, hasDC := toFloat64(container["doc_count"]); hasDC && dc == 0 && !allowZeroDocCount && !isCountTarget {
			return
		}
		if len(segs) > 1 {
			if sub, ok := container[segs[0]].(map[string]any); ok && isRuntimeBucketContainer(sub) {
				collectValuesFromAggContainerWithZeroPolicy(sub, segs[1:], insertZeros, allowZeroDocCount, out)
				return
			}
		}
		if v, ok := extractBucketMetricBySegs(container, segs); ok {
			*out = append(*out, v)
		} else if insertZeros {
			*out = append(*out, 0)
		}
	}
}

func extractBucketMetricByPath(b map[string]any, metricPath string) (float64, bool) {
	return extractBucketMetricBySegs(b, normalizeBucketsPath(metricPath))
}

func extractBucketMetricBySegs(b map[string]any, segs []string) (float64, bool) {
	if b == nil || len(segs) == 0 {
		return 0, false
	}
	if len(segs) == 1 {
		seg := segs[0]
		switch seg {
		case "_count", "doc_count":
			return toFloat64(b["doc_count"])
		case "_key", "key":
			return toFloat64(b["key"])
		}
		if subMap, ok := b[seg].(map[string]any); ok {
			if v, okV := toFloat64(subMap["value"]); okV {
				return v, true
			}
			return 0, false
		}
		return toFloat64(b[seg])
	}

	head := segs[0]
	tail := segs[1:]
	subMap, ok := b[head].(map[string]any)
	if !ok {
		if rawBuckets, okB := b["buckets"].(map[string]any); okB {
			for k := 1; k <= len(segs); k++ {
				candKey := strings.Join(segs[:k], ".")
				if keyedBucket, okKB := lookupKeyedBucketMap(rawBuckets, candKey); okKB {
					rem := segs[k:]
					if len(rem) == 0 {
						rem = []string{"_count"}
					}
					tailIsCount := len(rem) == 1 && (rem[0] == "_count" || rem[0] == "doc_count")
					if dc, hasDC := toFloat64(keyedBucket["doc_count"]); hasDC && dc == 0 && !tailIsCount {
						return 0, false
					}
					return extractBucketMetricBySegs(keyedBucket, rem)
				}
			}
		} else if rawSlice, okS := b["buckets"].([]map[string]any); okS {
			for k := 1; k <= len(segs); k++ {
				candKey := strings.Join(segs[:k], ".")
				for _, sb := range rawSlice {
					if fmt.Sprintf("%v", sb["key"]) == candKey || (sb["key_as_string"] != nil && fmt.Sprintf("%v", sb["key_as_string"]) == candKey) {
						rem := segs[k:]
						if len(rem) == 0 {
							rem = []string{"_count"}
						}
						tailIsCount := len(rem) == 1 && (rem[0] == "_count" || rem[0] == "doc_count")
						if dc, hasDC := toFloat64(sb["doc_count"]); hasDC && dc == 0 && !tailIsCount {
							return 0, false
						}
						return extractBucketMetricBySegs(sb, rem)
					}
				}
			}
		}
		return 0, false
	}

	if isRuntimeBucketContainer(subMap) {
		if rawBuckets, okB := subMap["buckets"].(map[string]any); okB && len(tail) > 0 {
			for k := 1; k <= len(tail); k++ {
				candKey := strings.Join(tail[:k], ".")
				if keyedBucket, okKB := lookupKeyedBucketMap(rawBuckets, candKey); okKB {
					nextTail := tail[k:]
					if len(nextTail) == 0 {
						nextTail = []string{"_count"}
					}
					tailIsCount := len(nextTail) == 1 && (nextTail[0] == "_count" || nextTail[0] == "doc_count")
					if dc, hasDC := toFloat64(keyedBucket["doc_count"]); hasDC && dc == 0 && !tailIsCount {
						return 0, false
					}
					return extractBucketMetricBySegs(keyedBucket, nextTail)
				}
			}
		} else if rawSlice, okS := subMap["buckets"].([]map[string]any); okS && len(tail) > 0 {
			for k := 1; k <= len(tail); k++ {
				candKey := strings.Join(tail[:k], ".")
				for _, sb := range rawSlice {
					if fmt.Sprintf("%v", sb["key"]) == candKey || (sb["key_as_string"] != nil && fmt.Sprintf("%v", sb["key_as_string"]) == candKey) {
						nextTail := tail[k:]
						if len(nextTail) == 0 {
							nextTail = []string{"_count"}
						}
						tailIsCount := len(nextTail) == 1 && (nextTail[0] == "_count" || nextTail[0] == "doc_count")
						if dc, hasDC := toFloat64(sb["doc_count"]); hasDC && dc == 0 && !tailIsCount {
							return 0, false
						}
						return extractBucketMetricBySegs(sb, nextTail)
					}
				}
			}
		}
		tailIsCount := len(tail) == 1 && (tail[0] == "_count" || tail[0] == "doc_count")
		if dc, hasDC := toFloat64(subMap["doc_count"]); hasDC && dc == 0 && !tailIsCount {
			return 0, false
		}
		return extractBucketMetricBySegs(subMap, tail)
	}

	prop := strings.Join(tail, ".")
	if cnt, hasCnt := toFloat64(subMap["count"]); hasCnt && cnt == 0 && prop != "count" && prop != "sum" {
		return 0, false
	}
	if dc, hasDC := toFloat64(b["doc_count"]); hasDC && dc == 0 && prop != "_count" && prop != "doc_count" && prop != "count" {
		if _, hasVals := subMap["values"]; hasVals {
			return 0, false
		}
		if _, hasQ1 := subMap["q1"]; hasQ1 {
			return 0, false
		}
	}
	if len(tail) == 1 {
		if prop == "_count" || prop == "doc_count" {
			if v, okV := toFloat64(subMap["doc_count"]); okV {
				return v, true
			}
		}
		if v, okV := toFloat64(subMap[prop]); okV {
			return v, true
		}
	}
	if valMap, okVM := subMap["value"].(map[string]any); okVM {
		valTail := tail
		if len(valTail) > 1 && valTail[0] == "value" {
			valTail = valTail[1:]
		}
		if v, okV := extractBucketMetricBySegs(valMap, valTail); okV {
			return v, true
		}
	}
	if valsMap, okVals := subMap["values"].(map[string]float64); okVals {
		if v, exists := valsMap[prop]; exists {
			return v, true
		}
		if !strings.Contains(prop, ".") {
			if v, exists := valsMap[prop+".0"]; exists {
				return v, true
			}
		}
	}
	if valsMapAny, okVals := subMap["values"].(map[string]any); okVals {
		if v, okV := toFloat64(valsMapAny[prop]); okV {
			return v, true
		}
		if !strings.Contains(prop, ".") {
			if v, okV := toFloat64(valsMapAny[prop+".0"]); okV {
				return v, true
			}
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
	if len(tail) > 1 {
		if nextMap, okNM := subMap[tail[0]].(map[string]any); okNM {
			if v, okV := extractBucketMetricBySegs(nextMap, tail[1:]); okV {
				return v, true
			}
		}
	}
	return extractBucketMetricBySegs(subMap, tail)
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
	src, scriptParams := extractScriptSourceAndParams(spec.Script)
	if src == "" {
		return 0, false
	}
	insertZeros := strings.EqualFold(spec.GapPolicy, "insert_zeros")
	vars := make(map[string]float64, len(spec.BucketsPath)+len(scriptParams))
	for k, v := range scriptParams {
		if fv, ok := toFloat64(v); ok {
			vars[k] = fv
		}
	}
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
	if !strings.ContainsAny(src, ";{}") && !strings.Contains(src, "def ") && !strings.Contains(src, "if ") && !strings.Contains(src, "if(") {
		if fv, ok := evalBucketArithmeticExprDepth(src, vars, 0); ok {
			if math.IsNaN(fv) || math.IsInf(fv, 0) {
				return 0, false
			}
			return fv, true
		}
	}
	painlessParams := make(map[string]any, len(vars)+len(scriptParams))
	for k, v := range scriptParams {
		painlessParams[k] = v
	}
	for k, v := range vars {
		painlessParams[k] = v
	}
	if res, err := painless.Eval(map[string]any{}, src, painlessParams); err == nil && res != nil {
		return toFloat64(res)
	}
	return 0, false
}

func extractScriptSourceAndParams(script any) (string, map[string]any) {
	var src string
	var params map[string]any
	switch sv := script.(type) {
	case string:
		src = sv
	case map[string]any:
		if inner, ok := sv["script"]; ok && inner != nil {
			return extractScriptSourceAndParams(inner)
		}
		if s, ok := sv["source"].(string); ok {
			src = s
		} else if s, ok := sv["inline"].(string); ok {
			src = s
		}
		if pm, ok := sv["params"].(map[string]any); ok {
			params = pm
		}
	}
	return strings.TrimSpace(src), params
}

func evalBucketSelector(b map[string]any, spec *esast.BucketSelectorAggSpec) bool {
	if spec == nil {
		return true
	}
	src, scriptParams := extractScriptSourceAndParams(spec.Script)
	if src == "" {
		return true
	}
	insertZeros := strings.EqualFold(spec.GapPolicy, "insert_zeros")
	vars := make(map[string]float64, len(spec.BucketsPath)+len(scriptParams))
	for k, v := range scriptParams {
		if fv, ok := toFloat64(v); ok {
			vars[k] = fv
		}
	}
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
	if strings.ContainsAny(src, ";{") || strings.Contains(src, "def ") || strings.Contains(src, "return ") || strings.Contains(src, "Math.") {
		painlessParams := make(map[string]any, len(vars)+len(scriptParams))
		for k, v := range scriptParams {
			painlessParams[k] = v
		}
		for k, v := range vars {
			painlessParams[k] = v
		}
		if ok, err := painless.EvalFilter(map[string]any{}, src, painlessParams); err == nil {
			return ok
		}
	}
	if res, ok := evalBucketSelectorExpr(src, vars); ok {
		return res
	}
	painlessParams := make(map[string]any, len(vars)+len(scriptParams))
	for k, v := range scriptParams {
		painlessParams[k] = v
	}
	for k, v := range vars {
		painlessParams[k] = v
	}
	if ok, err := painless.EvalFilter(map[string]any{}, src, painlessParams); err == nil {
		return ok
	}
	return false
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

func evalBucketSelectorExpr(expr string, vars map[string]float64) (bool, bool) {
	return evalBucketSelectorExprDepth(expr, vars, 0)
}

func evalBucketSelectorExprDepth(expr string, vars map[string]float64, depth int) (bool, bool) {
	if depth > 64 {
		return false, false
	}
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "return ") || strings.HasPrefix(expr, "return\t") || strings.HasPrefix(expr, "return(") {
		expr = strings.TrimSpace(strings.TrimPrefix(expr, "return"))
	}
	expr = strings.TrimSpace(strings.TrimSuffix(expr, ";"))
	expr = trimOuterParens(expr)
	if expr == "" {
		return true, true
	}
	if strings.EqualFold(expr, "true") {
		return true, true
	}
	if strings.EqualFold(expr, "false") {
		return false, true
	}
	if qIdx := findTopLevelOp(expr, "?"); qIdx > 0 {
		rest := expr[qIdx+1:]
		if cIdx := findMatchingTernaryColon(rest); cIdx > 0 {
			condVal, okCond := evalBucketSelectorExprDepth(expr[:qIdx], vars, depth+1)
			if !okCond {
				return false, false
			}
			if condVal {
				return evalBucketSelectorExprDepth(rest[:cIdx], vars, depth+1)
			}
			return evalBucketSelectorExprDepth(rest[cIdx+1:], vars, depth+1)
		}
	}
	if parts := splitTopLevelLogicalOp(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			val, ok := evalBucketSelectorExprDepth(p, vars, depth+1)
			if !ok {
				return false, false
			}
			if val {
				return true, true
			}
		}
		return false, true
	}
	if parts := splitTopLevelLogicalOp(expr, "&&"); len(parts) > 1 {
		for _, p := range parts {
			val, ok := evalBucketSelectorExprDepth(p, vars, depth+1)
			if !ok {
				return false, false
			}
			if !val {
				return false, true
			}
		}
		return true, true
	}
	if strings.HasPrefix(expr, "!") && !strings.HasPrefix(expr, "!=") {
		val, ok := evalBucketSelectorExprDepth(expr[1:], vars, depth+1)
		if !ok {
			return false, false
		}
		return !val, true
	}
	for _, op := range []string{">=", "<=", "!=", "==", ">", "<"} {
		if idx := findTopLevelOp(expr, op); idx > 0 {
			lVal, okL := evalBucketArithmeticExprDepth(expr[:idx], vars, depth+1)
			rVal, okR := evalBucketArithmeticExprDepth(expr[idx+len(op):], vars, depth+1)
			if !okL || !okR {
				return false, false
			}
			switch op {
			case ">=":
				return lVal >= rVal, true
			case "<=":
				return lVal <= rVal, true
			case "!=":
				return lVal != rVal, true
			case "==":
				return lVal == rVal, true
			case ">":
				return lVal > rVal, true
			case "<":
				return lVal < rVal, true
			}
		}
	}
	return false, false
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
			condVal, okCond := evalBucketSelectorExprDepth(expr[:qIdx], vars, depth+1)
			if !okCond {
				return 0, false
			}
			if condVal {
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
		return sum, true
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
		return res, true
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
		return prod, true
	}
	if parts := splitTopLevelBinaryMath(expr, '/'); len(parts) >= 2 {
		res, ok := evalBucketArithmeticExprDepth(parts[0], vars, depth+1)
		if !ok {
			return 0, false
		}
		for _, p := range parts[1:] {
			denom, okD := evalBucketArithmeticExprDepth(p, vars, depth+1)
			if !okD {
				return 0, false
			}
			if denom == 0 {
				return math.NaN(), true
			}
			res /= denom
		}
		return res, true
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
	boundRngSpec := &esast.RangeAggSpec{
		Format:   spec.Format,
		TimeZone: spec.TimeZone,
	}
	if spec.HardBounds != nil {
		if spec.HardBounds.Min != nil {
			if ms, ok := parseRuntimeDateRangeBoundMillis(spec.HardBounds.Min, boundRngSpec, nowUTC); ok {
				hardMin = floorDateBucket(ms)
				hasHardMin = true
			} else if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.HardBounds.Min), nowUTC, false); ok {
				hardMin = floorDateBucket(ms)
				hasHardMin = true
			}
		}
		if spec.HardBounds.Max != nil {
			if ms, ok := parseRuntimeDateRangeBoundMillis(spec.HardBounds.Max, boundRngSpec, nowUTC); ok {
				hardMax = floorDateBucket(ms)
				hasHardMax = true
			} else if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.HardBounds.Max), nowUTC, true); ok {
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
		if spec.MinDocCount != nil && *spec.MinDocCount > 0 {
			minCnt := int64(*spec.MinDocCount)
			filtered := make([]AggRow, 0, len(rows))
			for _, r := range rows {
				if r.effectiveCount() >= minCnt {
					filtered = append(filtered, r)
				}
			}
			return filtered
		}
		return rows
	}

	byKey := make(map[int64]AggRow, len(rows))
	var minKey, maxKey int64
	hasObserved := false
	hasMinKey, hasMaxKey := false, false
	for _, r := range rows {
		if k, err := strconv.ParseInt(r.BucketKey, 10, 64); err == nil {
			byKey[k] = r
			if !hasMinKey || k < minKey {
				minKey = k
				hasMinKey = true
			}
			if !hasMaxKey || k > maxKey {
				maxKey = k
				hasMaxKey = true
			}
			hasObserved = true
		}
	}
	if spec.ExtendedBounds != nil {
		if spec.ExtendedBounds.Min != nil {
			if ms, ok := parseRuntimeDateRangeBoundMillis(spec.ExtendedBounds.Min, boundRngSpec, nowUTC); ok {
				extMin := floorDateBucket(ms)
				if !hasMinKey || extMin < minKey {
					minKey = extMin
					hasMinKey = true
				}
			} else if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.ExtendedBounds.Min), nowUTC, false); ok {
				extMin := floorDateBucket(ms)
				if !hasMinKey || extMin < minKey {
					minKey = extMin
					hasMinKey = true
				}
			}
		}
		if spec.ExtendedBounds.Max != nil {
			if ms, ok := parseRuntimeDateRangeBoundMillis(spec.ExtendedBounds.Max, boundRngSpec, nowUTC); ok {
				extMax := floorDateBucket(ms)
				if !hasMaxKey || extMax > maxKey {
					maxKey = extMax
					hasMaxKey = true
				}
			} else if ms, ok := schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", spec.ExtendedBounds.Max), nowUTC, true); ok {
				extMax := floorDateBucket(ms)
				if !hasMaxKey || extMax > maxKey {
					maxKey = extMax
					hasMaxKey = true
				}
			}
		}
	}
	if hasMinKey && hasMaxKey {
		hasObserved = true
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
				hardMin = math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				hasHardMin = true
			}
		}
		if spec.HardBounds.Max != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.HardBounds.Max)); ok {
				hardMax = math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				hasHardMax = true
			}
		}
	}
	for i := range rows {
		if k, ok := parseFiniteFloat(rows[i].BucketKey); ok {
			k = math.Round(k*1e12) / 1e12
			rows[i].BucketKey = strconv.FormatFloat(k, 'f', -1, 64)
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
		if spec.MinDocCount != nil && *spec.MinDocCount > 0 {
			minCnt := int64(*spec.MinDocCount)
			filtered := make([]AggRow, 0, len(rows))
			for _, r := range rows {
				if r.effectiveCount() >= minCnt {
					filtered = append(filtered, r)
				}
			}
			return filtered
		}
		return rows
	}

	byKey := make(map[string]AggRow, len(rows))
	var minKey, maxKey float64
	hasMin, hasMax := false, false
	for _, r := range rows {
		if k, ok := parseFiniteFloat(r.BucketKey); ok {
			k = math.Round(k*1e12) / 1e12
			normKey := strconv.FormatFloat(k, 'f', -1, 64)
			r.BucketKey = normKey
			byKey[normKey] = r
			if !hasMin || k < minKey {
				minKey = k
				hasMin = true
			}
			if !hasMax || k > maxKey {
				maxKey = k
				hasMax = true
			}
		}
	}
	if spec.ExtendedBounds != nil {
		if spec.ExtendedBounds.Min != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.ExtendedBounds.Min)); ok {
				extMin := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				if !hasMin || extMin < minKey {
					minKey = extMin
					hasMin = true
				}
			}
		}
		if spec.ExtendedBounds.Max != nil {
			if f, ok := parseFiniteFloat(fmt.Sprintf("%v", spec.ExtendedBounds.Max)); ok {
				extMax := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				if !hasMax || extMax > maxKey {
					maxKey = extMax
					hasMax = true
				}
			}
		}
	}
	if hasHardMin && (!hasMin || minKey < hardMin) {
		minKey = hardMin
		hasMin = true
	}
	if hasHardMax && (!hasMax || maxKey > hardMax) {
		maxKey = hardMax
		hasMax = true
	}
	if !hasMin || !hasMax || maxKey < minKey {
		return rows
	}

	startStep := int64(math.Round((minKey - offset) / interval))
	endStep := int64(math.Round((maxKey - offset) / interval))
	var out []AggRow
	for step := startStep; step <= endStep && len(out) < transpiler.DefaultMaxAggBuckets; step++ {
		k := math.Round((float64(step)*interval+offset)*1e12) / 1e12
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

func isAllDigitsASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func buildTopHitsEnvelope(
	defaultIndex string,
	rows []AggRow,
	spec *esast.TopHitsAggSpec,
	bucketDocCount int64,
	docLookup func(string) *HitRow,
) map[string]any {
	topHitsList := buildTopHitsList(defaultIndex, rows, spec, docLookup)
	thTotal := bucketDocCount
	if int64(len(topHitsList)) > thTotal {
		thTotal = int64(len(topHitsList))
	}
	trackScores := spec.TrackScores != nil && *spec.TrackScores
	nullifyScore := len(spec.Sort) > 0 && !sortSpecsUseScore(spec.Sort) && !trackScores
	var maxScoreAny any
	if !nullifyScore && len(topHitsList) > 0 {
		var best float64
		hasScore := false
		for _, hm := range topHitsList {
			if sc, ok := toFloat64(hm["_score"]); ok {
				if !hasScore || sc > best {
					best = sc
					hasScore = true
				}
			}
		}
		if hasScore {
			maxScoreAny = best
		}
	}
	return map[string]any{
		"hits": map[string]any{
			"total":     map[string]any{"value": thTotal, "relation": "eq"},
			"max_score": maxScoreAny,
			"hits":      topHitsList,
		},
	}
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
	seenDocID := make(map[string]bool, len(rows))
	var fallbackSchema *schema.IndexSchema
	var searchQuery *esast.Query
	for _, r := range rows {
		var h *HitRow
		if docLookup != nil {
			h = docLookup(r.BucketKey)
		}
		if h != nil {
			if fallbackSchema == nil && h.Schema != nil {
				fallbackSchema = h.Schema
			}
			if searchQuery == nil && h.Query != nil {
				searchQuery = h.Query
			}
		}
		docID := r.BucketKey
		var hitIdx string
		if sep := strings.LastIndex(docID, "\x1f"); sep >= 0 {
			docID = docID[sep+1:]
		}
		if nul := strings.IndexByte(docID, '\x00'); nul >= 0 {
			hitIdx = docID[:nul]
			docID = docID[nul+1:]
		}
		if h != nil && h.Index != "" {
			hitIdx = h.Index
		}
		dedupKey := hitIdx + "\x00" + docID
		if seenDocID[dedupKey] {
			continue
		}
		seenDocID[dedupKey] = true
		candidates = append(candidates, candidate{docID: docID, hit: h})
	}
	if len(candidates) > 1 && len(spec.Sort) > 0 {
		sort.SliceStable(candidates, func(i, j int) bool {
			var ha, hb HitRow
			ha.ID = candidates[i].docID
			hb.ID = candidates[j].docID
			sa, sb := fallbackSchema, fallbackSchema
			if candidates[i].hit != nil {
				ha = *candidates[i].hit
				if ha.Schema != nil {
					sa = ha.Schema
				}
			}
			if candidates[j].hit != nil {
				hb = *candidates[j].hit
				if hb.Schema != nil {
					sb = hb.Schema
				}
			}
			if cmp := compareHitRowsBySortWithSchemas(ha, hb, spec.Sort, sa, sb); cmp != 0 {
				return cmp < 0
			}
			return ha.ID < hb.ID
		})
	} else if len(candidates) > 1 {
		sort.SliceStable(candidates, func(i, j int) bool {
			var sa, sb float64
			if candidates[i].hit != nil {
				sa = candidates[i].hit.Score
			}
			if candidates[j].hit != nil {
				sb = candidates[j].hit.Score
			}
			if sa != sb {
				return sa > sb
			}
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
	trackScores := spec.TrackScores != nil && *spec.TrackScores
	nullifyScore := len(spec.Sort) > 0 && !sortSpecsUseScore(spec.Sort) && !trackScores
	fieldSpecs := spec.EffectiveFieldSpecs()
	var syntheticReq *esast.SearchRequest
	if len(fieldSpecs) > 0 {
		syntheticReq = &esast.SearchRequest{Fields: fieldSpecs}
	}
	topHitsList := make([]map[string]any, 0, len(candidates))
	for _, c := range candidates {
		hitIdx := defaultIndex
		if c.hit != nil && c.hit.Index != "" {
			hitIdx = c.hit.Index
		}
		var scoreAny any = 1.0
		if c.hit != nil && (c.hit.Score != 0 || c.hit.Query != nil) {
			scoreAny = c.hit.Score
		}
		if nullifyScore {
			scoreAny = nil
		}
		hitMap := map[string]any{
			"_index": hitIdx,
			"_type":  "_doc",
			"_id":    c.docID,
			"_score": scoreAny,
		}
		if c.hit != nil {
			if c.hit.Routing != "" {
				hitMap["_routing"] = c.hit.Routing
			}
			cSchema := c.hit.Schema
			if cSchema == nil {
				cSchema = fallbackSchema
			}
			if (spec.Source == nil || !spec.Source.Disabled) && (!spec.HasStoredFieldsNone() || spec.Source != nil) {
				thSrc := c.hit.Source
				if len(thSrc) == 0 {
					thSrc = c.hit.EffectiveSource()
				}
				hitMap["_source"] = filterSourceJSON(thSrc, spec.Source)
			}
			if len(spec.Sort) > 0 {
				hitMap["sort"] = extractHitSortValues(*c.hit, spec.Sort, cSchema)
			}
			if syntheticReq != nil {
				if fm := extractHitFieldsMap(*c.hit, hitIdx, syntheticReq, cSchema); len(fm) > 0 {
					hitMap["fields"] = fm
				}
			}
			if len(spec.ScriptFields) > 0 {
				if sfm := evalHitScriptFields(*c.hit, spec.ScriptFields, cSchema); len(sfm) > 0 {
					fm, _ := hitMap["fields"].(map[string][]any)
					if fm == nil {
						fm = make(map[string][]any, len(sfm))
					}
					for k, v := range sfm {
						fm[k] = v
					}
					hitMap["fields"] = fm
				}
			}
			if spec.Highlight != nil && len(spec.Highlight.Fields) > 0 {
				if hl := buildHighlightMapWithSchema(c.hit.EffectiveSource(), &esast.SearchRequest{Query: searchQuery, Highlight: spec.Highlight}, cSchema); len(hl) > 0 {
					hitMap["highlight"] = hl
				}
			}
		}
		topHitsList = append(topHitsList, hitMap)
	}
	return topHitsList
}

func attachSubAggsToBucketWithSchema(
	indexName string,
	bucketMap map[string]any,
	parentFullKey string,
	parentBucketKey string,
	subAggs map[string]esast.AggSpec,
	bucketsByAgg map[string][]AggRow,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
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
					if r.Weight >= 0 {
						val = r.effectiveValue()
						found = true
					}
					break
				}
			}
			if !found && (subSpec.Avg != nil || subSpec.Min != nil || subSpec.Max != nil) {
				bucketMap[subName] = map[string]any{"value": nil}
				continue
			}
			bucketMap[subName] = map[string]any{"value": val}
		case subSpec.ScriptedMetric != nil:
			var smVal any
			foundSM := false
			for _, r := range subRows {
				if lb, rv, _, ok := parseScriptedMetricBucketKey(r.BucketKey); ok && lb == parentBucketKey {
					smVal = rv
					foundSM = true
					break
				}
			}
			if !foundSM {
				smVal, _ = evalScriptedMetricCombineAndReduce(subSpec.ScriptedMetric, nil)
			}
			bucketMap[subName] = map[string]any{"value": smVal}
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
					matchingRows = append(matchingRows, AggRow{BucketKey: pctKey, Value: 0, Weight: -1})
				}
			}
			if subSpec.Percentiles.Keyed != nil && !*subSpec.Percentiles.Keyed {
				valuesArr := make([]map[string]any, 0, len(matchingRows))
				for _, r := range matchingRows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					var valAny any
					if r.Weight >= 0 && bucketDocCount > 0 {
						valAny = r.effectiveValue()
					}
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": valAny,
					})
				}
				bucketMap[subName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]any, len(matchingRows))
				for _, r := range matchingRows {
					if r.Weight >= 0 && bucketDocCount > 0 {
						valuesMap[r.BucketKey] = r.effectiveValue()
					} else {
						valuesMap[r.BucketKey] = nil
					}
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
			hasValidBox := false
			vals := make(map[string]float64, 5)
			for _, r := range matchingRows {
				if r.Weight >= 0 {
					hasValidBox = true
				}
				vals[r.BucketKey] = r.effectiveValue()
			}
			if !hasValidBox || bucketDocCount == 0 {
				bucketMap[subName] = map[string]any{
					"min":   nil,
					"max":   nil,
					"q1":    nil,
					"q2":    nil,
					"q3":    nil,
					"lower": nil,
					"upper": nil,
				}
			} else {
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
					matchingRows = append(matchingRows, AggRow{BucketKey: valKey, Value: 0, Weight: -1})
				}
			}
			if subSpec.PercentileRanks.Keyed != nil && !*subSpec.PercentileRanks.Keyed {
				valuesArr := make([]map[string]any, 0, len(matchingRows))
				for _, r := range matchingRows {
					kFloat, _ := parseFiniteFloat(r.BucketKey)
					var valAny any
					if r.Weight >= 0 && bucketDocCount > 0 {
						valAny = r.effectiveValue()
					}
					valuesArr = append(valuesArr, map[string]any{
						"key":   kFloat,
						"value": valAny,
					})
				}
				bucketMap[subName] = map[string]any{"values": valuesArr}
			} else {
				valuesMap := make(map[string]any, len(matchingRows))
				for _, r := range matchingRows {
					if r.Weight >= 0 && bucketDocCount > 0 {
						valuesMap[r.BucketKey] = r.effectiveValue()
					} else {
						valuesMap[r.BucketKey] = nil
					}
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
			for _, statKey := range []string{"_stats_count", "_stats_min", "_stats_max", "_stats_avg", "_stats_entropy", "_sstats_count", "_sstats_min", "_sstats_max", "_sstats_avg", "_sstats_entropy"} {
				for _, r := range bucketsByAgg[subFullKey+"."+statKey] {
					if r.BucketKey == parentBucketKey {
						cp := r
						cp.BucketKey = statKey
						matchingRows = append(matchingRows, cp)
					}
				}
			}
			var cntVal int64
			var minVal, maxVal, avgVal, entropyVal float64
			for _, r := range matchingRows {
				switch r.BucketKey {
				case "_stats_count", "_sstats_count":
					cntVal = r.effectiveCount()
				case "_stats_min", "_sstats_min":
					minVal = r.effectiveValue()
				case "_stats_max", "_sstats_max":
					maxVal = r.effectiveValue()
				case "_stats_avg", "_sstats_avg":
					avgVal = r.effectiveValue()
				case "_stats_entropy", "_sstats_entropy":
					entropyVal = r.effectiveValue()
				}
			}
			if cntVal == 0 {
				bucketMap[subName] = map[string]any{
					"count":      int64(0),
					"min_length": nil,
					"max_length": nil,
					"avg_length": nil,
					"entropy":    0.0,
				}
			} else {
				bucketMap[subName] = map[string]any{
					"count":      cntVal,
					"min_length": int64(minVal),
					"max_length": int64(maxVal),
					"avg_length": avgVal,
					"entropy":    entropyVal,
				}
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
				attachSubAggsToBucketWithSchema(indexName, filterObj, subFullKey, parentBucketKey, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
				evaluateSiblingPipelineAggs(grandSubAggs, filterObj)
				_ = evaluateChildPipelineAggs([]map[string]any{filterObj}, grandSubAggs)
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
				keyStr := formatDateHistogramKeyAsString(epochMs, subSpec.DateHistogram)
				cb := map[string]any{
					"key_as_string": keyStr,
					"key":           epochMs,
					"doc_count":     r.effectiveCount(),
				}
				if len(grandSubAggs) > 0 {
					attachSubAggsToBucketWithSchema(indexName, cb, subFullKey, parentBucketKey+"\x1f"+r.BucketKey, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
					evaluateSiblingPipelineAggs(grandSubAggs, cb)
				}
				childBuckets = append(childBuckets, cb)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateChildPipelineAggsWithoutBucketSort(childBuckets, grandSubAggs)
			}
			if subSpec.DateHistogram.Order != nil && len(childBuckets) > 1 {
				childBuckets = sortHistogramBuckets(childBuckets, subSpec.DateHistogram.Order)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateBucketSortPipelineAggs(childBuckets, grandSubAggs)
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
					attachSubAggsToBucketWithSchema(indexName, cb, subFullKey, parentBucketKey+"\x1f"+r.BucketKey, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
					evaluateSiblingPipelineAggs(grandSubAggs, cb)
				}
				childBuckets = append(childBuckets, cb)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateChildPipelineAggsWithoutBucketSort(childBuckets, grandSubAggs)
			}
			if subSpec.Histogram.Order != nil && len(childBuckets) > 1 {
				childBuckets = sortHistogramBuckets(childBuckets, subSpec.Histogram.Order)
			}
			if len(grandSubAggs) > 0 {
				childBuckets = evaluateBucketSortPipelineAggs(childBuckets, grandSubAggs)
			}
			bucketMap[subName] = formatKeyedBuckets(childBuckets, subSpec.Histogram.Keyed, "key")
		case subSpec.EffectiveRange() != nil:
			rngSpec := subSpec.EffectiveRange()
			isDateRange := subSpec.DateRange != nil
			if !isDateRange && subSpec.Range != nil {
				fieldClean := strings.TrimSpace(rngSpec.Field)
				fieldIsDate := fieldClean == "@timestamp"
				if !fieldIsDate && idxSchema != nil && fieldClean != "" {
					if b, ok := idxSchema.Fields[fieldClean]; ok && (b.ESType == "date" || b.ESType == "date_nanos") {
						fieldIsDate = true
					} else if strings.HasSuffix(fieldClean, ".keyword") {
						if b, ok := idxSchema.Fields[strings.TrimSuffix(fieldClean, ".keyword")]; ok && (b.ESType == "date" || b.ESType == "date_nanos") {
							fieldIsDate = true
						}
					}
				}
				if fieldIsDate {
					if rngSpec.Format != "" {
						isDateRange = true
					} else {
						for _, r := range rngSpec.Ranges {
							if _, ok := r.From.(string); ok {
								isDateRange = true
								break
							}
							if _, ok := r.To.(string); ok {
								isDateRange = true
								break
							}
						}
					}
				}
			}
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
						if ms, ok := parseRuntimeDateRangeBoundMillis(rng.From, rngSpec, nowUTC); ok {
							entry["from"] = float64(ms)
							entry["from_as_string"] = formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{
								Format:   rngSpec.Format,
								TimeZone: rngSpec.TimeZone,
							})
						}
					} else if !isIPRange {
						if f, ok := toFloat(rng.From); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
							entry["from"] = f
						}
					}
				}
				if rng.To != nil {
					entry["to"] = rng.To
					if isDateRange {
						if ms, ok := parseRuntimeDateRangeBoundMillis(rng.To, rngSpec, nowUTC); ok {
							entry["to"] = float64(ms)
							entry["to_as_string"] = formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{
								Format:   rngSpec.Format,
								TimeZone: rngSpec.TimeZone,
							})
						}
					} else if !isIPRange {
						if f, ok := toFloat(rng.To); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
							entry["to"] = f
						}
					}
				}
				if isDateRange && rng.Key == "" {
					fromStr, _ := entry["from_as_string"].(string)
					if fromStr == "" {
						fromStr = "*"
					}
					toStr, _ := entry["to_as_string"].(string)
					if toStr == "" {
						toStr = "*"
					}
					entry["key"] = fromStr + "-" + toStr
				}
				if len(grandSubAggs) > 0 {
					attachSubAggsToBucketWithSchema(indexName, entry, subFullKey, parentBucketKey+"\x1f"+ek, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
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
						attachSubAggsToBucketWithSchema(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+fk, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					ordered = append(ordered, bMap)
				}
				if subSpec.Filters.OtherBucket {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{"doc_count": byKey[otherKey]}
					if len(grandSubAggs) > 0 {
						attachSubAggsToBucketWithSchema(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+otherKey, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
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
						attachSubAggsToBucketWithSchema(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+fk, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					bucketsMap[fk] = bMap
				}
				if subSpec.Filters.OtherBucket {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					bMap := map[string]any{"doc_count": byKey[otherKey]}
					if len(grandSubAggs) > 0 {
						attachSubAggsToBucketWithSchema(indexName, bMap, subFullKey, parentBucketKey+"\x1f"+otherKey, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
						evaluateSiblingPipelineAggs(grandSubAggs, bMap)
					}
					bucketsMap[otherKey] = bMap
				}
				if len(grandSubAggs) > 0 {
					keys := sortedFilterBucketKeys(subSpec.Filters, bucketsMap)
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
					keys := sortedFilterBucketKeys(subSpec.Filters, bucketsMap)
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
			grandSubAggs := subSpec.SubAggs()
			var sumOtherDocCount int64
			matchingRows, sumOtherDocCount = filterAndSortTermsRowsWithSubAggs(matchingRows, tSpec, subFullKey, parentBucketKey, bucketsByAgg, grandSubAggs, indexName, docLookup, idxSchema)
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
			for _, r := range matchingRows {
				docCnt := r.effectiveCount()
				keyVal, keyAsStr, hasKeyAsStr := formatTermsBucketKeyAndString(r.BucketKey, tSpec, idxSchema)
				cb := map[string]any{
					"key":       keyVal,
					"doc_count": docCnt,
				}
				if hasKeyAsStr {
					cb["key_as_string"] = keyAsStr
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
					attachSubAggsToBucketWithSchema(indexName, cb, subFullKey, parentBucketKey+"\x1f"+r.BucketKey, grandSubAggs, bucketsByAgg, docLookup, idxSchema)
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
					"sum_other_doc_count":         sumOtherDocCount,
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
			bucketMap[subName] = buildTopHitsEnvelope(indexName, matchingRows, subSpec.TopHits, bucketDocCount, docLookup)
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
		case subSpec.Composite != nil:
			var matchingRows []AggRow
			for _, r := range subRows {
				if childKey, ok := trimSubAggBucketPrefix(r.BucketKey, parentBucketKey); ok {
					cp := r
					cp.BucketKey = childKey
					matchingRows = append(matchingRows, cp)
				}
			}
			bucketMap[subName] = buildCompositeAggObjectWithSchema(indexName, subFullKey, parentBucketKey, subSpec.Composite, subSpec.SubAggs(), matchingRows, bucketsByAgg, docLookup, idxSchema)
		case subSpec.RareTerms != nil || subSpec.MultiTerms != nil || subSpec.AutoDateHistogram != nil || subSpec.VariableWidthHistogram != nil ||
			subSpec.GeoDistance != nil || subSpec.GeohashGrid != nil || subSpec.GeotileGrid != nil || subSpec.AdjacencyMatrix != nil:
			bucketMap[subName] = formatRuntimeBucketAggObjectWithSchema(indexName, subFullKey, parentBucketKey, subSpec, subRows, bucketsByAgg, docLookup, idxSchema)
		case subSpec.WeightedAvg != nil || subSpec.MedianAbsoluteDeviation != nil || subSpec.GeoBounds != nil ||
			subSpec.GeoCentroid != nil || subSpec.MatrixStats != nil || subSpec.TTest != nil:
			bucketMap[subName] = formatRuntimeJSONMetricAggObject(parentBucketKey, subSpec, subRows)
		}
	}
}

func extractHitFieldsMap(h HitRow, hitIdx string, req *esast.SearchRequest, idxSchema *schema.IndexSchema) map[string][]any {
	specs := req.EffectiveFieldSpecs()
	if len(specs) == 0 {
		return nil
	}
	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
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
		case "_routing":
			if h.Routing != "" {
				out["_routing"] = []any{h.Routing}
			}
			continue
		case "_version":
			if h.Version > 0 {
				out["_version"] = []any{h.Version}
			} else {
				out["_version"] = []any{int64(1)}
			}
			continue
		case "_seq_no":
			if h.Version > 0 {
				out["_seq_no"] = []any{h.Version}
			} else {
				out["_seq_no"] = []any{int64(1)}
			}
			continue
		case "_primary_term":
			out["_primary_term"] = []any{int64(1)}
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
			if idxSchema != nil {
				hasExplicitDot := strings.Contains(cleanField, ".")
				for fieldName, fb := range idxSchema.Fields {
					if !hasExplicitDot && (strings.HasSuffix(fieldName, ".keyword") || strings.HasSuffix(fieldName, ".ngram")) {
						continue
					}
					if _, already := out[fieldName]; already {
						continue
					}
					if !matchWildcardPattern(cleanField, fieldName) {
						continue
					}
					pathSegs := strings.Split(strings.TrimSuffix(strings.TrimSuffix(fieldName, ".keyword"), ".ngram"), ".")
					if len(fb.SourceJSONPath) > 0 {
						pathSegs = fb.SourceJSONPath
					}
					vals := collectSchemaAwareScalarValues(doc, fieldName, pathSegs, idxSchema)
					if len(vals) > 0 {
						out[fieldName] = formatFieldValues(fieldName, vals, spec.Format, idxSchema)
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
		vals := collectSchemaAwareScalarValues(doc, spec.Field, pathSegs, idxSchema)
		if len(vals) > 0 {
			out[spec.Field] = formatFieldValues(spec.Field, vals, spec.Format, idxSchema)
		}
	}
	return out
}

func formatFieldValues(field string, vals []any, format string, idxSchema *schema.IndexSchema) []any {
	cleanField := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	isDateField := cleanField == "@timestamp"
	isBoolField := false
	var mappedFormat string
	if idxSchema != nil {
		b := idxSchema.ResolveField(field)
		if b.ESType == "date" || b.ESType == "date_nanos" {
			isDateField = true
			mappedFormat = b.Format
		}
		if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
			isBoolField = true
		}
	}
	effFormat := format
	if effFormat == "" && mappedFormat != "" {
		effFormat = strings.TrimSpace(strings.Split(mappedFormat, "||")[0])
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
			if isBoolField {
				switch strings.ToLower(strings.TrimSpace(typed)) {
				case "true", "1":
					v = true
				case "false", "0":
					v = false
				}
			} else if strings.EqualFold(effFormat, "epoch_millis") {
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(typed, mappedFormat, time.Now().UTC()); ok {
					v = ms
				}
			} else if strings.EqualFold(effFormat, "epoch_second") {
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(typed, mappedFormat, time.Now().UTC()); ok {
					v = int64(math.Floor(float64(ms) / 1000.0))
				}
			} else if isDateField && effFormat != "" {
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(typed, mappedFormat, time.Now().UTC()); ok {
					v = formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{Format: effFormat})
				}
			} else if idxSchema != nil {
				b := idxSchema.ResolveField(field)
				if b.EffectiveLowercase(strings.HasSuffix(field, ".keyword")) {
					v = strings.ToLower(typed)
				}
			}
		case int64:
			if isBoolField {
				switch typed {
				case 1:
					v = true
				case 0:
					v = false
				}
			} else if isDateField {
				if strings.EqualFold(effFormat, "epoch_millis") {
					v = typed
				} else if strings.EqualFold(effFormat, "epoch_second") {
					v = int64(math.Floor(float64(typed) / 1000.0))
				} else {
					v = formatDateHistogramKeyAsString(typed, &esast.DateHistogramAggSpec{Format: effFormat})
				}
			}
		case float64:
			if isBoolField {
				switch typed {
				case 1:
					v = true
				case 0:
					v = false
				}
			} else if isDateField {
				ms := int64(typed)
				if strings.EqualFold(effFormat, "epoch_millis") {
					v = ms
				} else if strings.EqualFold(effFormat, "epoch_second") {
					v = int64(math.Floor(float64(ms) / 1000.0))
				} else {
					v = formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{Format: effFormat})
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
	return collectScalarValuesAtPathWithNull(node, path, nil)
}

func collectScalarValuesAtPathWithNull(node any, path []string, nullValue any) []any {
	if node == nil {
		if len(path) == 0 && nullValue != nil {
			return []any{nullValue}
		}
		return nil
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case map[string]any:
			return nil
		case []any:
			var res []any
			for _, item := range v {
				res = append(res, collectScalarValuesAtPathWithNull(item, nil, nullValue)...)
			}
			return res
		default:
			return []any{v}
		}
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, exists := curr[path[0]]; exists {
			return collectScalarValuesAtPathWithNull(next, path[1:], nullValue)
		}
		if len(path) > 1 {
			if flat, exists := curr[strings.Join(path, ".")]; exists {
				return collectScalarValuesAtPathWithNull(flat, nil, nullValue)
			}
		}
		return nil
	case []any:
		var res []any
		for _, item := range curr {
			res = append(res, collectScalarValuesAtPathWithNull(item, path, nullValue)...)
		}
		return res
	}
	return nil
}

func collectSchemaAwareScalarValues(doc map[string]any, field string, pathSegs []string, idxSchema *schema.IndexSchema) []any {
	var nullVal any
	cleanTarget := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	if idxSchema != nil {
		b := idxSchema.ResolveField(field)
		nullVal = b.NullValue
		if b.AliasTarget != "" {
			cleanTarget = strings.TrimSuffix(strings.TrimSuffix(b.AliasTarget, ".keyword"), ".ngram")
		} else if len(b.SourceJSONPath) > 0 {
			cleanTarget = strings.Join(b.SourceJSONPath, ".")
		}
	}
	vals := collectScalarValuesAtPathWithNull(doc, pathSegs, nullVal)
	if len(vals) == 0 && idxSchema != nil && idxSchema.RawMapping != nil {
		visited := map[string]bool{cleanTarget: true}
		frontier := []string{cleanTarget}
		for hop := 0; hop < 4 && len(frontier) > 0; hop++ {
			var nextFrontier []string
			for _, target := range frontier {
				for _, srcPath := range collectCopyToSourcePaths(idxSchema.RawMapping.Properties, "", target) {
					var srcNull any
					if sb, ok := idxSchema.Fields[srcPath]; ok {
						srcNull = sb.NullValue
					}
					srcVals := collectScalarValuesAtPathWithNull(doc, strings.Split(srcPath, "."), srcNull)
					if len(srcVals) > 0 {
						vals = append(vals, srcVals...)
					}
					if !visited[srcPath] {
						visited[srcPath] = true
						nextFrontier = append(nextFrontier, srcPath)
					}
				}
			}
			frontier = nextFrontier
		}
	}
	if idxSchema != nil && len(vals) > 0 {
		if b := idxSchema.ResolveField(field); b.IgnoreAbove > 0 {
			filtered := make([]any, 0, len(vals))
			for _, v := range vals {
				if s, ok := v.(string); ok && utf8.RuneCountInString(s) > b.IgnoreAbove {
					continue
				}
				filtered = append(filtered, v)
			}
			vals = filtered
		}
	}
	return vals
}

func deepCloneAnySlice(s []any) []any {
	if s == nil {
		return nil
	}
	cp := make([]any, len(s))
	for i, elem := range s {
		switch tv := elem.(type) {
		case map[string]any:
			cp[i] = deepCloneDocMap(tv)
		case []any:
			cp[i] = deepCloneAnySlice(tv)
		default:
			cp[i] = elem
		}
	}
	return cp
}

func deepCloneDocMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		switch sub := v.(type) {
		case map[string]any:
			cp[k] = deepCloneDocMap(sub)
		case []any:
			cp[k] = deepCloneAnySlice(sub)
		default:
			cp[k] = v
		}
	}
	return cp
}

func filterIgnoreAboveInPlace(curr any, segs []string, ignoreAbove int) {
	if curr == nil || len(segs) == 0 || ignoreAbove <= 0 {
		return
	}
	switch node := curr.(type) {
	case map[string]any:
		if len(segs) == 1 {
			k := segs[0]
			val, exists := node[k]
			if !exists {
				return
			}
			switch tv := val.(type) {
			case string:
				if utf8.RuneCountInString(tv) > ignoreAbove {
					node[k] = nil
				}
			case []any:
				filtered := make([]any, 0, len(tv))
				for _, item := range tv {
					if s, ok := item.(string); ok && utf8.RuneCountInString(s) > ignoreAbove {
						continue
					}
					filtered = append(filtered, item)
				}
				switch len(filtered) {
				case 0:
					node[k] = nil
				case 1:
					node[k] = filtered[0]
				default:
					node[k] = filtered
				}
			}
			return
		}
		if len(segs) > 1 {
			if next, exists := node[segs[0]]; exists {
				filterIgnoreAboveInPlace(next, segs[1:], ignoreAbove)
			}
		}
		if flatKey := strings.Join(segs, "."); node[flatKey] != nil {
			filterIgnoreAboveInPlace(node, []string{flatKey}, ignoreAbove)
		}
	case []any:
		for _, elem := range node {
			filterIgnoreAboveInPlace(elem, segs, ignoreAbove)
		}
	}
}

func setRuntimeScriptDocPath(curr map[string]any, segs []string, val any) {
	if curr == nil || len(segs) == 0 {
		return
	}
	if len(segs) == 1 {
		curr[segs[0]] = val
		return
	}
	head := segs[0]
	rest := segs[1:]
	switch next := curr[head].(type) {
	case map[string]any:
		setRuntimeScriptDocPath(next, rest, val)
	case []any:
		wroteToElem := false
		for _, elem := range next {
			if em, ok := elem.(map[string]any); ok {
				setRuntimeScriptDocPath(em, rest, val)
				wroteToElem = true
			}
		}
		if !wroteToElem {
			child := make(map[string]any)
			setRuntimeScriptDocPath(child, rest, val)
			curr[head] = child
		}
	default:
		child := make(map[string]any)
		setRuntimeScriptDocPath(child, rest, val)
		curr[head] = child
	}
}

func prepareDocForRuntimeScript(idxSchema *schema.IndexSchema, doc map[string]any) map[string]any {
	var cp map[string]any
	ensureCopy := func() {
		if cp == nil {
			cp = deepCloneDocMap(doc)
			if cp == nil {
				cp = make(map[string]any)
			}
		}
	}
	if doc != nil {
		if doc["__meta_index"] == nil && idxSchema != nil && idxSchema.IndexName != "" && idxSchema.IndexName != "eval_idx" {
			ensureCopy()
			cp["__meta_index"] = idxSchema.IndexName
		}
		if doc["__meta_version"] == nil {
			ensureCopy()
			cp["__meta_version"] = int64(1)
		}
	}
	if idxSchema == nil || len(idxSchema.Fields) == 0 {
		if cp != nil {
			return cp
		}
		return doc
	}
	for fieldName, fb := range idxSchema.Fields {
		cleanField := strings.TrimSuffix(strings.TrimSuffix(fieldName, ".keyword"), ".ngram")
		if cleanField == "" {
			continue
		}
		rawSegs := strings.Split(cleanField, ".")
		rawVals := collectScalarValuesAtPath(doc, rawSegs)
		if len(rawVals) > 0 {
			if fb.IgnoreAbove > 0 {
				exceeded := false
				for _, rv := range rawVals {
					if s, ok := rv.(string); ok && utf8.RuneCountInString(s) > fb.IgnoreAbove {
						exceeded = true
						break
					}
				}
				if exceeded {
					ensureCopy()
					filterIgnoreAboveInPlace(cp, rawSegs, fb.IgnoreAbove)
				}
			}
			continue
		}
		pathSegs := rawSegs
		if len(fb.SourceJSONPath) > 0 {
			pathSegs = fb.SourceJSONPath
		}
		vals := collectSchemaAwareScalarValues(doc, fieldName, pathSegs, idxSchema)
		if len(vals) == 0 {
			continue
		}
		ensureCopy()
		if len(vals) == 1 {
			setRuntimeScriptDocPath(cp, rawSegs, vals[0])
		} else {
			setRuntimeScriptDocPath(cp, rawSegs, vals)
		}
	}
	if cp != nil {
		return cp
	}
	return doc
}

func extractHitSortValues(h HitRow, sorts []esast.SortSpec, idxSchema *schema.IndexSchema) []any {
	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	if doc == nil {
		doc = make(map[string]any)
	}
	if h.ID != "" {
		doc["__meta_id"] = h.ID
	}
	if h.Index != "" {
		doc["__meta_index"] = h.Index
	}
	if h.Version > 0 {
		doc["__meta_version"] = h.Version
	} else {
		doc["__meta_version"] = int64(1)
	}
	if idxSchema == nil && h.Schema != nil {
		idxSchema = h.Schema
	}
	out := make([]any, 0, len(sorts))
	for _, s := range sorts {
		switch s.Entry.Field {
		case "_score":
			out = append(out, h.Score)
		case "_id", "_doc":
			out = append(out, h.ID)
		case "_script":
			var val any
			srcStr, params := extractScriptSourceAndParams(s.Entry.Script)
			if srcStr != "" {
				evalSingleScriptDoc := func(d map[string]any) (any, bool) {
					evalDoc := prepareDocForRuntimeScript(idxSchema, d)
					if _, isMissing := scriptHasMissingDocValueRef(evalDoc, srcStr); isMissing {
						return nil, false
					}
					cp := make(map[string]any, len(params)+1)
					for k, v := range params {
						cp[k] = v
					}
					cp["_score"] = h.Score
					v, err := painless.Eval(evalDoc, srcStr, cp)
					if err != nil || v == nil {
						return nil, false
					}
					if arr, ok := v.([]any); ok {
						v = reduceSortFieldValues(arr, s.Entry.Mode, s.Entry.Order)
					}
					if !strings.EqualFold(s.Entry.Type, "string") {
						if fv, ok := toFloat64(v); ok {
							return fv, true
						}
					}
					return v, true
				}
				if s.Entry.Nested != nil {
					nestedPath := deepestNestedSortPathLocal(s.Entry.Nested)
					if nestedPath != "" {
						nestedSegs := strings.Split(nestedPath, ".")
						nestedEvalSchema := deriveNestedEvalSchema(idxSchema, nestedPath)
						var elemVals []any
						for _, cand := range extractNestedElementsAtPath(doc, nestedSegs) {
							elemDoc := buildSingleNestedElementDoc(nestedSegs, cand.obj)
							if s.Entry.Nested.Filter != nil && !evalBranchMatchesDoc(nestedEvalSchema, elemDoc, s.Entry.Nested.Filter) {
								continue
							}
							if ev, ok := evalSingleScriptDoc(elemDoc); ok && ev != nil {
								elemVals = append(elemVals, ev)
							}
						}
						if len(elemVals) == 1 {
							val = elemVals[0]
						} else if len(elemVals) > 1 {
							val = reduceSortFieldValues(elemVals, s.Entry.Mode, s.Entry.Order)
						}
					} else if ev, ok := evalSingleScriptDoc(doc); ok {
						val = ev
					}
				} else if ev, ok := evalSingleScriptDoc(doc); ok {
					val = ev
				}
			}
			if val == nil && s.Entry.Missing != "" && !strings.EqualFold(s.Entry.Missing, "_last") && !strings.EqualFold(s.Entry.Missing, "_first") {
				if !strings.EqualFold(s.Entry.Type, "string") {
					if fv, err := strconv.ParseFloat(s.Entry.Missing, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						val = fv
					} else {
						val = s.Entry.Missing
					}
				} else {
					val = s.Entry.Missing
				}
			}
			out = append(out, val)
		case "_geo_distance":
			out = append(out, evalGeoDistanceSortValue(prepareDocForRuntimeScript(idxSchema, doc), s))
		default:
			resolvedSortField := resolveSortEntryField(s, idxSchema)
			cleanField := strings.TrimSuffix(strings.TrimSuffix(resolvedSortField, ".keyword"), ".ngram")
			pathSegs := strings.Split(cleanField, ".")
			if idxSchema != nil {
				b := idxSchema.ResolveField(resolvedSortField)
				if len(b.SourceJSONPath) > 0 {
					pathSegs = b.SourceJSONPath
				}
			}
			var rawVals []any
			if s.Entry.Nested != nil && s.Entry.Nested.Filter != nil {
				nestedPath := deepestNestedSortPathLocal(s.Entry.Nested)
				if nestedPath == "" && idxSchema != nil {
					nestedPath = idxSchema.ResolveField(resolvedSortField).NestedPath
				}
				if nestedPath != "" && strings.HasPrefix(cleanField, nestedPath+".") {
					nestedSegs := strings.Split(nestedPath, ".")
					relSegs := strings.Split(strings.TrimPrefix(cleanField, nestedPath+"."), ".")
					nestedEvalSchema := deriveNestedEvalSchema(idxSchema, nestedPath)
					for _, cand := range extractNestedElementsAtPath(doc, nestedSegs) {
						elemDoc := buildSingleNestedElementDoc(nestedSegs, cand.obj)
						if evalBranchMatchesDoc(nestedEvalSchema, elemDoc, s.Entry.Nested.Filter) {
							rawVals = append(rawVals, collectScalarValuesAtPath(cand.obj, relSegs)...)
						}
					}
				} else {
					rawVals = collectSchemaAwareScalarValues(doc, resolvedSortField, pathSegs, idxSchema)
				}
			} else {
				rawVals = collectSchemaAwareScalarValues(doc, resolvedSortField, pathSegs, idxSchema)
			}
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
					b := idxSchema.ResolveField(resolvedSortField)
					if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
						switch tv := v.(type) {
						case string:
							switch strings.ToLower(strings.TrimSpace(tv)) {
							case "true", "1":
								v = true
							case "false", "0":
								v = false
							}
						case int64:
							v = tv != 0
						case float64:
							v = tv != 0
						}
					} else if strVal, ok := v.(string); ok {
						if b.EffectiveLowercase(true) {
							v = strings.ToLower(strVal)
						} else if b.ESType == "date" || b.ESType == "date_nanos" || b.DorisType == schema.DorisBigInt {
							if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
								v = ms
							} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
								v = iv
							}
						} else if b.DorisType == schema.DorisDouble || b.ESType == "double" || b.ESType == "float" || b.ESType == "half_float" || b.ESType == "scaled_float" || strings.EqualFold(s.Entry.Type, "double") || strings.EqualFold(s.Entry.Type, "float") {
							if fv, ok := parseFiniteFloat(strings.TrimSpace(strVal)); ok {
								v = fv
							}
						}
					}
					if b.ESType == "date_nanos" {
						if iv, ok := v.(int64); ok && iv > 1_000_000_000_000_000 {
							v = iv / 1_000_000
						} else if fv, ok := v.(float64); ok && fv > 1_000_000_000_000_000 {
							v = int64(fv) / 1_000_000
						}
					}
				}
				normVals = append(normVals, v)
			}
			var val any
			if len(normVals) == 1 {
				val = normVals[0]
			} else if len(normVals) > 1 {
				if s.Entry.Mode == "" && s.Entry.Order == "" {
					val = normVals[0]
				} else {
					val = reduceSortFieldValues(normVals, s.Entry.Mode, s.Entry.Order)
				}
			} else if s.Entry.Missing != "" {
				mStr := s.Entry.Missing
				if !strings.EqualFold(mStr, "_last") && !strings.EqualFold(mStr, "_first") {
					if strings.EqualFold(s.Entry.Type, "boolean") {
						switch strings.ToLower(strings.TrimSpace(mStr)) {
						case "true", "1":
							val = true
						case "false", "0":
							val = false
						}
					}
					if idxSchema != nil && val == nil {
						b := idxSchema.ResolveField(resolvedSortField)
						if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
							switch strings.ToLower(strings.TrimSpace(mStr)) {
							case "true", "1":
								val = true
							case "false", "0":
								val = false
							}
						} else if b.ESType == "date" || b.ESType == "date_nanos" || b.DorisType == schema.DorisBigInt {
							if ms, ok := schema.ParseESDateToEpochMillis(mStr, time.Now().UTC()); ok {
								val = ms
							}
						}
					}
					if val == nil {
						if iv, err := strconv.ParseInt(mStr, 10, 64); err == nil {
							val = iv
						} else if fv, err := strconv.ParseFloat(mStr, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
							val = fv
						} else {
							if idxSchema != nil {
								b := idxSchema.ResolveField(resolvedSortField)
								if b.EffectiveLowercase(true) {
									mStr = strings.ToLower(mStr)
								}
							}
							val = mStr
						}
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
		switch effMode {
		case "max":
			return strs[len(strs)-1]
		case "median":
			return strs[len(strs)/2]
		case "avg":
			var sum float64
			for _, s := range strs {
				ip, _ := parseIPv4SortUint32(s)
				sum += float64(ip)
			}
			return sum / float64(len(strs))
		case "sum":
			var sum int64
			for _, s := range strs {
				ip, _ := parseIPv4SortUint32(s)
				sum += int64(ip)
			}
			return sum
		default:
			return strs[0]
		}
	}
	sort.Strings(strs)
	if effMode == "max" {
		return strs[len(strs)-1]
	}
	if effMode == "median" {
		return strs[len(strs)/2]
	}
	return strs[0]
}

func filterSourceJSON(raw json.RawMessage, sf *esast.SourceFilter) json.RawMessage {
	if sf == nil {
		return raw
	}
	if sf.Disabled {
		return nil
	}
	if len(sf.Includes) == 0 && len(sf.Excludes) == 0 {
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

func formatDateHistogramKeyAsString(epochMs int64, spec *esast.DateHistogramAggSpec) string {
	var tzOffsetMs int64
	var formatStr string
	if spec != nil {
		tzOffsetMs = spec.EffectiveTimeZoneOffsetMs()
		formatStr = strings.TrimSpace(spec.Format)
		if idx := strings.Index(formatStr, "||"); idx > 0 {
			formatStr = strings.TrimSpace(formatStr[:idx])
		}
	}
	loc := time.UTC
	if tzOffsetMs != 0 {
		loc = time.FixedZone("ES_TZ", int(tzOffsetMs/1000))
	}
	t := time.UnixMilli(epochMs).In(loc)
	switch strings.ToLower(formatStr) {
	case "":
		if tzOffsetMs != 0 {
			return t.Format("2006-01-02T15:04:05.000-07:00")
		}
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	case "epoch_millis":
		return strconv.FormatInt(epochMs, 10)
	case "epoch_second":
		return strconv.FormatInt(int64(math.Floor(float64(epochMs)/1000.0)), 10)
	case "strict_date_optional_time", "date_optional_time", "date_time":
		if tzOffsetMs != 0 {
			return t.Format("2006-01-02T15:04:05.000-07:00")
		}
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	case "strict_date", "date", "year_month_day":
		return t.Format("2006-01-02")
	default:
		goFmt := strings.ReplaceAll(formatStr, "''", "\x00")
		goFmt = strings.ReplaceAll(goFmt, "'T'", "T")
		goFmt = strings.ReplaceAll(goFmt, "'Z'", "\x01")
		replacements := []struct{ from, to string }{
			{"yyyy", "2006"},
			{"YYYY", "2006"},
			{"uuuu", "2006"},
			{"yy", "06"},
			{"YY", "06"},
			{"MM", "01"},
			{"dd", "02"},
			{"HH", "15"},
			{"mm", "04"},
			{"ss", "05"},
			{"SSS", "000"},
			{"XXX", "-07:00"},
			{"Z", "-0700"},
		}
		for _, r := range replacements {
			goFmt = strings.ReplaceAll(goFmt, r.from, r.to)
		}
		goFmt = strings.ReplaceAll(goFmt, "\x01", "Z")
		goFmt = strings.ReplaceAll(goFmt, "'", "")
		goFmt = strings.ReplaceAll(goFmt, "\x00", "'")
		return t.Format(goFmt)
	}
}

func sortedOrderMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ki, kj := strings.TrimSpace(keys[i]), strings.TrimSpace(keys[j])
		pi := ki != "_key" && ki != "_term" && ki != "key"
		pj := kj != "_key" && kj != "_term" && kj != "key"
		if pi != pj {
			return pi
		}
		return ki < kj
	})
	return keys
}

func sortHistogramBuckets(buckets []map[string]any, order any) []map[string]any {
	type histSortSpec struct {
		target string
		desc   bool
	}
	var specs []histSortSpec
	parseMap := func(m map[string]any) {
		for _, k := range sortedOrderMapKeys(m) {
			v := m[k]
			if dir := extractCompositeSourceOrder(v); dir != "" {
				specs = append(specs, histSortSpec{
					target: strings.TrimSpace(k),
					desc:   strings.EqualFold(strings.TrimSpace(dir), "desc"),
				})
			}
		}
	}
	switch ov := order.(type) {
	case map[string]any:
		parseMap(ov)
	case []any:
		for _, item := range ov {
			if m, ok := item.(map[string]any); ok {
				parseMap(m)
			}
		}
	}
	if len(specs) == 0 || len(buckets) <= 1 {
		return buckets
	}
	sort.SliceStable(buckets, func(i, j int) bool {
		for _, sp := range specs {
			var vi, vj float64
			var okI, okJ bool
			switch sp.target {
			case "_key", "_term", "key":
				vi, okI = toFloat64(buckets[i]["key"])
				vj, okJ = toFloat64(buckets[j]["key"])
			case "_count", "doc_count":
				vi, okI = toFloat64(buckets[i]["doc_count"])
				vj, okJ = toFloat64(buckets[j]["doc_count"])
			default:
				vi, okI = extractBucketMetricByPath(buckets[i], sp.target)
				vj, okJ = extractBucketMetricByPath(buckets[j], sp.target)
			}
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
				if sp.desc {
					return vi > vj
				}
				return vi < vj
			}
		}
		ki, _ := toFloat64(buckets[i]["key"])
		kj, _ := toFloat64(buckets[j]["key"])
		return ki < kj
	})
	return buckets
}

func buildHighlightMapWithSchema(raw json.RawMessage, req *esast.SearchRequest, hitSchema *schema.IndexSchema) map[string][]string {
	if req == nil || req.Highlight == nil || len(req.Highlight.Fields) == 0 {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make(map[string][]string)
	var allLeafPaths map[string][]string
	fieldNames := make([]string, 0, len(req.Highlight.Fields))
	for field := range req.Highlight.Fields {
		fieldNames = append(fieldNames, field)
	}
	sort.Slice(fieldNames, func(i, j int) bool {
		wi := strings.Contains(fieldNames[i], "*")
		wj := strings.Contains(fieldNames[j], "*")
		if wi != wj {
			return !wi
		}
		return fieldNames[i] < fieldNames[j]
	})
	for _, field := range fieldNames {
		fSpec := req.Highlight.FieldSpec(field)
		effTagSchema := req.Highlight.TagSchema
		if fSpec.TagSchema != "" {
			effTagSchema = fSpec.TagSchema
		}
		preTag := "<em>"
		postTag := "</em>"
		if strings.EqualFold(effTagSchema, "styled") {
			preTag = `<em class="hlt1">`
			postTag = "</em>"
		}
		if len(req.Highlight.PreTags) > 0 && req.Highlight.PreTags[0] != "" {
			preTag = req.Highlight.PreTags[0]
		}
		if len(req.Highlight.PostTags) > 0 && req.Highlight.PostTags[0] != "" {
			postTag = req.Highlight.PostTags[0]
		}
		if len(fSpec.PreTags) > 0 && fSpec.PreTags[0] != "" {
			preTag = fSpec.PreTags[0]
		}
		if len(fSpec.PostTags) > 0 && fSpec.PostTags[0] != "" {
			postTag = fSpec.PostTags[0]
		}
		effEncoder := req.Highlight.Encoder
		if fSpec.Encoder != "" {
			effEncoder = fSpec.Encoder
		}
		htmlEscape := strings.EqualFold(effEncoder, "html")

		effQuery := req.Query
		if req.Highlight.HighlightQuery != nil {
			effQuery = req.Highlight.HighlightQuery
		}
		if fSpec.HighlightQuery != nil {
			effQuery = fSpec.HighlightQuery
		}

		requireFieldMatch := true
		if req.Highlight.RequireFieldMatch != nil {
			requireFieldMatch = *req.Highlight.RequireFieldMatch
		}
		if fSpec.RequireFieldMatch != nil {
			requireFieldMatch = *fSpec.RequireFieldMatch
		}
		if fSpec.HighlightQuery != nil && fSpec.RequireFieldMatch == nil && req.Highlight.RequireFieldMatch == nil {
			requireFieldMatch = false
		}

		effFragSize := 0
		if req.Highlight.FragmentSize != nil {
			effFragSize = *req.Highlight.FragmentSize
		}
		if fSpec.FragmentSize != nil {
			effFragSize = *fSpec.FragmentSize
		}
		effNumFrags := -1
		if req.Highlight.NumberOfFragments != nil {
			effNumFrags = *req.Highlight.NumberOfFragments
		}
		if fSpec.NumberOfFragments != nil {
			effNumFrags = *fSpec.NumberOfFragments
		}
		if effNumFrags > 0 && effFragSize <= 0 {
			effFragSize = 100
		}
		effNoMatchSize := 0
		if req.Highlight.NoMatchSize != nil {
			effNoMatchSize = *req.Highlight.NoMatchSize
		}
		if fSpec.NoMatchSize != nil {
			effNoMatchSize = *fSpec.NoMatchSize
		}

		cleanField := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
		if strings.Contains(cleanField, "*") {
			if allLeafPaths == nil {
				allLeafPaths = make(map[string][]string)
				collectAllLeafStringPaths(doc, "", allLeafPaths)
			}
			for leafPath, vals := range allLeafPaths {
				if _, alreadyExplicit := out[leafPath]; alreadyExplicit {
					continue
				}
				if matchWildcardPattern(cleanField, leafPath) {
					targetFields := []string{leafPath}
					if len(fSpec.MatchedFields) > 0 {
						targetFields = append(targetFields, fSpec.MatchedFields...)
					}
					re := compileHighlightRegexForFields(effQuery, targetFields, requireFieldMatch, hitSchema)
					frags := buildHighlightedFieldSnippets(vals, re, preTag, postTag, htmlEscape, effFragSize, effNumFrags, effNoMatchSize)
					if len(frags) > 0 {
						out[leafPath] = frags
					}
				}
			}
			continue
		}

		targetFields := []string{field}
		if len(fSpec.MatchedFields) > 0 {
			targetFields = append(targetFields, fSpec.MatchedFields...)
		}
		re := compileHighlightRegexForFields(effQuery, targetFields, requireFieldMatch, hitSchema)
		vals := collectHighlightFieldStrings(doc, field, hitSchema)
		frags := buildHighlightedFieldSnippets(vals, re, preTag, postTag, htmlEscape, effFragSize, effNumFrags, effNoMatchSize)
		if len(frags) > 0 {
			out[field] = frags
		}
	}
	return out
}

func collectHighlightFieldStrings(doc map[string]any, field string, hitSchema *schema.IndexSchema) []string {
	cleanField := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	pathSegs := strings.Split(cleanField, ".")
	if hitSchema != nil {
		b := hitSchema.ResolveField(field)
		if len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
			cleanField = strings.Join(b.SourceJSONPath, ".")
		} else if b.AliasTarget != "" {
			cleanField = strings.TrimSuffix(strings.TrimSuffix(b.AliasTarget, ".keyword"), ".ngram")
			pathSegs = strings.Split(cleanField, ".")
		}
	}
	vals := collectStringValuesAtPath(doc, pathSegs)
	if len(vals) == 0 && hitSchema != nil && hitSchema.RawMapping != nil {
		visited := map[string]bool{cleanField: true}
		frontier := []string{cleanField}
		for hop := 0; hop < 4 && len(frontier) > 0; hop++ {
			var nextFrontier []string
			for _, target := range frontier {
				targetsToCheck := []string{target}
				for fn, fb := range hitSchema.Fields {
					if fb.AliasTarget == target || strings.TrimSuffix(fb.AliasTarget, ".keyword") == target {
						targetsToCheck = append(targetsToCheck, fn)
					}
				}
				for _, t := range targetsToCheck {
					for _, srcPath := range collectCopyToSourcePaths(hitSchema.RawMapping.Properties, "", t) {
						vals = append(vals, collectStringValuesAtPath(doc, strings.Split(srcPath, "."))...)
						if !visited[srcPath] {
							visited[srcPath] = true
							nextFrontier = append(nextFrontier, srcPath)
						}
					}
				}
			}
			frontier = nextFrontier
		}
	}
	return vals
}

func collectCopyToSourcePaths(props map[string]esast.FieldProperty, prefix, target string) []string {
	var out []string
	for name, prop := range props {
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		for _, ct := range prop.CopyToSlice() {
			if ct == target || strings.TrimSuffix(ct, ".keyword") == target {
				out = append(out, full)
			}
		}
		if len(prop.Properties) > 0 {
			out = append(out, collectCopyToSourcePaths(prop.Properties, full, target)...)
		}
	}
	return out
}

func compileHighlightRegexForFields(q *esast.Query, targetFields []string, requireFieldMatch bool, hitSchema *schema.IndexSchema) *regexp.Regexp {
	var terms []string
	if !requireFieldMatch {
		terms = extractQueryTerms(q)
	} else {
		allowed := buildAllowedHighlightQueryFields(targetFields, hitSchema)
		collectTermsFromQueryForFields(q, allowed, &terms)
	}
	if len(terms) == 0 {
		return nil
	}
	var quotedTerms []string
	seenTerms := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		term = strings.Trim(term, "\"")
		if len(strings.Trim(term, "*?")) == 0 {
			continue
		}
		lc := strings.ToLower(term)
		if _, exists := seenTerms[lc]; exists {
			continue
		}
		seenTerms[lc] = struct{}{}
		if strings.ContainsAny(term, "*?") {
			var sb strings.Builder
			for _, r := range term {
				switch r {
				case '*':
					sb.WriteString(`[\p{L}\p{N}_]*`)
				case '?':
					sb.WriteString(`[\p{L}\p{N}_]`)
				default:
					sb.WriteString(regexp.QuoteMeta(string(r)))
				}
			}
			quotedTerms = append(quotedTerms, sb.String())
		} else {
			quotedTerms = append(quotedTerms, regexp.QuoteMeta(term))
		}
	}
	if len(quotedTerms) == 0 {
		return nil
	}
	sort.SliceStable(quotedTerms, func(i, j int) bool {
		return len(quotedTerms[i]) > len(quotedTerms[j])
	})
	re, err := regexp.Compile("(?i)(" + strings.Join(quotedTerms, "|") + ")")
	if err != nil {
		return nil
	}
	return re
}

func buildAllowedHighlightQueryFields(targetFields []string, hitSchema *schema.IndexSchema) map[string]bool {
	allowed := make(map[string]bool, len(targetFields)*4)
	addField := func(f string) {
		if f == "" {
			return
		}
		clean := strings.TrimSuffix(strings.TrimSuffix(f, ".keyword"), ".ngram")
		allowed[f] = true
		allowed[clean] = true
		allowed[clean+".keyword"] = true
		allowed[clean+".ngram"] = true
	}
	for _, tf := range targetFields {
		addField(tf)
		if hitSchema != nil {
			b := hitSchema.ResolveField(tf)
			if len(b.SourceJSONPath) > 0 {
				addField(strings.Join(b.SourceJSONPath, "."))
			}
			if b.AliasTarget != "" {
				addField(b.AliasTarget)
			}
			clean := strings.TrimSuffix(strings.TrimSuffix(tf, ".keyword"), ".ngram")
			if len(b.SourceJSONPath) > 0 {
				clean = strings.Join(b.SourceJSONPath, ".")
			}
			for fn, fb := range hitSchema.Fields {
				if fb.AliasTarget == tf || fb.AliasTarget == clean || strings.TrimSuffix(fb.AliasTarget, ".keyword") == clean {
					addField(fn)
				}
				if len(fb.SourceJSONPath) > 0 && strings.Join(fb.SourceJSONPath, ".") == clean {
					addField(fn)
				}
			}
			for nestedRoot := range hitSchema.NestedRoots {
				if strings.HasPrefix(clean, nestedRoot+".") {
					addField(strings.TrimPrefix(clean, nestedRoot+"."))
				} else {
					addField(nestedRoot + "." + clean)
				}
			}
			if hitSchema.RawMapping != nil {
				visitedSrc := map[string]bool{clean: true}
				frontierSrc := []string{clean}
				for hop := 0; hop < 4 && len(frontierSrc) > 0; hop++ {
					var nextFrontier []string
					for _, t := range frontierSrc {
						for _, src := range collectCopyToSourcePaths(hitSchema.RawMapping.Properties, "", t) {
							addField(src)
							if !visitedSrc[src] {
								visitedSrc[src] = true
								nextFrontier = append(nextFrontier, src)
							}
						}
					}
					frontierSrc = nextFrontier
				}
				visitedDst := map[string]bool{clean: true}
				frontierDst := []string{clean}
				for hop := 0; hop < 4 && len(frontierDst) > 0; hop++ {
					var nextFrontier []string
					for _, s := range frontierDst {
						for _, dst := range collectCopyToTargetsForField(hitSchema.RawMapping.Properties, "", s) {
							addField(dst)
							cleanDst := strings.TrimSuffix(dst, ".keyword")
							if !visitedDst[cleanDst] {
								visitedDst[cleanDst] = true
								nextFrontier = append(nextFrontier, cleanDst)
							}
						}
					}
					frontierDst = nextFrontier
				}
			}
			for fn, fb := range hitSchema.Fields {
				if fb.AliasTarget != "" {
					cleanTarget := strings.TrimSuffix(strings.TrimSuffix(fb.AliasTarget, ".keyword"), ".ngram")
					if allowed[fb.AliasTarget] || allowed[cleanTarget] {
						addField(fn)
					}
				}
			}
		}
	}
	return allowed
}

func collectCopyToTargetsForField(props map[string]esast.FieldProperty, prefix, sourceField string) []string {
	var out []string
	for name, prop := range props {
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		if full == sourceField {
			out = append(out, prop.CopyToSlice()...)
		}
		if len(prop.Properties) > 0 {
			out = append(out, collectCopyToTargetsForField(prop.Properties, full, sourceField)...)
		}
	}
	return out
}

func fieldMatchesAllowedHighlightSet(queryField string, allowed map[string]bool) bool {
	if len(allowed) == 0 {
		return true
	}
	qf := queryField
	if idx := strings.IndexByte(qf, '^'); idx >= 0 {
		qf = qf[:idx]
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(qf, ".keyword"), ".ngram")
	if allowed[qf] || allowed[clean] {
		return true
	}
	if strings.ContainsAny(clean, "*?") {
		for af := range allowed {
			if matchWildcardPattern(clean, af) {
				return true
			}
		}
	}
	return false
}

func collectTermsFromQueryForFields(q *esast.Query, allowed map[string]bool, out *[]string) {
	if q == nil {
		return
	}
	for field, te := range q.Term {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			if s := strings.TrimSpace(fmt.Sprintf("%v", te.Value)); s != "" {
				*out = append(*out, s)
			}
		}
	}
	if q.Terms != nil {
		for f, vals := range q.Terms.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				for _, v := range vals {
					if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
						*out = append(*out, s)
					}
				}
			}
		}
	}
	for field, me := range q.Match {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			*out = append(*out, strings.Fields(fmt.Sprintf("%v", me.Query))...)
		}
	}
	for field, pe := range q.MatchPhrase {
		if fieldMatchesAllowedHighlightSet(field, allowed) && pe.Query != "" {
			if pe.Slop > 0 {
				*out = append(*out, strings.Fields(pe.Query)...)
			} else {
				*out = append(*out, pe.Query)
			}
		}
	}
	for field, pe := range q.MatchPhrasePrefix {
		if fieldMatchesAllowedHighlightSet(field, allowed) && pe.Query != "" {
			words := strings.Fields(pe.Query)
			if len(words) > 0 {
				*out = append(*out, words[:len(words)-1]...)
				*out = append(*out, words[len(words)-1]+"*")
			}
		}
	}
	for field, pe := range q.MatchBoolPrefix {
		if fieldMatchesAllowedHighlightSet(field, allowed) && pe.Query != "" {
			words := strings.Fields(pe.Query)
			if len(words) > 0 {
				*out = append(*out, words[:len(words)-1]...)
				*out = append(*out, words[len(words)-1]+"*")
			}
		}
	}
	if q.CombinedFields != nil && q.CombinedFields.Query != nil {
		matched := len(q.CombinedFields.Fields) == 0
		for _, f := range q.CombinedFields.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				matched = true
				break
			}
		}
		if matched {
			*out = append(*out, strings.Fields(fmt.Sprintf("%v", q.CombinedFields.Query))...)
		}
	}
	if q.MultiMatch != nil && q.MultiMatch.Query != nil {
		matched := len(q.MultiMatch.Fields) == 0
		for _, f := range q.MultiMatch.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				matched = true
				break
			}
		}
		if matched {
			qStr := fmt.Sprintf("%v", q.MultiMatch.Query)
			if strings.EqualFold(q.MultiMatch.Type, "phrase") {
				if q.MultiMatch.Slop > 0 {
					*out = append(*out, strings.Fields(qStr)...)
				} else {
					*out = append(*out, qStr)
				}
			} else if strings.EqualFold(q.MultiMatch.Type, "phrase_prefix") || strings.EqualFold(q.MultiMatch.Type, "bool_prefix") {
				words := strings.Fields(qStr)
				if len(words) > 0 {
					*out = append(*out, words[:len(words)-1]...)
					*out = append(*out, words[len(words)-1]+"*")
				}
			} else {
				*out = append(*out, strings.Fields(qStr)...)
			}
		}
	}
	if q.QueryString != nil && q.QueryString.Query != "" {
		defaultMatched := q.QueryString.DefaultField == "" && len(q.QueryString.Fields) == 0
		if q.QueryString.DefaultField != "" && fieldMatchesAllowedHighlightSet(q.QueryString.DefaultField, allowed) {
			defaultMatched = true
		}
		for _, f := range q.QueryString.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				defaultMatched = true
				break
			}
		}
		extractLuceneScopedTermsForHighlight(q.QueryString.Query, defaultMatched, allowed, out)
	}
	if q.SimpleQueryString != nil && q.SimpleQueryString.Query != "" {
		matched := len(q.SimpleQueryString.Fields) == 0
		for _, f := range q.SimpleQueryString.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				matched = true
				break
			}
		}
		if matched {
			for _, tok := range strings.Fields(q.SimpleQueryString.Query) {
				if tildeIdx := strings.LastIndexByte(tok, '~'); tildeIdx > 0 {
					allDigits := true
					for j := tildeIdx + 1; j < len(tok); j++ {
						if (tok[j] < '0' || tok[j] > '9') && tok[j] != '.' && tok[j] != ')' && tok[j] != '"' {
							allDigits = false
							break
						}
					}
					if allDigits {
						tok = tok[:tildeIdx]
					}
				}
				tok = strings.Trim(tok, "()\"+-|~")
				if strings.Trim(tok, "*?") != "" {
					*out = append(*out, tok)
				}
			}
		}
	}
	for field, we := range q.Wildcard {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			if strings.Trim(we.Value, "*?") != "" {
				*out = append(*out, we.Value)
			}
		}
	}
	for field, pe := range q.Prefix {
		if fieldMatchesAllowedHighlightSet(field, allowed) && pe.Value != "" {
			*out = append(*out, pe.Value+"*")
		}
	}
	for field, ts := range q.TermsSet {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			for _, v := range ts.Terms {
				if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
					*out = append(*out, s)
				}
			}
		}
	}
	for field, fe := range q.Fuzzy {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			if s := strings.TrimSpace(fmt.Sprintf("%v", fe.Value)); s != "" {
				*out = append(*out, s)
			}
		}
	}
	for field, re := range q.Regexp {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			if cleaned := strings.Trim(re.Value, ".*+?^$()[]{}|\\"); cleaned != "" {
				*out = append(*out, cleaned)
			}
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectTermsFromQueryForFields(&q.Bool.Must[i], allowed, out)
		}
		for i := range q.Bool.Should {
			collectTermsFromQueryForFields(&q.Bool.Should[i], allowed, out)
		}
		for i := range q.Bool.Filter {
			collectTermsFromQueryForFields(&q.Bool.Filter[i], allowed, out)
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectTermsFromQueryForFields(&q.DisMax.Queries[i], allowed, out)
		}
	}
	if q.Boosting != nil {
		collectTermsFromQueryForFields(&q.Boosting.Positive, allowed, out)
	}
	if q.Nested != nil {
		collectTermsFromQueryForFields(&q.Nested.Query, allowed, out)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectTermsFromQueryForFields(q.FunctionScore.Query, allowed, out)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectTermsFromQueryForFields(q.ScriptScore.Query, allowed, out)
	}
	if q.ConstantScore != nil {
		collectTermsFromQueryForFields(&q.ConstantScore.Filter, allowed, out)
	}
}

func extractLuceneScopedTermsForHighlight(raw string, defaultMatched bool, allowed map[string]bool, out *[]string) {
	appendCleaned := func(tok string) {
		hadSlop := false
		if tildeIdx := strings.LastIndexByte(tok, '~'); tildeIdx > 0 {
			allDigits := true
			for j := tildeIdx + 1; j < len(tok); j++ {
				if (tok[j] < '0' || tok[j] > '9') && tok[j] != '.' && tok[j] != ')' && tok[j] != '"' {
					allDigits = false
					break
				}
			}
			if allDigits {
				hadSlop = true
				tok = tok[:tildeIdx]
			}
		}
		tok = strings.Trim(tok, "()\"+-!~")
		if strings.Trim(tok, "*?") != "" {
			*out = append(*out, tok)
			if hadSlop && strings.ContainsAny(tok, " \t") {
				for _, w := range strings.Fields(tok) {
					w = strings.Trim(w, "()\"+-!~*?")
					if w != "" {
						*out = append(*out, w)
					}
				}
			}
		}
	}
	n := len(raw)
	i := 0
	var activeGroupField string
	groupDepth := 0
	for i < n {
		for i < n && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\n' || raw[i] == '\r') {
			i++
		}
		if i >= n {
			break
		}
		if (raw[i] == '+' || raw[i] == '-' || raw[i] == '!') && i+1 < n && raw[i+1] == '(' {
			i++
		}
		if raw[i] == '(' {
			if groupDepth > 0 {
				groupDepth++
			}
			i++
			continue
		}
		if raw[i] == ')' {
			if groupDepth > 0 {
				groupDepth--
				if groupDepth == 0 {
					activeGroupField = ""
				}
			}
			i++
			continue
		}
		start := i
		inQuote := false
		colonIdx := -1
		for i < n {
			ch := raw[i]
			if ch == '\\' && i+1 < n {
				i += 2
				continue
			}
			if ch == '"' {
				inQuote = !inQuote
				i++
				continue
			}
			if !inQuote {
				if ch == ':' && colonIdx < 0 {
					colonIdx = i
					if i+1 < n {
						next := raw[i+1]
						if next == '(' || ((next == '+' || next == '-' || next == '!') && i+2 < n && raw[i+2] == '(') {
							fieldPrefix := strings.TrimLeft(raw[start:colonIdx], "+-!(")
							activeGroupField = fieldPrefix
							groupDepth = 1
							if next == '(' {
								i += 2
							} else {
								i += 3
							}
							start = i
							colonIdx = -1
							break
						}
					}
				}
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ')' {
					break
				}
			}
			i++
		}
		if start >= i {
			continue
		}
		tok := raw[start:i]
		upper := strings.ToUpper(strings.Trim(tok, "()"))
		if upper == "AND" || upper == "OR" || upper == "NOT" || upper == "TO" {
			continue
		}
		if colonIdx >= start {
			fieldName := strings.TrimLeft(raw[start:colonIdx], "+-!(")
			valPart := raw[colonIdx+1 : i]
			if fieldMatchesAllowedHighlightSet(fieldName, allowed) {
				appendCleaned(valPart)
			}
			continue
		}
		if activeGroupField != "" {
			if fieldMatchesAllowedHighlightSet(activeGroupField, allowed) {
				appendCleaned(tok)
			}
			continue
		}
		if defaultMatched {
			appendCleaned(tok)
		}
	}
}

func buildHighlightedFieldSnippets(
	vals []string,
	re *regexp.Regexp,
	preTag, postTag string,
	htmlEscape bool,
	fragSize int,
	numFrags int,
	noMatchSize int,
) []string {
	var out []string
	for _, v := range vals {
		if re == nil || !re.MatchString(v) {
			continue
		}
		if numFrags == 0 || fragSize <= 0 || utf8.RuneCountInString(v) <= fragSize {
			highlighted, ok := highlightWithCombinedRegexAndEncoder(v, re, preTag, postTag, htmlEscape)
			if ok {
				out = append(out, highlighted)
			}
			continue
		}
		locs := re.FindAllStringIndex(v, -1)
		lastEnd := -1
		for _, loc := range locs {
			if loc[0] < lastEnd {
				continue
			}
			half := (fragSize - (loc[1] - loc[0])) / 2
			if half < 0 {
				half = 0
			}
			start := loc[0] - half
			if start < 0 {
				start = 0
			}
			end := start + fragSize
			if end > len(v) {
				end = len(v)
				start = end - fragSize
				if start < 0 {
					start = 0
				}
			}
			if end < loc[1] {
				end = loc[1]
			}
			for start > 0 && !utf8.RuneStart(v[start]) {
				start--
			}
			for end < len(v) && !utf8.RuneStart(v[end]) {
				end++
			}
			snippet := v[start:end]
			highlighted, ok := highlightWithCombinedRegexAndEncoder(snippet, re, preTag, postTag, htmlEscape)
			if ok {
				out = append(out, highlighted)
				lastEnd = end
				if numFrags > 0 && len(out) >= numFrags {
					return out[:numFrags]
				}
			}
		}
	}
	if numFrags > 0 && len(out) > numFrags {
		out = out[:numFrags]
	}
	if len(out) == 0 && noMatchSize > 0 {
		for _, v := range vals {
			if v == "" {
				continue
			}
			runes := []rune(v)
			if len(runes) > noMatchSize {
				runes = runes[:noMatchSize]
			}
			s := string(runes)
			if htmlEscape {
				s = html.EscapeString(s)
			}
			return []string{s}
		}
	}
	return out
}

func highlightWithCombinedRegexAndEncoder(text string, re *regexp.Regexp, preTag, postTag string, htmlEscape bool) (string, bool) {
	if !htmlEscape {
		return highlightWithCombinedRegex(text, re, preTag, postTag)
	}
	if re == nil {
		return text, false
	}
	locs := re.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text, false
	}
	var sb strings.Builder
	prev := 0
	for _, loc := range locs {
		if loc[0] > prev {
			sb.WriteString(html.EscapeString(text[prev:loc[0]]))
		}
		sb.WriteString(preTag)
		sb.WriteString(html.EscapeString(text[loc[0]:loc[1]]))
		sb.WriteString(postTag)
		prev = loc[1]
	}
	if prev < len(text) {
		sb.WriteString(html.EscapeString(text[prev:]))
	}
	return sb.String(), true
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
		if len(path) > 1 {
			if flatVal, exists := curr[strings.Join(path, ".")]; exists {
				if res := collectStringValuesAtPath(flatVal, nil); len(res) > 0 {
					return res
				}
			}
		}
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
	collectTermsFromQueryForFields(q, nil, out)
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

func jsonStructurallyEqual(a, b json.RawMessage) bool {
	if bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b)) {
		return true
	}
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	ba, errA := json.Marshal(va)
	bb, errB := json.Marshal(vb)
	return errA == nil && errB == nil && bytes.Equal(ba, bb)
}

func deepestNestedSortPathLocal(n *esast.NestedSortSpec) string {
	curr := n
	var path string
	for curr != nil {
		if p := strings.TrimSpace(curr.Path); p != "" {
			path = p
		}
		curr = curr.Nested
	}
	return path
}

func resolveSortEntryField(s esast.SortSpec, idxSchema *schema.IndexSchema) string {
	field := strings.TrimSpace(s.Entry.Field)
	nestedPath := deepestNestedSortPathLocal(s.Entry.Nested)
	if nestedPath != "" && field != "" && field != nestedPath && !strings.HasPrefix(field, nestedPath+".") {
		prefixed := nestedPath + "." + field
		if idxSchema != nil {
			if _, ok := idxSchema.Fields[prefixed]; ok {
				return prefixed
			}
			if _, ok := idxSchema.Fields[field]; !ok {
				return prefixed
			}
		} else {
			return prefixed
		}
	}
	return field
}

func (s *Server) applySearchRoutingToAliasFilters(rawIndexPattern string, targets []string, reqRouting string, aliasFilters map[string]*esast.Query) map[string]*esast.Query {
	reqRouting = strings.TrimSpace(reqRouting)
	var reqRoutingVals []string
	if reqRouting != "" {
		for _, p := range strings.Split(reqRouting, ",") {
			if p = strings.TrimSpace(p); p != "" {
				reqRoutingVals = append(reqRoutingVals, p)
			}
		}
	}

	s.mu.RLock()
	aliasRoutingsByIdx := make(map[string][]string)
	directNoAliasRouting := make(map[string]bool)
	if len(reqRoutingVals) == 0 && rawIndexPattern != "" && rawIndexPattern != "_all" && rawIndexPattern != "*" {
		for _, part := range strings.Split(rawIndexPattern, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "-") {
				continue
			}
			if part == "_all" || part == "*" {
				for _, t := range targets {
					directNoAliasRouting[t] = true
				}
				continue
			}
			for _, t := range targets {
				if matchWildcardPattern(part, t) {
					directNoAliasRouting[t] = true
				}
			}
			for alias, aTargets := range s.aliases {
				if matchWildcardPattern(part, alias) {
					metaByIdx := s.aliasMeta[alias]
					for _, t := range aTargets {
						var sr string
						if metaByIdx != nil {
							sr = strings.TrimSpace(metaByIdx[t].SearchRouting)
							if sr == "" {
								sr = strings.TrimSpace(metaByIdx[t].Routing)
							}
						}
						if sr == "" {
							directNoAliasRouting[t] = true
						} else {
							for _, rv := range strings.Split(sr, ",") {
								if rv = strings.TrimSpace(rv); rv != "" {
									aliasRoutingsByIdx[t] = append(aliasRoutingsByIdx[t], rv)
								}
							}
						}
					}
				}
			}
		}
	}

	routingRestrictions := make(map[string]map[string]bool)
	for _, t := range targets {
		if len(reqRoutingVals) > 0 {
			set := make(map[string]bool, len(reqRoutingVals))
			for _, rv := range reqRoutingVals {
				set[rv] = true
			}
			routingRestrictions[t] = set
		} else if !directNoAliasRouting[t] && len(aliasRoutingsByIdx[t]) > 0 {
			set := make(map[string]bool, len(aliasRoutingsByIdx[t]))
			for _, rv := range aliasRoutingsByIdx[t] {
				set[rv] = true
			}
			routingRestrictions[t] = set
		}
	}

	if len(routingRestrictions) == 0 {
		s.mu.RUnlock()
		return aliasFilters
	}

	if aliasFilters == nil {
		aliasFilters = make(map[string]*esast.Query, len(routingRestrictions))
	} else {
		cp := make(map[string]*esast.Query, len(aliasFilters)+len(routingRestrictions))
		for k, v := range aliasFilters {
			cp[k] = v
		}
		aliasFilters = cp
	}

	for idxName, allowedSet := range routingRestrictions {
		allowedIDsMap := make(map[string]bool)
		excludedDefaultIDs := make(map[string]bool)
		if docMap := s.docRouting[idxName]; len(docMap) > 0 {
			for docID, rt := range docMap {
				effRt := strings.TrimSpace(rt)
				if effRt == "" {
					effRt = docID
				}
				if allowedSet[effRt] {
					allowedIDsMap[docID] = true
				} else {
					excludedDefaultIDs[docID] = true
				}
			}
		}
		for rv := range allowedSet {
			if !excludedDefaultIDs[rv] {
				allowedIDsMap[rv] = true
			}
		}
		allowedIDs := make([]string, 0, len(allowedIDsMap))
		for id := range allowedIDsMap {
			allowedIDs = append(allowedIDs, id)
		}
		sort.Strings(allowedIDs)
		idsQuery := esast.Query{
			Ids: &esast.IdsQuery{Values: allowedIDs},
		}
		if prev := aliasFilters[idxName]; prev != nil {
			combined := esast.Query{
				Bool: &esast.BoolQuery{
					Filter: []esast.Query{*prev, idsQuery},
				},
			}
			aliasFilters[idxName] = &combined
		} else {
			cp := idsQuery
			aliasFilters[idxName] = &cp
		}
	}
	s.mu.RUnlock()
	return aliasFilters
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
		isIndexExcluded := func(idxName string) bool {
			if isExcluded(idxName) {
				return true
			}
			for alias, targets := range s.aliases {
				if isExcluded(alias) {
					for _, t := range targets {
						if t == idxName {
							return true
						}
					}
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
					if matchWildcardPattern(excl, idxName) || (directNoFilter[idxName] && isIndexExcluded(idxName)) {
						removeTarget(idxName)
					}
				}
				continue
			}
			if part == "_all" || part == "*" {
				for idxName := range s.indices {
					if !isIndexExcluded(idxName) {
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
						if !isIndexExcluded(idxName) {
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
				for dsName, ds := range s.dataStreams {
					if matchWildcardPattern(part, dsName) {
						matchedAny = true
						if isExcluded(dsName) {
							continue
						}
						if rawIndices, ok := ds["indices"].([]any); ok {
							for _, item := range rawIndices {
								if m, okM := item.(map[string]any); okM {
									if bIdx, okS := m["index_name"].(string); okS && bIdx != "" && !isExcluded(bIdx) {
										addTarget(bIdx, nil)
									}
								}
							}
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
			if ds, ok := s.dataStreams[part]; ok {
				if isExcluded(part) {
					continue
				}
				addedDS := false
				if rawIndices, okI := ds["indices"].([]any); okI {
					for _, item := range rawIndices {
						if m, okM := item.(map[string]any); okM {
							if bIdx, okS := m["index_name"].(string); okS && bIdx != "" && !isExcluded(bIdx) {
								addTarget(bIdx, nil)
								addedDS = true
							}
						}
					}
				}
				if addedDS {
					continue
				}
			}
			if checkUnknown {
				if _, isKnownIndex := s.indices[part]; !isKnownIndex {
					needsSync = true
				}
			}
			if !isIndexExcluded(part) {
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
				if metaByIdx != nil && metaByIdx[targets[0]].IsWriteIndex != nil && !*metaByIdx[targets[0]].IsWriteIndex {
					return "", nil, true, fmt.Errorf("no write index is defined for alias [%s]. The write index may be explicitly disabled using is_write_index=false or the alias points to multiple indices without one being designated as a write index", nameOrAlias)
				}
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
		if ds, ok := s.dataStreams[nameOrAlias]; ok {
			if rawIndices, okI := ds["indices"].([]any); okI && len(rawIndices) > 0 {
				if m, okM := rawIndices[len(rawIndices)-1].(map[string]any); okM {
					if bIdx, okS := m["index_name"].(string); okS && bIdx != "" {
						return bIdx, nil, true, nil
					}
				}
			}
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
		if ds, ok := s.dataStreams[nameOrAlias]; ok {
			if rawIndices, okI := ds["indices"].([]any); okI && len(rawIndices) > 0 {
				if m, okM := rawIndices[len(rawIndices)-1].(map[string]any); okM {
					if bIdx, okS := m["index_name"].(string); okS && bIdx != "" {
						return bIdx, nil, true, nil
					}
				}
			}
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

func (s *Server) resolveEffectiveIndexRouting(rawIndex, resolvedIndex string) string {
	return s.resolveEffectiveWriteRouting(rawIndex, resolvedIndex, "", "")
}

func effectiveRuntimeMappings(idxSchema *schema.IndexSchema, reqMappings map[string]esast.FieldProperty) map[string]esast.FieldProperty {
	var hasIdx bool
	if idxSchema != nil && idxSchema.RawMapping != nil && len(idxSchema.RawMapping.Runtime) > 0 {
		hasIdx = true
	}
	if !hasIdx && len(reqMappings) == 0 {
		return nil
	}
	out := make(map[string]esast.FieldProperty, len(reqMappings)+4)
	if hasIdx {
		for k, v := range idxSchema.RawMapping.Runtime {
			out[k] = v
		}
	}
	for k, v := range reqMappings {
		out[k] = v
	}
	return out
}

func (s *Server) augmentSchemaWithRuntimeMappings(idxSchema *schema.IndexSchema, reqMappings map[string]esast.FieldProperty) *schema.IndexSchema {
	rtMap := effectiveRuntimeMappings(idxSchema, reqMappings)
	if len(rtMap) == 0 || idxSchema == nil {
		return idxSchema
	}
	cp := *idxSchema
	cp.Fields = make(map[string]schema.FieldBinding, len(idxSchema.Fields)+len(rtMap)*2)
	for k, v := range idxSchema.Fields {
		cp.Fields[k] = v
	}
	cp.OrderedFields = append([]schema.FieldBinding(nil), idxSchema.OrderedFields...)
	orderedSet := make(map[string]bool, len(cp.OrderedFields))
	for _, ob := range cp.OrderedFields {
		orderedSet[ob.ESFieldPath] = true
	}
	for fName, prop := range rtMap {
		esType := strings.ToLower(strings.TrimSpace(prop.Type))
		if esType == "" {
			esType = "keyword"
		}
		dType := schema.DorisString
		switch esType {
		case "long", "integer", "short", "byte", "unsigned_long":
			dType = schema.DorisBigInt
		case "double", "float", "half_float", "scaled_float":
			dType = schema.DorisDouble
		case "boolean":
			dType = schema.DorisBoolean
		case "date", "date_nanos":
			dType = schema.DorisDateTimeV2
		}
		colIdent := "f__" + schema.SanitizeDorisIdentifier(fName)
		binding := schema.FieldBinding{
			ESFieldPath:    fName,
			ESType:         esType,
			Format:         prop.Format,
			Kind:           schema.StoragePromotedScalar,
			ColumnName:     colIdent,
			DorisType:      dType,
			NotIndexed:     prop.Index != nil && !*prop.Index,
			DocValuesFalse: prop.DocValues != nil && !*prop.DocValues,
			NullValue:      prop.NullValue,
			Coerce:         prop.Coerce,
			ScalingFactor:  prop.ScalingFactor,
			IgnoreAbove:    prop.IgnoreAbove,
			SourceJSONPath: strings.Split(fName, "."),
		}
		cp.Fields[fName] = binding
		if !orderedSet[fName] {
			cp.OrderedFields = append(cp.OrderedFields, binding)
			orderedSet[fName] = true
		}
		if esType == "keyword" || esType == "text" {
			kwBinding := binding
			kwBinding.ESFieldPath = fName + ".keyword"
			kwBinding.ESType = "keyword"
			cp.Fields[fName+".keyword"] = kwBinding
		}
	}
	return &cp
}

func (s *Server) evalRuntimeMappingsOnHitRows(idxSchema *schema.IndexSchema, reqMappings map[string]esast.FieldProperty, hits []HitRow) {
	rtMap := effectiveRuntimeMappings(idxSchema, reqMappings)
	if len(rtMap) == 0 || len(hits) == 0 {
		return
	}
	rtNames := make([]string, 0, len(rtMap))
	for k := range rtMap {
		rtNames = append(rtNames, k)
	}
	sort.Strings(rtNames)
	nowUTC := time.Now().UTC()
	for i := range hits {
		h := &hits[i]
		src := h.EffectiveSource()
		var doc map[string]any
		if len(src) > 0 {
			dec := json.NewDecoder(bytes.NewReader(src))
			dec.UseNumber()
			_ = dec.Decode(&doc)
		}
		if doc == nil {
			doc = make(map[string]any)
		}
		doc["__meta_id"] = h.ID
		if h.Index != "" {
			doc["__meta_index"] = h.Index
		}
		if h.Version > 0 {
			doc["__meta_version"] = h.Version
		} else {
			doc["__meta_version"] = int64(1)
		}
		evalDoc := prepareDocForRuntimeScript(idxSchema, doc)
		modified := false
		for _, fName := range rtNames {
			prop := rtMap[fName]
			if prop.Script == nil {
				continue
			}
			scriptSrc, scriptParams := extractScriptSourceAndParams(prop.Script)
			if strings.TrimSpace(scriptSrc) == "" {
				continue
			}
			p := make(map[string]any, len(scriptParams)+2)
			for k, v := range scriptParams {
				p[k] = v
			}
			p["_source"] = doc
			res, err := painless.Eval(evalDoc, scriptSrc, p)
			var rawVals []any
			if emitted, ok := p["__emitted_vals"].([]any); ok && len(emitted) > 0 {
				rawVals = emitted
			} else if err == nil && res != nil {
				if arr, ok := res.([]any); ok {
					rawVals = arr
				} else {
					rawVals = []any{res}
				}
			}
			if len(rawVals) == 0 {
				continue
			}
			esType := strings.ToLower(strings.TrimSpace(prop.Type))
			coercedVals := make([]any, 0, len(rawVals))
			for _, rv := range rawVals {
				if rv == nil {
					continue
				}
				switch esType {
				case "long", "integer", "short", "byte", "unsigned_long":
					if f, ok := toFloat64(rv); ok {
						coercedVals = append(coercedVals, int64(f))
					}
				case "double", "float", "half_float", "scaled_float":
					if f, ok := toFloat64(rv); ok {
						coercedVals = append(coercedVals, f)
					}
				case "boolean":
					switch bv := rv.(type) {
					case bool:
						coercedVals = append(coercedVals, bv)
					case string:
						if strings.EqualFold(strings.TrimSpace(bv), "true") || strings.TrimSpace(bv) == "1" {
							coercedVals = append(coercedVals, true)
						} else if strings.EqualFold(strings.TrimSpace(bv), "false") || strings.TrimSpace(bv) == "0" {
							coercedVals = append(coercedVals, false)
						}
					}
				case "date", "date_nanos":
					if f, ok := toFloat64(rv); ok {
						coercedVals = append(coercedVals, int64(f))
					} else if sv, ok := rv.(string); ok {
						if ms, ok := schema.ParseESDateWithFormatToEpochMillis(sv, prop.Format, nowUTC); ok {
							coercedVals = append(coercedVals, ms)
						} else {
							coercedVals = append(coercedVals, sv)
						}
					}
				default:
					coercedVals = append(coercedVals, fmt.Sprintf("%v", rv))
				}
			}
			if len(coercedVals) == 0 {
				continue
			}
			var finalVal any
			if len(coercedVals) == 1 {
				finalVal = coercedVals[0]
			} else {
				finalVal = coercedVals
			}
			doc[fName] = finalVal
			if strings.Contains(fName, ".") {
				setIngestPath(doc, fName, finalVal)
			}
			evalDoc[fName] = finalVal
			modified = true
		}
		if modified {
			delete(doc, "__meta_id")
			delete(doc, "__meta_index")
			delete(doc, "__meta_version")
			if updatedBytes, err := json.Marshal(doc); err == nil {
				h.RawSource = updatedBytes
			}
		}
		h.Schema = idxSchema
	}
}

func (s *Server) docMatchesAliasFilter(ctx context.Context, indexName, docID string, rawSource json.RawMessage, filter *esast.Query) bool {
	return s.docMatchesAliasFilterWithSchema(ctx, indexName, nil, docID, rawSource, filter)
}

func (s *Server) docMatchesAliasFilterWithSchema(ctx context.Context, indexName string, idxSchema *schema.IndexSchema, docID string, rawSource json.RawMessage, filter *esast.Query) bool {
	if filter == nil {
		return true
	}
	if len(rawSource) == 0 {
		return false
	}
	if idxSchema == nil {
		idxSchema = s.getOrCompileReadOnlySchema(ctx, indexName)
	}
	if idxSchema == nil {
		idxSchema = schema.CompileIndexSchema(s.dorisDB, indexName, nil)
	}
	if len(effectiveRuntimeMappings(idxSchema, nil)) > 0 {
		idxSchema = s.augmentSchemaWithRuntimeMappings(idxSchema, nil)
		tmpHits := []HitRow{{ID: docID, Index: indexName, Source: rawSource}}
		s.evalRuntimeMappingsOnHitRows(idxSchema, nil, tmpHits)
		rawSource = tmpHits[0].EffectiveSource()
	}
	origFields := idxSchema.Fields
	if idxSchema.RawMapping == nil || idxSchema.RawMapping.Dynamic == nil || idxSchema.RawMapping.Dynamic == true || idxSchema.RawMapping.Dynamic == "true" {
		inferred := schema.InferMappingFromSampleDocs([]json.RawMessage{rawSource})
		if inferred != nil && len(inferred.Properties) > 0 {
			merged := schema.MergeMappingSpecs(inferred, idxSchema.RawMapping)
			idxSchema = schema.CompileIndexSchema(s.dorisDB, indexName, merged)
			for k, v := range origFields {
				if _, exists := idxSchema.Fields[k]; !exists {
					idxSchema.Fields[k] = v
					if v.AliasTarget == "" && v.ColumnName != "" && !strings.HasSuffix(k, ".keyword") {
						idxSchema.OrderedFields = append(idxSchema.OrderedFields, v)
					}
				}
			}
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
	if whereExpr != "" && whereExpr != "1=1" && !strings.EqualFold(whereExpr, "TRUE") {
		if !evalWhereExpr(row, whereExpr) {
			return false
		}
	}
	if queryHasRuntimeScript(effFilter) || queryHasMinScore(effFilter) {
		if docMap == nil {
			docMap = make(map[string]any)
		}
		docMap["__meta_id"] = docID
		if !evalQueryScriptFilterOnDocWithSchema(idxSchema, docMap, effFilter) {
			return false
		}
	}
	return true
}

func hasExclusionOrWildcard(rawIndex string) bool {
	if strings.ContainsAny(rawIndex, "*?") {
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
			if len(sampleDocs) > 0 {
				if delta := detectArrayPromotions(idx, sampleDocs); delta != nil {
					return s.applyArrayPromotionDelta(ctx, indexName, idx, delta)
				}
			}
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
		if len(sampleDocs) > 0 {
			if delta := detectArrayPromotions(idx, sampleDocs); delta != nil {
				return s.applyArrayPromotionDelta(ctx, indexName, idx, delta)
			}
		}
		return idx
	}
	var existingEmptySchema *schema.IndexSchema
	if ok {
		existingEmptySchema = idx
	}
	tplMappings, tplDefPipe, hasTplDefPipe, tplFinPipe, hasTplFinPipe, tplAliases := s.matchingTemplateConfigLocked(indexName)
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
	if len(sampleDocs) > 0 {
		if delta := detectArrayPromotions(compiled, sampleDocs); delta != nil {
			effectiveMappings = schema.MergeMappingSpecs(effectiveMappings, delta)
			compiled = schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
		}
	}
	_ = s.backend.ExecDDL(ctx, schema.GenerateCreateTableDDL(compiled))
	if existingEmptySchema != nil {
		for _, stmt := range schema.GenerateAlterTableDDL(existingEmptySchema, compiled) {
			_ = s.backend.ExecDDL(ctx, stmt)
		}
	}
	aliasesToPersist := make(map[string][]string)
	s.mu.Lock()
	if existing, exists := s.indices[indexName]; exists && (len(existing.Fields) > 0 || len(existing.NestedRoots) > 0) {
		s.mu.Unlock()
		return existing
	}
	s.indices[indexName] = compiled
	if existingEmptySchema == nil {
		if hasTplDefPipe && tplDefPipe != "" {
			if _, hasCur := s.indexDefaultPipelines[indexName]; !hasCur {
				s.indexDefaultPipelines[indexName] = tplDefPipe
			}
		}
		if hasTplFinPipe && tplFinPipe != "" {
			if _, hasCur := s.indexFinalPipelines[indexName]; !hasCur {
				s.indexFinalPipelines[indexName] = tplFinPipe
			}
		}
		for alias, rawMeta := range tplAliases {
			meta := parseAliasMetadata(rawMeta)
			s.addAliasWithMetaLocked(alias, indexName, meta)
			aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
		}
	}
	s.mu.Unlock()
	s.persistIndex(ctx, indexName, compiled)
	for alias, targets := range aliasesToPersist {
		s.persistAlias(ctx, alias, targets)
	}
	s.queryCache.InvalidateAll()
	return compiled
}

func (s *Server) applyArrayPromotionDelta(ctx context.Context, indexName string, oldSchema *schema.IndexSchema, delta *esast.MappingSpec) *schema.IndexSchema {
	merged := schema.MergeMappingSpecs(oldSchema.RawMapping, delta)
	newSchema := schema.CompileIndexSchema(s.dorisDB, indexName, merged)
	for _, stmt := range schema.GenerateAlterTableDDL(oldSchema, newSchema) {
		_ = s.backend.ExecDDL(ctx, stmt)
	}
	s.mu.Lock()
	s.indices[indexName] = newSchema
	s.mu.Unlock()
	s.persistIndex(ctx, indexName, newSchema)
	s.backfillIndexSchema(ctx, newSchema)
	s.queryCache.InvalidateAll()
	return newSchema
}

func detectArrayPromotions(idx *schema.IndexSchema, sampleDocs []json.RawMessage) *esast.MappingSpec {
	if idx == nil || len(idx.Fields) == 0 || len(sampleDocs) == 0 {
		return nil
	}
	promotedPaths := make(map[string]schema.FieldBinding)
	for _, docBytes := range sampleDocs {
		if len(docBytes) == 0 {
			continue
		}
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(docBytes))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			continue
		}
		for _, fb := range idx.Fields {
			if fb.Kind != schema.StoragePromotedScalar || len(fb.SourceJSONPath) == 0 {
				continue
			}
			dotPath := strings.Join(fb.SourceJSONPath, ".")
			if fb.ESFieldPath != dotPath {
				continue
			}
			if _, already := promotedPaths[dotPath]; already {
				continue
			}
			if hasJSONArrayAtPath(doc, fb.SourceJSONPath) {
				promotedPaths[dotPath] = fb
			}
		}
	}
	if len(promotedPaths) == 0 {
		return nil
	}
	delta := &esast.MappingSpec{
		Properties: make(map[string]esast.FieldProperty),
	}
	for _, fb := range promotedPaths {
		esType := fb.ESType
		if esType == "" {
			switch fb.DorisType {
			case schema.DorisBigInt:
				esType = "long"
			case schema.DorisDouble:
				esType = "double"
			case schema.DorisBoolean:
				esType = "boolean"
			default:
				esType = "text"
			}
		}
		setFieldPropertyAtPath(delta.Properties, fb.SourceJSONPath, esast.FieldProperty{
			Type:          esType,
			MultiValued:   true,
			UpgradedArray: true,
		})
	}
	return delta
}

func hasJSONNonNilAtPath(node any, path []string) bool {
	if node == nil {
		return false
	}
	if len(path) == 0 {
		return true
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok && hasJSONNonNilAtPath(next, path[1:]) {
			return true
		}
		if len(path) > 1 {
			if flat, ok := curr[strings.Join(path, ".")]; ok && flat != nil {
				return true
			}
		}
	case []any:
		for _, elem := range curr {
			if hasJSONNonNilAtPath(elem, path) {
				return true
			}
		}
	}
	return false
}

func hasJSONArrayAtPath(node any, path []string) bool {
	if node == nil {
		return false
	}
	if len(path) == 0 {
		_, isArr := node.([]any)
		return isArr
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok && hasJSONArrayAtPath(next, path[1:]) {
			return true
		}
		if len(path) > 1 {
			if flat, ok := curr[strings.Join(path, ".")]; ok && hasJSONArrayAtPath(flat, nil) {
				return true
			}
		}
	case []any:
		for _, elem := range curr {
			if hasJSONNonNilAtPath(elem, path) {
				return true
			}
		}
	}
	return false
}

func setFieldPropertyAtPath(props map[string]esast.FieldProperty, path []string, prop esast.FieldProperty) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		if existing, ok := props[path[0]]; ok {
			if prop.Fields == nil && len(existing.Fields) > 0 {
				prop.Fields = existing.Fields
			}
			if prop.Normalizer == "" && existing.Normalizer != "" {
				prop.Normalizer = existing.Normalizer
			}
			if prop.Analyzer == "" && existing.Analyzer != "" {
				prop.Analyzer = existing.Analyzer
			}
			if prop.Format == "" && existing.Format != "" {
				prop.Format = existing.Format
			}
		}
		props[path[0]] = prop
		return
	}
	child := props[path[0]]
	if child.Properties == nil {
		child.Properties = make(map[string]esast.FieldProperty)
	}
	setFieldPropertyAtPath(child.Properties, path[1:], prop)
	props[path[0]] = child
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

func queryHasRuntimeScript(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Script != nil || q.ScriptScore != nil {
		return true
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.ScriptScore != nil || q.FunctionScore.MinScore != nil || q.FunctionScore.RandomScore != nil {
			return true
		}
		for _, fn := range q.FunctionScore.Functions {
			if fn.ScriptScore != nil || fn.RandomScore != nil || queryHasRuntimeScript(fn.Filter) {
				return true
			}
		}
		if queryHasRuntimeScript(q.FunctionScore.Query) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryHasRuntimeScript(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryHasRuntimeScript(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryHasRuntimeScript(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryHasRuntimeScript(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryHasRuntimeScript(&q.ConstantScore.Filter) {
		return true
	}
	if q.Nested != nil && (queryHasRuntimeScript(&q.Nested.Query) || queryContainsNested(&q.Nested.Query)) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryHasRuntimeScript(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if queryHasRuntimeScript(&q.Boosting.Positive) || queryHasRuntimeScript(&q.Boosting.Negative) {
			return true
		}
	}
	return false
}

func sortsHaveScript(sorts []esast.SortSpec) bool {
	for _, s := range sorts {
		if s.Entry.Field == "_script" || s.Entry.Script != nil || s.Entry.Field == "_geo_distance" || s.Entry.Type != "" {
			return true
		}
	}
	return false
}

func evalGeoDistanceSortValue(doc map[string]any, s esast.SortSpec) any {
	geoMap, ok := s.Entry.Script.(map[string]any)
	if !ok || len(geoMap) == 0 {
		return nil
	}
	reserved := map[string]bool{
		"order": true, "mode": true, "missing": true, "unit": true,
		"distance_type": true, "validation_method": true, "ignore_unmapped": true, "nested": true,
	}
	var geoField string
	var originRaw any
	for k, v := range geoMap {
		if !reserved[k] {
			geoField = k
			originRaw = v
			break
		}
	}
	if geoField == "" {
		return nil
	}
	tLat, tLon, ok := parseGeoPointLatLon(originRaw)
	if !ok {
		return nil
	}
	unit := "m"
	if uStr, okU := geoMap["unit"].(string); okU && uStr != "" {
		unit = strings.ToLower(strings.TrimSpace(uStr))
	}
	pts := collectGeoPointsAtPath(doc, strings.Split(geoField, "."))
	if len(pts) == 0 {
		if s.Entry.Missing != "" && !strings.EqualFold(s.Entry.Missing, "_last") && !strings.EqualFold(s.Entry.Missing, "_first") {
			if fv, err := strconv.ParseFloat(s.Entry.Missing, 64); err == nil {
				return fv
			}
		}
		return nil
	}
	dists := make([]any, 0, len(pts))
	for _, pt := range pts {
		d := haversineDistanceMeters(tLat, tLon, pt[0], pt[1])
		switch unit {
		case "km", "kilometers", "kilometer":
			d /= 1000.0
		case "mi", "miles", "mile":
			d /= 1609.344
		case "yd", "yards", "yard":
			d /= 0.9144
		case "ft", "feet", "foot":
			d /= 0.3048
		case "nmi", "NM":
			d /= 1852.0
		}
		dists = append(dists, d)
	}
	if len(dists) == 1 {
		return dists[0]
	}
	return reduceSortFieldValues(dists, s.Entry.Mode, s.Entry.Order)
}

func parseGeoPointLatLon(v any) (lat, lon float64, ok bool) {
	switch tv := v.(type) {
	case map[string]any:
		latVal, okLat := toFloat64(tv["lat"])
		lonVal, okLon := toFloat64(tv["lon"])
		if okLat && okLon {
			return latVal, lonVal, true
		}
	case []any:
		if len(tv) >= 2 {
			lonVal, okLon := toFloat64(tv[0])
			latVal, okLat := toFloat64(tv[1])
			if okLat && okLon {
				return latVal, lonVal, true
			}
		}
	case string:
		str := strings.TrimSpace(tv)
		if strings.HasPrefix(strings.ToUpper(str), "POINT") {
			openIdx := strings.IndexByte(str, '(')
			closeIdx := strings.LastIndexByte(str, ')')
			if openIdx > 0 && closeIdx > openIdx {
				fields := strings.Fields(str[openIdx+1 : closeIdx])
				if len(fields) == 2 {
					lonVal, err1 := strconv.ParseFloat(fields[0], 64)
					latVal, err2 := strconv.ParseFloat(fields[1], 64)
					if err1 == nil && err2 == nil {
						return latVal, lonVal, true
					}
				}
			}
		}
		if parts := strings.Split(str, ","); len(parts) == 2 {
			latVal, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			lonVal, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 == nil && err2 == nil {
				return latVal, lonVal, true
			}
		}
		if latVal, lonVal, okHash := schema.DecodeGeohashLatLon(str); okHash {
			return latVal, lonVal, true
		}
	}
	return 0, 0, false
}

func collectGeoPointsAtPath(node any, path []string) [][2]float64 {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		if lat, lon, ok := parseGeoPointLatLon(node); ok {
			return [][2]float64{{lat, lon}}
		}
		if arr, ok := node.([]any); ok {
			var res [][2]float64
			for _, elem := range arr {
				res = append(res, collectGeoPointsAtPath(elem, nil)...)
			}
			return res
		}
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, exists := curr[path[0]]; exists {
			return collectGeoPointsAtPath(next, path[1:])
		}
		if len(path) > 1 {
			if flat, exists := curr[strings.Join(path, ".")]; exists {
				return collectGeoPointsAtPath(flat, nil)
			}
		}
	case []any:
		var res [][2]float64
		for _, item := range curr {
			res = append(res, collectGeoPointsAtPath(item, path)...)
		}
		return res
	}
	return nil
}

func haversineDistanceMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusMeters = 6371008.7714
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0
	rLat1 := lat1 * math.Pi / 180.0
	rLat2 := lat2 * math.Pi / 180.0
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(rLat1)*math.Cos(rLat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(math.Max(0, 1-a)))
	return earthRadiusMeters * c
}

func aliasFiltersHaveRuntimeScript(aliasFilters map[string]*esast.Query) bool {
	for _, q := range aliasFilters {
		if queryHasRuntimeScript(q) {
			return true
		}
	}
	return false
}

func aliasFiltersHaveMinScore(aliasFilters map[string]*esast.Query) bool {
	for _, q := range aliasFilters {
		if queryHasMinScore(q) {
			return true
		}
	}
	return false
}

func queryHasMinScore(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.MinScore != nil || queryHasMinScore(q.FunctionScore.Query) {
			return true
		}
		for _, fn := range q.FunctionScore.Functions {
			if queryHasMinScore(fn.Filter) {
				return true
			}
		}
	}
	if q.ScriptScore != nil {
		if q.ScriptScore.MinScore != nil || queryHasMinScore(q.ScriptScore.Query) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryHasMinScore(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryHasMinScore(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryHasMinScore(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryHasMinScore(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryHasMinScore(&q.ConstantScore.Filter) {
		return true
	}
	if q.Boosting != nil && (queryHasMinScore(&q.Boosting.Positive) || queryHasMinScore(&q.Boosting.Negative)) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryHasMinScore(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Nested != nil && queryHasMinScore(&q.Nested.Query) {
		return true
	}
	return false
}

func aggSpecHasDirectRuntimeScript(spec esast.AggSpec) bool {
	if spec.RareTerms != nil || spec.MultiTerms != nil || spec.AutoDateHistogram != nil || spec.VariableWidthHistogram != nil ||
		spec.WeightedAvg != nil || spec.MedianAbsoluteDeviation != nil ||
		spec.GeoBounds != nil || spec.GeoCentroid != nil || spec.GeoDistance != nil ||
		spec.GeohashGrid != nil || spec.GeotileGrid != nil ||
		spec.AdjacencyMatrix != nil || spec.MatrixStats != nil || spec.TTest != nil {
		return true
	}
	if t := spec.EffectiveTerms(); t != nil && t.Script != nil {
		return true
	}
	if spec.Histogram != nil && spec.Histogram.Script != nil {
		return true
	}
	if spec.DateHistogram != nil && spec.DateHistogram.Script != nil {
		return true
	}
	if r := spec.EffectiveRange(); r != nil && r.Script != nil {
		return true
	}
	if spec.Filter != nil && queryHasRuntimeScript(spec.Filter) {
		return true
	}
	if spec.Filters != nil {
		for _, fq := range spec.Filters.Filters {
			q := fq
			if queryHasRuntimeScript(&q) {
				return true
			}
		}
		for i := range spec.Filters.AnonymousFilters {
			if queryHasRuntimeScript(&spec.Filters.AnonymousFilters[i]) {
				return true
			}
		}
	}
	if spec.Composite != nil {
		for _, srcMap := range spec.Composite.Sources {
			for _, src := range srcMap {
				if (src.Terms != nil && src.Terms.Script != nil) ||
					(src.Histogram != nil && src.Histogram.Script != nil) ||
					(src.DateHistogram != nil && src.DateHistogram.Script != nil) {
					return true
				}
			}
		}
	}
	for _, m := range []*esast.MetricAggSpec{
		spec.Avg, spec.Sum, spec.Min, spec.Max,
		spec.EffectiveStats(), spec.ValueCount, spec.Cardinality, spec.Boxplot,
	} {
		if m != nil && m.Script != nil {
			return true
		}
	}
	if spec.Percentiles != nil && spec.Percentiles.Script != nil {
		return true
	}
	if spec.PercentileRanks != nil && spec.PercentileRanks.Script != nil {
		return true
	}
	if spec.StringStats != nil && spec.StringStats.Script != nil {
		return true
	}
	if spec.Rate != nil && spec.Rate.Script != nil {
		return true
	}
	if spec.TopHits != nil && sortsHaveScript(spec.TopHits.Sort) {
		return true
	}
	if spec.TopMetrics != nil && sortsHaveScript(spec.TopMetrics.Sort) {
		return true
	}
	if spec.ScriptedMetric != nil {
		return true
	}
	if reverseNestedPath(spec.ReverseNested) != "" {
		return true
	}
	if spec.EffectiveSampler() != nil {
		return true
	}
	return false
}

func sampleDocsForSampler(docs []runtimeMatchedDoc, spec esast.AggSpec, idxSchema *schema.IndexSchema) []runtimeMatchedDoc {
	s := spec.EffectiveSampler()
	if s == nil || len(docs) == 0 {
		return docs
	}
	shardSize := s.ShardSize
	if shardSize <= 0 {
		shardSize = 100
	}
	sorted := make([]runtimeMatchedDoc, len(docs))
	copy(sorted, docs)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].hit.Score != sorted[j].hit.Score {
			return sorted[i].hit.Score > sorted[j].hit.Score
		}
		return sorted[i].hit.ID < sorted[j].hit.ID
	})
	if spec.DiversifiedSampler == nil && s.Field == "" && s.Script == nil && s.MaxDocsPerValue <= 0 {
		if len(sorted) > shardSize {
			return sorted[:shardSize]
		}
		return sorted
	}
	maxPerVal := s.MaxDocsPerValue
	if maxPerVal <= 0 {
		maxPerVal = 1
	}
	seenPerVal := make(map[string]int)
	out := make([]runtimeMatchedDoc, 0, min(len(sorted), shardSize))
	cleanField := strings.TrimSuffix(strings.TrimSuffix(s.Field, ".keyword"), ".ngram")
	for _, md := range sorted {
		if len(out) >= shardSize {
			break
		}
		effSchema := md.EffectiveSchema(idxSchema)
		var vals []any
		if s.Script != nil {
			src, params := extractScriptSourceAndParams(s.Script)
			if src != "" {
				evalDoc := prepareDocForRuntimeScript(effSchema, md.doc)
				if v, err := painless.Eval(evalDoc, src, params); err == nil && v != nil {
					if arr, ok := v.([]any); ok {
						vals = arr
					} else {
						vals = []any{v}
					}
				}
			}
		} else if s.Field != "" {
			pathSegs := strings.Split(cleanField, ".")
			if effSchema != nil {
				if b := effSchema.ResolveField(s.Field); len(b.SourceJSONPath) > 0 {
					pathSegs = b.SourceJSONPath
				}
			}
			vals = collectSchemaAwareScalarValues(md.doc, s.Field, pathSegs, effSchema)
		}
		if len(vals) == 0 {
			out = append(out, md)
			continue
		}
		exceeded := false
		strKeys := make([]string, 0, len(vals))
		for _, v := range vals {
			k := fmt.Sprintf("%v", v)
			strKeys = append(strKeys, k)
			if seenPerVal[k] >= maxPerVal {
				exceeded = true
				break
			}
		}
		if !exceeded {
			for _, k := range strKeys {
				seenPerVal[k]++
			}
			out = append(out, md)
		}
	}
	return out
}

func reverseNestedPath(rn map[string]any) string {
	if rn == nil {
		return ""
	}
	if p, ok := rn["path"].(string); ok {
		return strings.TrimSpace(p)
	}
	return ""
}

func aggsHaveRuntimeScript(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if aggSpecHasDirectRuntimeScript(spec) {
			return true
		}
		if aggsHaveRuntimeScript(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func globalAggsHaveRuntimeScript(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Global != nil && aggsHaveRuntimeScript(spec.SubAggs()) {
			return true
		}
		if globalAggsHaveRuntimeScript(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func aggsHaveGlobalAgg(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Global != nil || aggsHaveGlobalAgg(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func collectNestedPathsFromQuery(q *esast.Query, out map[string]bool) {
	if q == nil {
		return
	}
	if q.Nested != nil && q.Nested.Path != "" {
		out[q.Nested.Path] = true
		collectNestedPathsFromQuery(&q.Nested.Query, out)
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectNestedPathsFromQuery(&q.Bool.Must[i], out)
		}
		for i := range q.Bool.Filter {
			collectNestedPathsFromQuery(&q.Bool.Filter[i], out)
		}
		for i := range q.Bool.Should {
			collectNestedPathsFromQuery(&q.Bool.Should[i], out)
		}
		for i := range q.Bool.MustNot {
			collectNestedPathsFromQuery(&q.Bool.MustNot[i], out)
		}
	}
	if q.ConstantScore != nil {
		collectNestedPathsFromQuery(&q.ConstantScore.Filter, out)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectNestedPathsFromQuery(&q.DisMax.Queries[i], out)
		}
	}
	if q.Boosting != nil {
		collectNestedPathsFromQuery(&q.Boosting.Positive, out)
		collectNestedPathsFromQuery(&q.Boosting.Negative, out)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectNestedPathsFromQuery(q.FunctionScore.Query, out)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectNestedPathsFromQuery(q.ScriptScore.Query, out)
	}
}

func resetNestedScalarMultiValued(props map[string]esast.FieldProperty, elems []nestedElemCandidate) map[string]esast.FieldProperty {
	if len(props) == 0 {
		return props
	}
	cp := make(map[string]esast.FieldProperty, len(props))
	for k, v := range props {
		isElemArray := false
		for _, el := range elems {
			if el.obj != nil {
				if _, ok := el.obj[k].([]any); ok {
					isElemArray = true
					break
				}
			}
		}
		if !isElemArray {
			v.MultiValued = false
		}
		cp[k] = v
	}
	return cp
}

func promoteMappingPropsToNested(props map[string]esast.FieldProperty, segs []string, elems []nestedElemCandidate) map[string]esast.FieldProperty {
	if len(segs) == 0 {
		return props
	}
	if props == nil {
		props = make(map[string]esast.FieldProperty)
	}
	cp := make(map[string]esast.FieldProperty, len(props))
	for k, v := range props {
		cp[k] = v
	}
	head := segs[0]
	prop := cp[head]
	if len(segs) == 1 {
		prop.Type = "nested"
		prop.MultiValued = false
		prop.Properties = resetNestedScalarMultiValued(prop.Properties, elems)
	} else {
		prop.Properties = promoteMappingPropsToNested(prop.Properties, segs[1:], elems)
	}
	cp[head] = prop
	return cp
}

func queryContainsNested(q *esast.Query) bool {
	if q == nil {
		return false
	}
	out := make(map[string]bool)
	collectNestedPathsFromQuery(q, out)
	return len(out) > 0
}

func resolveRuntimeEvalSchema(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query, rawSource []byte) *schema.IndexSchema {
	effSchema := idxSchema
	nestedPaths := make(map[string]bool)
	if effSchema != nil {
		for np := range effSchema.NestedRoots {
			nestedPaths[np] = true
		}
	}
	collectNestedPathsFromQuery(q, nestedPaths)
	missingNestedRoot := false
	for np := range nestedPaths {
		if effSchema == nil || effSchema.NestedRoots[np] == "" {
			missingNestedRoot = true
			break
		}
	}
	if effSchema == nil || effSchema.RawMapping == nil || effSchema.RawMapping.Dynamic == nil || effSchema.RawMapping.Dynamic == true || effSchema.RawMapping.Dynamic == "true" || missingNestedRoot {
		inferred := schema.InferMappingFromSampleDocs([]json.RawMessage{rawSource})
		var baseMapping *esast.MappingSpec
		dbName, idxName := "default", "eval_idx"
		if effSchema != nil {
			baseMapping = effSchema.RawMapping
			dbName = effSchema.DorisDB
			idxName = effSchema.IndexName
		}
		merged := schema.MergeMappingSpecs(inferred, baseMapping)
		if len(nestedPaths) > 0 {
			if merged == nil {
				merged = &esast.MappingSpec{Properties: make(map[string]esast.FieldProperty)}
			} else {
				cp := *merged
				merged = &cp
			}
			for np := range nestedPaths {
				segs := strings.Split(np, ".")
				elems := extractNestedElementsAtPath(doc, segs)
				merged.Properties = promoteMappingPropsToNested(merged.Properties, segs, elems)
			}
		}
		effSchema = schema.CompileIndexSchema(dbName, idxName, merged)
		if idxSchema != nil {
			for k, v := range idxSchema.Fields {
				if _, exists := effSchema.Fields[k]; !exists {
					effSchema.Fields[k] = v
					if v.AliasTarget == "" && v.ColumnName != "" && !strings.HasSuffix(k, ".keyword") {
						effSchema.OrderedFields = append(effSchema.OrderedFields, v)
					}
				}
			}
		}
	}
	return effSchema
}

func marshalDocAndExtractEvalID(doc map[string]any, defaultID string) ([]byte, string, error) {
	docID := defaultID
	if doc != nil {
		if idStr, ok := doc["__meta_id"].(string); ok && idStr != "" {
			docID = idStr
		} else if idStr, ok := doc["_id"].(string); ok && idStr != "" {
			docID = idStr
		}
		if doc["__meta_id"] != nil || doc["__meta_index"] != nil || doc["__meta_version"] != nil {
			clean := make(map[string]any, len(doc))
			for k, v := range doc {
				if k != "__meta_id" && k != "__meta_index" && k != "__meta_version" {
					clean[k] = v
				}
			}
			b, err := json.Marshal(clean)
			return b, docID, err
		}
	}
	b, err := json.Marshal(doc)
	return b, docID, err
}

func docMatchesNonScriptClause(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query) bool {
	if q == nil {
		return true
	}
	rawSource, docID, err := marshalDocAndExtractEvalID(doc, "_eval")
	if err != nil {
		return false
	}
	effSchema := resolveRuntimeEvalSchema(idxSchema, doc, q, rawSource)
	shreddedBytes, err := schema.ShredDocument(effSchema, docID, 1, false, rawSource)
	if err != nil {
		return false
	}
	var row map[string]any
	dec := json.NewDecoder(bytes.NewReader(shreddedBytes))
	dec.UseNumber()
	if err := dec.Decode(&row); err != nil {
		return false
	}
	row["_doc"] = doc
	t := transpiler.NewTranspiler(effSchema, transpiler.TranspilerOptions{})
	cq := t.CompileQuery(q, false, nil)
	whereExpr := strings.TrimSpace(cq.WhereSQL)
	if whereExpr == "" || whereExpr == "1=1" || strings.EqualFold(whereExpr, "TRUE") {
		return true
	}
	return evalWhereExpr(row, whereExpr)
}

func evalBranchMatchesDoc(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query) bool {
	if q == nil {
		return true
	}
	if !docMatchesNonScriptClause(idxSchema, doc, q) {
		return false
	}
	if (queryHasRuntimeScript(q) || queryHasMinScore(q)) && !evalQueryScriptFilterOnDocWithSchema(idxSchema, doc, q) {
		return false
	}
	return true
}

func resolveMinimumShouldMatch(msm any, totalShould int, noMustOrFilter bool) int {
	if totalShould == 0 {
		return 0
	}
	if msm == nil {
		if noMustOrFilter {
			return 1
		}
		return 0
	}
	switch v := msm.(type) {
	case int:
		if v < 0 {
			return max(0, totalShould+v)
		}
		return v
	case int64:
		if v < 0 {
			return max(0, totalShould+int(v))
		}
		return int(v)
	case float64:
		iv := int(v)
		if iv < 0 {
			return max(0, totalShould+iv)
		}
		return iv
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			if iv < 0 {
				return max(0, totalShould+int(iv))
			}
			return int(iv)
		}
	case string:
		s := strings.TrimSpace(v)
		if strings.Contains(s, "<") {
			parts := strings.Fields(s)
			activeSpec := ""
			first := true
			for _, part := range parts {
				if idx := strings.IndexByte(part, '<'); idx > 0 {
					if thresh, err := strconv.Atoi(strings.TrimSpace(part[:idx])); err == nil {
						if first && totalShould <= thresh {
							return totalShould
						}
						first = false
						if totalShould > thresh {
							activeSpec = strings.TrimSpace(part[idx+1:])
						}
					}
				}
			}
			if activeSpec != "" {
				s = activeSpec
			}
		}
		if strings.HasSuffix(s, "%") {
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64); err == nil {
				if pct < 0 {
					req := totalShould - int(math.Floor(float64(totalShould)*math.Abs(pct)/100.0))
					return max(1, req)
				}
				req := int(math.Floor(float64(totalShould) * pct / 100.0))
				if req < 1 && pct > 0 {
					req = 1
				}
				return req
			}
		}
		if iv, err := strconv.Atoi(s); err == nil {
			if iv < 0 {
				return max(1, totalShould+iv)
			}
			return iv
		}
	}
	if noMustOrFilter {
		return 1
	}
	return 0
}

func evalQueryScriptFilterOnDocWithSchema(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query) bool {
	return evalQueryScriptFilterOnDocWithScore(idxSchema, doc, q, 1.0)
}

func evalQueryScriptFilterOnDocWithScore(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query, baseScore float64) bool {
	if q == nil {
		return true
	}
	if q.Script != nil && q.Script.Script != nil {
		src, params := extractScriptSourceAndParams(q.Script.Script)
		if src != "" {
			evalDoc := prepareDocForRuntimeScript(idxSchema, doc)
			cp := make(map[string]any, len(params)+1)
			for k, v := range params {
				cp[k] = v
			}
			cp["_score"] = baseScore
			ok, err := painless.EvalFilter(evalDoc, src, cp)
			if err != nil || !ok {
				return false
			}
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, &q.Bool.Must[i], 1.0) {
				return false
			}
		}
		for i := range q.Bool.Filter {
			if !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, &q.Bool.Filter[i], baseScore) {
				return false
			}
		}
		for i := range q.Bool.MustNot {
			if (queryHasRuntimeScript(&q.Bool.MustNot[i]) || queryHasMinScore(&q.Bool.MustNot[i])) && evalBranchMatchesDoc(idxSchema, doc, &q.Bool.MustNot[i]) {
				return false
			}
		}
		if len(q.Bool.Should) > 0 {
			hasScriptShould := false
			for i := range q.Bool.Should {
				if queryHasRuntimeScript(&q.Bool.Should[i]) || queryHasMinScore(&q.Bool.Should[i]) {
					hasScriptShould = true
					break
				}
			}
			reqMin := resolveMinimumShouldMatch(q.Bool.MinimumShouldMatch, len(q.Bool.Should), len(q.Bool.Must) == 0 && len(q.Bool.Filter) == 0)
			if hasScriptShould && reqMin > 0 {
				matchedShould := 0
				for i := range q.Bool.Should {
					if evalBranchMatchesDoc(idxSchema, doc, &q.Bool.Should[i]) {
						matchedShould++
					}
				}
				if matchedShould < reqMin {
					return false
				}
			}
		}
	}
	if q.ConstantScore != nil && !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, &q.ConstantScore.Filter, baseScore) {
		return false
	}
	if q.Nested != nil && (queryHasRuntimeScript(&q.Nested.Query) || queryHasMinScore(&q.Nested.Query) || queryContainsNested(&q.Nested.Query)) {
		pathSegs := strings.Split(q.Nested.Path, ".")
		cands := extractNestedElementsAtPath(doc, pathSegs)
		nestedSchema := deriveNestedEvalSchema(idxSchema, q.Nested.Path)
		matchedAny := false
		for _, cand := range cands {
			elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
			if doc != nil {
				if metaID, ok := doc["__meta_id"].(string); ok && metaID != "" {
					elemDoc["__meta_id"] = metaID
				}
			}
			if evalBranchMatchesDoc(nestedSchema, elemDoc, &q.Nested.Query) {
				matchedAny = true
				break
			}
		}
		if !matchedAny {
			return false
		}
	}
	if q.DisMax != nil {
		hasScriptSub := false
		for i := range q.DisMax.Queries {
			if queryHasRuntimeScript(&q.DisMax.Queries[i]) || queryHasMinScore(&q.DisMax.Queries[i]) {
				hasScriptSub = true
				break
			}
		}
		if hasScriptSub {
			anyMatched := false
			for i := range q.DisMax.Queries {
				if evalBranchMatchesDoc(idxSchema, doc, &q.DisMax.Queries[i]) {
					anyMatched = true
					break
				}
			}
			if !anyMatched {
				return false
			}
		}
	}
	if q.Boosting != nil {
		if !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, &q.Boosting.Positive, baseScore) {
			return false
		}
	}
	if q.ScriptScore != nil {
		if q.ScriptScore.Query != nil && !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, q.ScriptScore.Query, baseScore) {
			return false
		}
		if q.ScriptScore.MinScore != nil && evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q, baseScore) < *q.ScriptScore.MinScore {
			return false
		}
		return true
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil && !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, q.FunctionScore.Query, baseScore) {
			return false
		}
		fsBase := baseScore
		if !queryHasRuntimeScript(q) {
			fsBase = 1.0
		}
		if q.FunctionScore.MinScore != nil && evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q, fsBase) < *q.FunctionScore.MinScore {
			return false
		}
		return true
	}
	return true
}

func evalFieldValueFactorOnDoc(idxSchema *schema.IndexSchema, doc map[string]any, fvf *esast.FieldValueFactorSpec) (float64, bool) {
	if fvf == nil || fvf.Field == "" {
		return 0, false
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(fvf.Field, ".keyword"), ".ngram")
	pathSegs := strings.Split(clean, ".")
	if idxSchema != nil {
		if b := idxSchema.ResolveField(fvf.Field); len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
		}
	}
	rawVals := collectSchemaAwareScalarValues(doc, fvf.Field, pathSegs, idxSchema)
	var rawNum float64
	found := false
	for _, rv := range rawVals {
		if f, ok := toFloat64(rv); ok {
			rawNum = f
			found = true
			break
		}
	}
	if !found {
		if fvf.Missing != nil {
			if f, ok := toFloat64(fvf.Missing); ok {
				rawNum = f
				found = true
			}
		}
		if !found {
			return 0, true
		}
	}
	factor := 1.0
	if fvf.Factor != nil {
		factor = *fvf.Factor
	}
	v := rawNum * factor
	switch strings.ToLower(strings.TrimSpace(fvf.Modifier)) {
	case "", "none":
	case "log":
		v = math.Log10(math.Max(0, v))
	case "log1p":
		v = math.Log10(math.Max(0, 1.0+v))
	case "log2p":
		v = math.Log10(math.Max(0, 2.0+v))
	case "ln":
		v = math.Log(math.Max(0, v))
	case "ln1p":
		v = math.Log(math.Max(0, 1.0+v))
	case "ln2p":
		v = math.Log(math.Max(0, 2.0+v))
	case "square":
		v = v * v
	case "sqrt":
		v = math.Sqrt(math.Max(0, v))
	case "reciprocal":
		if 1.0+v == 0 {
			return 0, true
		}
		v = 1.0 / (1.0 + v)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, true
	}
	return v, true
}

func combineFunctionScoreValues(vals []float64, scoreMode string) float64 {
	if len(vals) == 0 {
		return 1.0
	}
	switch strings.ToLower(strings.TrimSpace(scoreMode)) {
	case "sum":
		var s float64
		for _, v := range vals {
			s += v
		}
		return s
	case "avg":
		var s float64
		for _, v := range vals {
			s += v
		}
		return s / float64(len(vals))
	case "first":
		return vals[0]
	case "max":
		m := vals[0]
		for _, v := range vals[1:] {
			if v > m {
				m = v
			}
		}
		return m
	case "min":
		m := vals[0]
		for _, v := range vals[1:] {
			if v < m {
				m = v
			}
		}
		return m
	default: // "multiply"
		p := 1.0
		for _, v := range vals {
			p *= v
		}
		return p
	}
}

func applyFunctionScoreBoostMode(baseScore, funcScore float64, boostMode string) float64 {
	switch strings.ToLower(strings.TrimSpace(boostMode)) {
	case "replace":
		return funcScore
	case "sum":
		return baseScore + funcScore
	case "avg":
		return (baseScore + funcScore) / 2.0
	case "max":
		return math.Max(baseScore, funcScore)
	case "min":
		return math.Min(baseScore, funcScore)
	default: // "multiply"
		return baseScore * funcScore
	}
}

func queryHasNestedScoring(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Nested != nil {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryHasNestedScoring(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryHasNestedScoring(&q.Bool.Should[i]) {
				return true
			}
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryHasNestedScoring(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		return queryHasNestedScoring(&q.Boosting.Positive)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		return queryHasNestedScoring(q.FunctionScore.Query)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		return queryHasNestedScoring(q.ScriptScore.Query)
	}
	return false
}

func scoreNonScriptClauseOnDoc(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query) float64 {
	if q == nil {
		return 1.0
	}
	if queryHasNestedScoring(q) {
		return evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q, 1.0)
	}
	rawBytes, docID, err := marshalDocAndExtractEvalID(doc, "0")
	if err != nil {
		return 1.0
	}
	evalSchema := resolveRuntimeEvalSchema(idxSchema, doc, q, rawBytes)
	shredBytes, err := schema.ShredDocument(evalSchema, docID, 1, false, rawBytes)
	if err != nil {
		return 1.0
	}
	var row map[string]any
	rDec := json.NewDecoder(bytes.NewReader(shredBytes))
	rDec.UseNumber()
	if err := rDec.Decode(&row); err != nil {
		return 1.0
	}
	row["_doc"] = doc
	tr := transpiler.NewTranspiler(evalSchema, transpiler.TranspilerOptions{})
	cq := tr.CompileQuery(q, true, nil)
	if cq.ScoreSQL != "" {
		sc := evalNumericExpr(row, cq.ScoreSQL)
		if sc == 0 && cq.ScoreSQL == "1.0" {
			return 1.0
		}
		return sc
	}
	return 1.0
}

func evalRandomScoreOnDoc(doc map[string]any, rs *esast.RandomScoreSpec) float64 {
	if rs == nil {
		return 0.5
	}
	fieldVal := ""
	if rs.Field == "" || rs.Field == "_id" || rs.Field == "_seq_no" {
		if id, ok := doc["__meta_id"].(string); ok && id != "" {
			fieldVal = id
		} else if id, ok := doc["_id"].(string); ok {
			fieldVal = id
		}
	} else if v, exists := getIngestPath(doc, rs.Field); exists && v != nil {
		fieldVal = fmt.Sprintf("%v", v)
	}
	h := uint64(14695981039346656037)
	key := fmt.Sprintf("%v:%s", rs.Seed, fieldVal)
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return float64((h%999999)+1) / 1000000.0
}

func evalQueryScriptScoreOnDocWithSchema(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query, baseScore float64) float64 {
	if q == nil {
		return baseScore
	}
	if q.ConstantScore != nil {
		if !evalBranchMatchesDoc(idxSchema, doc, &q.ConstantScore.Filter) {
			return 0.0
		}
		if q.ConstantScore.Boost != nil {
			return *q.ConstantScore.Boost
		}
		return 1.0
	}
	if q.Script != nil {
		if !evalQueryScriptFilterOnDocWithSchema(idxSchema, doc, q) {
			return 0.0
		}
		if q.Script.Boost != nil {
			return *q.Script.Boost
		}
		return 1.0
	}
	if q.ScriptScore != nil && q.ScriptScore.Script != nil {
		if q.ScriptScore.Query != nil {
			if !evalQueryScriptFilterOnDocWithSchema(idxSchema, doc, q.ScriptScore.Query) {
				return 0.0
			}
			if queryHasRuntimeScript(q.ScriptScore.Query) || queryHasNestedScoring(q.ScriptScore.Query) || q.ScriptScore.Query.FunctionScore != nil {
				baseScore = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q.ScriptScore.Query, baseScore)
			} else if baseScore == 1.0 {
				baseScore = scoreNonScriptClauseOnDoc(idxSchema, doc, q.ScriptScore.Query)
			}
		}
		src, params := extractScriptSourceAndParams(q.ScriptScore.Script)
		if src != "" {
			cp := make(map[string]any, len(params)+1)
			for k, v := range params {
				cp[k] = v
			}
			cp["_score"] = baseScore
			evalDoc := prepareDocForRuntimeScript(idxSchema, doc)
			if fv, ok, err := painless.EvalNumber(evalDoc, src, cp); err == nil && ok {
				if q.ScriptScore.Boost != nil {
					fv *= *q.ScriptScore.Boost
				}
				if q.ScriptScore.MinScore != nil && fv < *q.ScriptScore.MinScore {
					return fv
				}
				return fv
			}
		}
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil {
			if !evalQueryScriptFilterOnDocWithSchema(idxSchema, doc, q.FunctionScore.Query) {
				return 0.0
			}
			if queryHasRuntimeScript(q.FunctionScore.Query) || queryHasNestedScoring(q.FunctionScore.Query) || q.FunctionScore.Query.FunctionScore != nil {
				baseScore = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q.FunctionScore.Query, baseScore)
			} else if baseScore == 1.0 {
				baseScore = scoreNonScriptClauseOnDoc(idxSchema, doc, q.FunctionScore.Query)
			}
		}
		evalDoc := prepareDocForRuntimeScript(idxSchema, doc)
		var fnScores []float64
		if q.FunctionScore.ScriptScore != nil && q.FunctionScore.ScriptScore.Script != nil {
			src, params := extractScriptSourceAndParams(q.FunctionScore.ScriptScore.Script)
			if src != "" {
				cp := make(map[string]any, len(params)+1)
				for k, v := range params {
					cp[k] = v
				}
				cp["_score"] = baseScore
				if fv, ok, err := painless.EvalNumber(evalDoc, src, cp); err == nil && ok {
					if q.FunctionScore.Weight != nil {
						fv *= *q.FunctionScore.Weight
					}
					fnScores = append(fnScores, fv)
				}
			}
		}
		if q.FunctionScore.FieldValueFactor != nil {
			if fv, ok := evalFieldValueFactorOnDoc(idxSchema, doc, q.FunctionScore.FieldValueFactor); ok {
				if q.FunctionScore.Weight != nil {
					fv *= *q.FunctionScore.Weight
				}
				fnScores = append(fnScores, fv)
			}
		} else if q.FunctionScore.RandomScore != nil {
			fv := evalRandomScoreOnDoc(doc, q.FunctionScore.RandomScore)
			if q.FunctionScore.Weight != nil {
				fv *= *q.FunctionScore.Weight
			}
			fnScores = append(fnScores, fv)
		} else if q.FunctionScore.ScriptScore == nil && len(q.FunctionScore.Functions) == 0 && q.FunctionScore.Weight != nil {
			fnScores = append(fnScores, *q.FunctionScore.Weight)
		}
		for _, fn := range q.FunctionScore.Functions {
			if fn.Filter != nil && !evalBranchMatchesDoc(idxSchema, doc, fn.Filter) {
				continue
			}
			hasVal := false
			val := 1.0
			if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
				src, params := extractScriptSourceAndParams(fn.ScriptScore.Script)
				if src != "" {
					cp := make(map[string]any, len(params)+1)
					for k, v := range params {
						cp[k] = v
					}
					cp["_score"] = baseScore
					if fv, ok, err := painless.EvalNumber(evalDoc, src, cp); err == nil && ok {
						val = fv
						hasVal = true
					}
				}
			} else if fn.FieldValueFactor != nil {
				if fv, ok := evalFieldValueFactorOnDoc(idxSchema, doc, fn.FieldValueFactor); ok {
					val = fv
					hasVal = true
				}
			} else if fn.RandomScore != nil {
				val = evalRandomScoreOnDoc(doc, fn.RandomScore)
				hasVal = true
			}
			if fn.Weight != nil {
				if hasVal {
					val *= *fn.Weight
				} else {
					val = *fn.Weight
					hasVal = true
				}
			}
			if hasVal {
				fnScores = append(fnScores, val)
				if strings.EqualFold(q.FunctionScore.ScoreMode, "first") {
					break
				}
			}
		}
		if len(fnScores) > 0 {
			combined := combineFunctionScoreValues(fnScores, q.FunctionScore.ScoreMode)
			if q.FunctionScore.MaxBoost != nil && combined > *q.FunctionScore.MaxBoost {
				combined = *q.FunctionScore.MaxBoost
			}
			res := applyFunctionScoreBoostMode(baseScore, combined, q.FunctionScore.BoostMode)
			if q.FunctionScore.Boost != nil {
				res *= *q.FunctionScore.Boost
			}
			return res
		}
		combined := 1.0
		if q.FunctionScore.MaxBoost != nil && combined > *q.FunctionScore.MaxBoost {
			combined = *q.FunctionScore.MaxBoost
		}
		res := applyFunctionScoreBoostMode(baseScore, combined, q.FunctionScore.BoostMode)
		if q.FunctionScore.Boost != nil {
			res *= *q.FunctionScore.Boost
		}
		return res
	}
	if q.DisMax != nil {
		var scores []float64
		for i := range q.DisMax.Queries {
			sub := &q.DisMax.Queries[i]
			if evalBranchMatchesDoc(idxSchema, doc, sub) {
				var sc float64
				if queryHasRuntimeScript(sub) || queryHasNestedScoring(sub) || sub.FunctionScore != nil {
					sc = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, sub, 1.0)
				} else {
					sc = scoreNonScriptClauseOnDoc(idxSchema, doc, sub)
				}
				scores = append(scores, sc)
			}
		}
		if len(scores) > 0 {
			sort.Float64s(scores)
			best := scores[len(scores)-1]
			var rest float64
			for _, s := range scores[:len(scores)-1] {
				rest += s
			}
			res := best + q.DisMax.TieBreaker*rest
			if q.DisMax.Boost != nil {
				res *= *q.DisMax.Boost
			}
			return res
		}
		return 0.0
	}
	if q.Boosting != nil {
		if !evalBranchMatchesDoc(idxSchema, doc, &q.Boosting.Positive) {
			return 0.0
		}
		var posScore float64
		if queryHasRuntimeScript(&q.Boosting.Positive) || queryHasNestedScoring(&q.Boosting.Positive) || q.Boosting.Positive.FunctionScore != nil {
			posScore = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, &q.Boosting.Positive, 1.0)
		} else {
			posScore = scoreNonScriptClauseOnDoc(idxSchema, doc, &q.Boosting.Positive)
		}
		res := posScore
		if evalBranchMatchesDoc(idxSchema, doc, &q.Boosting.Negative) {
			res *= q.Boosting.EffectiveNegativeBoost()
		}
		if q.Boosting.Boost != nil {
			res *= *q.Boosting.Boost
		}
		return res
	}
	if q.Nested != nil {
		if strings.EqualFold(strings.TrimSpace(q.Nested.ScoreMode), "none") {
			return 0.0
		}
		pathSegs := strings.Split(q.Nested.Path, ".")
		cands := extractNestedElementsAtPath(doc, pathSegs)
		nestedSchema := deriveNestedEvalSchema(idxSchema, q.Nested.Path)
		var elemScores []float64
		for _, cand := range cands {
			elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
			if doc != nil {
				if metaID, ok := doc["__meta_id"].(string); ok && metaID != "" {
					elemDoc["__meta_id"] = metaID
				}
			}
			if evalBranchMatchesDoc(nestedSchema, elemDoc, &q.Nested.Query) {
				var sc float64
				if queryHasRuntimeScript(&q.Nested.Query) || queryHasNestedScoring(&q.Nested.Query) || q.Nested.Query.FunctionScore != nil {
					sc = evalQueryScriptScoreOnDocWithSchema(nestedSchema, elemDoc, &q.Nested.Query, 1.0)
				} else {
					sc = scoreNonScriptClauseOnDoc(nestedSchema, elemDoc, &q.Nested.Query)
				}
				elemScores = append(elemScores, sc)
			}
		}
		if len(elemScores) > 0 {
			var res float64
			switch strings.ToLower(strings.TrimSpace(q.Nested.ScoreMode)) {
			case "none":
				return 0.0
			case "sum":
				for _, s := range elemScores {
					res += s
				}
			case "max":
				res = elemScores[0]
				for _, s := range elemScores[1:] {
					if s > res {
						res = s
					}
				}
			case "min":
				res = elemScores[0]
				for _, s := range elemScores[1:] {
					if s < res {
						res = s
					}
				}
			default: // "avg"
				for _, s := range elemScores {
					res += s
				}
				res /= float64(len(elemScores))
			}
			if q.Nested.Boost != nil {
				res *= *q.Nested.Boost
			}
			return res
		}
		return 0.0
	}
	if q.Bool != nil {
		if !evalBranchMatchesDoc(idxSchema, doc, q) {
			return 0.0
		}
		var total float64
		hasScored := false
		for i := range q.Bool.Must {
			if queryHasRuntimeScript(&q.Bool.Must[i]) || queryHasNestedScoring(&q.Bool.Must[i]) || q.Bool.Must[i].FunctionScore != nil {
				total += evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, &q.Bool.Must[i], 1.0)
				hasScored = true
			} else {
				total += scoreNonScriptClauseOnDoc(idxSchema, doc, &q.Bool.Must[i])
				hasScored = true
			}
		}
		for i := range q.Bool.Should {
			if evalBranchMatchesDoc(idxSchema, doc, &q.Bool.Should[i]) {
				if queryHasRuntimeScript(&q.Bool.Should[i]) || queryHasNestedScoring(&q.Bool.Should[i]) || q.Bool.Should[i].FunctionScore != nil {
					total += evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, &q.Bool.Should[i], 1.0)
				} else {
					total += scoreNonScriptClauseOnDoc(idxSchema, doc, &q.Bool.Should[i])
				}
				hasScored = true
			}
		}
		if hasScored {
			if q.Bool.Boost != nil {
				total *= *q.Bool.Boost
			}
			return total
		}
		if q.Bool.Boost != nil {
			return *q.Bool.Boost
		}
		return 1.0
	}
	return baseScore
}

type runtimeNestedAncestor struct {
	doc    map[string]any
	schema *schema.IndexSchema
	elemID string
}

type runtimeMatchedDoc struct {
	hit             HitRow
	doc             map[string]any
	rootDoc         map[string]any
	rootSchema      *schema.IndexSchema
	nestedAncestors map[string]runtimeNestedAncestor
}

func (md runtimeMatchedDoc) EffectiveSchema(fallback *schema.IndexSchema) *schema.IndexSchema {
	if md.hit.Schema != nil {
		return md.hit.Schema
	}
	if md.rootSchema != nil {
		return md.rootSchema
	}
	return fallback
}

func computeRuntimeTermsScriptBucketDocsWithSchema(idxSchema *schema.IndexSchema, docs []runtimeMatchedDoc, tSpec *esast.TermsAggSpec) (map[string][]runtimeMatchedDoc, []string) {
	byBucket := make(map[string][]runtimeMatchedDoc)
	var keys []string
	seenKey := make(map[string]bool)
	addBucket := func(k string, d runtimeMatchedDoc) {
		if k == "" {
			return
		}
		if !seenKey[k] {
			seenKey[k] = true
			keys = append(keys, k)
		}
		byBucket[k] = append(byBucket[k], d)
	}
	src, _ := extractScriptSourceAndParams(tSpec.Script)
	missingStr := ""
	if tSpec.Missing != nil {
		missingStr = fmt.Sprintf("%v", tSpec.Missing)
	}
	for _, md := range docs {
		effSchema := md.EffectiveSchema(idxSchema)
		var fieldBinding schema.FieldBinding
		hasFieldBinding := false
		if effSchema != nil && tSpec.Field != "" {
			fieldBinding = effSchema.ResolveField(tSpec.Field)
			hasFieldBinding = true
		}
		var vals []string
		if src != "" {
			rawVals := extractDocRawValuesForMetric(md, &esast.MetricAggSpec{
				Field:   tSpec.Field,
				Missing: tSpec.Missing,
				Script:  tSpec.Script,
			})
			for _, el := range rawVals {
				if el != nil {
					s := fmt.Sprintf("%v", el)
					if s != "" {
						vals = append(vals, s)
					}
				}
			}
		} else if tSpec.Field != "" {
			clean := strings.TrimSuffix(strings.TrimSuffix(tSpec.Field, ".keyword"), ".ngram")
			pathSegs := strings.Split(clean, ".")
			if hasFieldBinding && len(fieldBinding.SourceJSONPath) > 0 {
				pathSegs = fieldBinding.SourceJSONPath
			}
			nowUTC := time.Now().UTC()
			for _, rv := range collectSchemaAwareScalarValues(md.doc, tSpec.Field, pathSegs, effSchema) {
				if rv != nil {
					s := fmt.Sprintf("%v", rv)
					if s != "" {
						if hasFieldBinding {
							if fieldBinding.ESType == "date" || fieldBinding.ESType == "date_nanos" {
								trimmed := strings.TrimSpace(s)
								if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
									if fieldBinding.ESType == "date_nanos" && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
										iv /= 1_000_000
									}
									s = strconv.FormatInt(iv, 10)
								} else if ms, ok := schema.ParseESDateToEpochMillis(trimmed, nowUTC); ok {
									s = strconv.FormatInt(ms, 10)
								}
							} else if fieldBinding.ESType == "boolean" || fieldBinding.DorisType == schema.DorisBoolean {
								switch strings.ToLower(strings.TrimSpace(s)) {
								case "1", "true":
									s = "true"
								case "0", "false":
									s = "false"
								}
							}
							if fieldBinding.EffectiveLowercase(!strings.HasSuffix(tSpec.Field, ".keyword")) {
								s = strings.ToLower(s)
							}
						}
						vals = append(vals, s)
					}
				}
			}
		}
		if len(vals) == 0 {
			if missingStr != "" {
				vals = []string{missingStr}
			} else if tSpec.MissingBucket {
				vals = []string{"__ES_MISSING_BUCKET__"}
			}
		}
		seenDocVal := make(map[string]bool, len(vals))
		for _, v := range vals {
			if !seenDocVal[v] {
				seenDocVal[v] = true
				addBucket(v, md)
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		ci, cj := len(byBucket[keys[i]]), len(byBucket[keys[j]])
		if ci != cj {
			return ci > cj
		}
		return keys[i] < keys[j]
	})
	return byBucket, keys
}

var reScriptDocFieldRef = regexp.MustCompile(`doc\[['"]([^'"]+)['"]\]([a-zA-Z0-9_.(\[]*)`)

func scriptHasMissingDocValueRef(doc map[string]any, src string) (string, bool) {
	if strings.Contains(src, ".size()") || strings.Contains(src, ".empty") || strings.Contains(src, ".length") || strings.Contains(src, "containsKey") {
		return "", false
	}
	matches := reScriptDocFieldRef.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		rawField := strings.TrimSuffix(strings.TrimSuffix(m[1], ".keyword"), ".ngram")
		tail := ""
		if len(m) >= 3 {
			tail = m[2]
		}
		if strings.HasPrefix(tail, ".size") || strings.HasPrefix(tail, ".empty") || strings.HasPrefix(tail, ".length") {
			continue
		}
		if (rawField == "_id" && doc["__meta_id"] != nil) ||
			(rawField == "_index" && doc["__meta_index"] != nil) ||
			(rawField == "_version" && doc["__meta_version"] != nil) {
			continue
		}
		if len(collectScalarValuesAtPath(doc, strings.Split(rawField, "."))) == 0 {
			return rawField, true
		}
	}
	return "", false
}

func cloneDocWithFieldPath(doc map[string]any, dotPath string, val any) map[string]any {
	cp := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		cp[k] = v
	}
	setIngestPath(cp, dotPath, val)
	return cp
}

func extractDocRawValuesForMetric(md runtimeMatchedDoc, mSpec *esast.MetricAggSpec) []any {
	if mSpec == nil {
		return nil
	}
	effSchema := md.EffectiveSchema(nil)
	if mSpec.Script != nil {
		src, params := extractScriptSourceAndParams(mSpec.Script)
		if src == "" {
			return nil
		}
		evalDoc := prepareDocForRuntimeScript(effSchema, md.doc)
		if mSpec.Field != "" {
			clean := strings.TrimSuffix(strings.TrimSuffix(mSpec.Field, ".keyword"), ".ngram")
			pathSegs := strings.Split(clean, ".")
			if effSchema != nil {
				if b := effSchema.ResolveField(mSpec.Field); len(b.SourceJSONPath) > 0 {
					pathSegs = b.SourceJSONPath
				}
			}
			rawVals := collectSchemaAwareScalarValues(md.doc, mSpec.Field, pathSegs, effSchema)
			if len(rawVals) == 0 && mSpec.Missing != nil {
				rawVals = []any{mSpec.Missing}
			}
			if len(rawVals) > 0 && strings.Contains(src, "_value") {
				var out []any
				for _, rv := range rawVals {
					cp := make(map[string]any, len(params)+2)
					for k, v := range params {
						cp[k] = v
					}
					cp["_value"] = rv
					cp["_score"] = md.hit.Score
					if v, err := painless.Eval(evalDoc, src, cp); err == nil && v != nil {
						if arr, ok := v.([]any); ok {
							out = append(out, arr...)
						} else {
							out = append(out, v)
						}
					}
				}
				return out
			}
			if len(rawVals) == 0 && strings.Contains(src, "_value") {
				return nil
			}
		}
		if missField, isMiss := scriptHasMissingDocValueRef(evalDoc, src); isMiss {
			if mSpec.Missing == nil {
				return nil
			}
			evalDoc = cloneDocWithFieldPath(evalDoc, missField, mSpec.Missing)
		}
		cp := make(map[string]any, len(params)+1)
		for k, v := range params {
			cp[k] = v
		}
		cp["_score"] = md.hit.Score
		if v, err := painless.Eval(evalDoc, src, cp); err == nil && v != nil {
			if arr, ok := v.([]any); ok {
				return arr
			}
			return []any{v}
		}
		return nil
	}
	if mSpec.Field == "" {
		return nil
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(mSpec.Field, ".keyword"), ".ngram")
	pathSegs := strings.Split(clean, ".")
	if effSchema != nil {
		if b := effSchema.ResolveField(mSpec.Field); len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
		}
	}
	rawVals := collectSchemaAwareScalarValues(md.doc, mSpec.Field, pathSegs, effSchema)
	if len(rawVals) == 0 && mSpec.Missing != nil {
		rawVals = []any{mSpec.Missing}
	}
	return rawVals
}

func extractDocNumericValuesForMetric(md runtimeMatchedDoc, mSpec *esast.MetricAggSpec) []float64 {
	rawVals := extractDocRawValuesForMetric(md, mSpec)
	var nums []float64
	for _, rv := range rawVals {
		if f, ok := toFloat64(rv); ok {
			nums = append(nums, f)
		}
	}
	return nums
}

func computeRuntimeInterpolatedPercentile(sortedVals []float64, pct float64) float64 {
	if len(sortedVals) == 0 {
		return 0
	}
	if pct <= 0 {
		return sortedVals[0]
	}
	if pct >= 100 {
		return sortedVals[len(sortedVals)-1]
	}
	pos := (pct / 100.0) * float64(len(sortedVals)-1)
	lower := int(math.Floor(pos))
	upper := int(math.Ceil(pos))
	if lower == upper || upper >= len(sortedVals) {
		return sortedVals[lower]
	}
	weight := pos - float64(lower)
	return sortedVals[lower]*(1-weight) + sortedVals[upper]*weight
}

func emitRuntimeMetricAggRows(
	fullAggName string,
	parentBucketKey string,
	subSpec esast.AggSpec,
	bDocs []runtimeMatchedDoc,
	out *[]AggRow,
) {
	metricBucketKey := parentBucketKey
	if metricBucketKey == "" {
		metricBucketKey = "_metric"
	}
	switch {
	case subSpec.Avg != nil || subSpec.Sum != nil || subSpec.Min != nil || subSpec.Max != nil:
		var mSpec *esast.MetricAggSpec
		switch {
		case subSpec.Avg != nil:
			mSpec = subSpec.Avg
		case subSpec.Sum != nil:
			mSpec = subSpec.Sum
		case subSpec.Min != nil:
			mSpec = subSpec.Min
		case subSpec.Max != nil:
			mSpec = subSpec.Max
		}
		var vals []float64
		for _, d := range bDocs {
			vals = append(vals, extractDocNumericValuesForMetric(d, mSpec)...)
		}
		if len(vals) > 0 || subSpec.Sum != nil {
			var res float64
			if len(vals) > 0 {
				switch {
				case subSpec.Sum != nil:
					for _, v := range vals {
						res += v
					}
				case subSpec.Avg != nil:
					for _, v := range vals {
						res += v
					}
					res /= float64(len(vals))
				case subSpec.Min != nil:
					res = vals[0]
					for _, v := range vals[1:] {
						if v < res {
							res = v
						}
					}
				case subSpec.Max != nil:
					res = vals[0]
					for _, v := range vals[1:] {
						if v > res {
							res = v
						}
					}
				}
			}
			*out = append(*out, AggRow{
				AggName:   fullAggName,
				BucketKey: metricBucketKey,
				DocCount:  int64(res),
				Value:     res,
				Weight:    int64(len(vals)),
			})
		} else if subSpec.Avg != nil || subSpec.Min != nil || subSpec.Max != nil {
			*out = append(*out, AggRow{
				AggName:   fullAggName,
				BucketKey: metricBucketKey,
				DocCount:  0,
				Value:     0,
				Weight:    -1,
			})
		}
	case subSpec.ValueCount != nil || subSpec.Cardinality != nil:
		mSpec := subSpec.ValueCount
		isCard := false
		if subSpec.Cardinality != nil {
			mSpec = subSpec.Cardinality
			isCard = true
		}
		seen := make(map[string]bool)
		var valCnt int64
		for _, d := range bDocs {
			rVals := extractDocRawValuesForMetric(d, mSpec)
			for _, rv := range rVals {
				if rv != nil {
					valCnt++
					seen[fmt.Sprintf("%v", rv)] = true
				}
			}
		}
		resCnt := valCnt
		if isCard {
			resCnt = int64(len(seen))
		}
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: metricBucketKey,
			DocCount:  resCnt,
			Value:     float64(resCnt),
		})
	case subSpec.EffectiveStats() != nil:
		mSpec := subSpec.EffectiveStats()
		var vals []float64
		for _, d := range bDocs {
			vals = append(vals, extractDocNumericValuesForMetric(d, mSpec)...)
		}
		sCnt := int64(len(vals))
		w := sCnt
		if sCnt == 0 {
			w = -1
		}
		var sMin, sMax, sSum, sAvg, sSumSq, sStd float64
		if sCnt > 0 {
			sMin, sMax = vals[0], vals[0]
			for _, v := range vals {
				if v < sMin {
					sMin = v
				}
				if v > sMax {
					sMax = v
				}
				sSum += v
				sSumSq += v * v
			}
			sAvg = sSum / float64(sCnt)
			variance := (sSumSq / float64(sCnt)) - (sAvg * sAvg)
			if variance > 0 {
				sStd = math.Sqrt(variance)
			}
		}
		if parentBucketKey == "" {
			*out = append(*out,
				AggRow{AggName: fullAggName, BucketKey: "_stats_count", DocCount: sCnt, Value: float64(sCnt)},
				AggRow{AggName: fullAggName, BucketKey: "_stats_min", DocCount: int64(sMin), Value: sMin, Weight: w},
				AggRow{AggName: fullAggName, BucketKey: "_stats_max", DocCount: int64(sMax), Value: sMax, Weight: w},
				AggRow{AggName: fullAggName, BucketKey: "_stats_avg", DocCount: int64(sAvg), Value: sAvg, Weight: w},
				AggRow{AggName: fullAggName, BucketKey: "_stats_sum", DocCount: int64(sSum), Value: sSum},
			)
			if subSpec.ExtendedStats != nil {
				*out = append(*out,
					AggRow{AggName: fullAggName, BucketKey: "_stats_sum_sq", DocCount: int64(sSumSq), Value: sSumSq},
					AggRow{AggName: fullAggName, BucketKey: "_stats_std", DocCount: int64(sStd), Value: sStd, Weight: w},
				)
			}
		} else {
			*out = append(*out,
				AggRow{AggName: fullAggName + "._stats_count", BucketKey: parentBucketKey, DocCount: sCnt, Value: float64(sCnt)},
				AggRow{AggName: fullAggName + "._stats_min", BucketKey: parentBucketKey, DocCount: int64(sMin), Value: sMin, Weight: w},
				AggRow{AggName: fullAggName + "._stats_max", BucketKey: parentBucketKey, DocCount: int64(sMax), Value: sMax, Weight: w},
				AggRow{AggName: fullAggName + "._stats_avg", BucketKey: parentBucketKey, DocCount: int64(sAvg), Value: sAvg, Weight: w},
				AggRow{AggName: fullAggName + "._stats_sum", BucketKey: parentBucketKey, DocCount: int64(sSum), Value: sSum},
			)
			if subSpec.ExtendedStats != nil {
				*out = append(*out,
					AggRow{AggName: fullAggName + "._stats_sum_sq", BucketKey: parentBucketKey, DocCount: int64(sSumSq), Value: sSumSq},
					AggRow{AggName: fullAggName + "._stats_std", BucketKey: parentBucketKey, DocCount: int64(sStd), Value: sStd, Weight: w},
				)
			}
		}
	case subSpec.Percentiles != nil:
		mSpec := &esast.MetricAggSpec{
			Field:   subSpec.Percentiles.Field,
			Missing: subSpec.Percentiles.Missing,
			Script:  subSpec.Percentiles.Script,
		}
		var vals []float64
		for _, d := range bDocs {
			vals = append(vals, extractDocNumericValuesForMetric(d, mSpec)...)
		}
		sort.Float64s(vals)
		w := int64(len(vals))
		if len(vals) == 0 {
			w = -1
		}
		for _, pct := range subSpec.Percentiles.EffectivePercents() {
			res := computeRuntimeInterpolatedPercentile(vals, pct)
			pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
			if !strings.Contains(pctKey, ".") {
				pctKey += ".0"
			}
			if parentBucketKey == "" {
				*out = append(*out, AggRow{AggName: fullAggName, BucketKey: pctKey, DocCount: int64(res), Value: res, Weight: w})
			} else {
				*out = append(*out, AggRow{AggName: fullAggName + "." + pctKey, BucketKey: parentBucketKey, DocCount: int64(res), Value: res, Weight: w})
			}
		}
	case subSpec.Boxplot != nil:
		var vals []float64
		for _, d := range bDocs {
			vals = append(vals, extractDocNumericValuesForMetric(d, subSpec.Boxplot)...)
		}
		sort.Float64s(vals)
		w := int64(len(vals))
		if len(vals) == 0 {
			w = -1
		}
		for _, pct := range []float64{0.0, 25.0, 50.0, 75.0, 100.0} {
			res := computeRuntimeInterpolatedPercentile(vals, pct)
			pctKey := fmt.Sprintf("%.1f", pct)
			if parentBucketKey == "" {
				*out = append(*out, AggRow{AggName: fullAggName, BucketKey: pctKey, DocCount: int64(res), Value: res, Weight: w})
			} else {
				*out = append(*out, AggRow{AggName: fullAggName + "." + pctKey, BucketKey: parentBucketKey, DocCount: int64(res), Value: res, Weight: w})
			}
		}
	case subSpec.PercentileRanks != nil:
		mSpec := &esast.MetricAggSpec{
			Field:   subSpec.PercentileRanks.Field,
			Missing: subSpec.PercentileRanks.Missing,
			Script:  subSpec.PercentileRanks.Script,
		}
		var vals []float64
		for _, d := range bDocs {
			vals = append(vals, extractDocNumericValuesForMetric(d, mSpec)...)
		}
		w := int64(len(vals))
		if len(vals) == 0 {
			w = -1
		}
		for _, thresh := range subSpec.PercentileRanks.Values {
			var leCount int64
			for _, v := range vals {
				if v <= thresh {
					leCount++
				}
			}
			var res float64
			if len(vals) > 0 {
				res = float64(leCount) * 100.0 / float64(len(vals))
			}
			valKey := strconv.FormatFloat(thresh, 'f', -1, 64)
			if !strings.Contains(valKey, ".") {
				valKey += ".0"
			}
			if parentBucketKey == "" {
				*out = append(*out, AggRow{AggName: fullAggName, BucketKey: valKey, DocCount: int64(res), Value: res, Weight: w})
			} else {
				*out = append(*out, AggRow{AggName: fullAggName + "." + valKey, BucketKey: parentBucketKey, DocCount: int64(res), Value: res, Weight: w})
			}
		}
	case subSpec.StringStats != nil:
		mSpec := &esast.MetricAggSpec{
			Field:   subSpec.StringStats.Field,
			Missing: subSpec.StringStats.Missing,
			Script:  subSpec.StringStats.Script,
		}
		var strs []string
		for _, d := range bDocs {
			for _, rv := range extractDocRawValuesForMetric(d, mSpec) {
				if rv != nil {
					strs = append(strs, fmt.Sprintf("%v", rv))
				}
			}
		}
		sCnt := int64(len(strs))
		w := sCnt
		if sCnt == 0 {
			w = -1
		}
		var minLen, maxLen, avgLen, entropy float64
		if sCnt > 0 {
			firstLen := float64(len([]rune(strs[0])))
			minLen, maxLen = firstLen, firstLen
			var sumLen float64
			charCounts := make(map[rune]int64)
			var totalChars int64
			for _, s := range strs {
				runes := []rune(s)
				l := float64(len(runes))
				if l < minLen {
					minLen = l
				}
				if l > maxLen {
					maxLen = l
				}
				sumLen += l
				for _, ch := range runes {
					charCounts[ch]++
					totalChars++
				}
			}
			avgLen = sumLen / float64(sCnt)
			if totalChars > 0 {
				for _, c := range charCounts {
					p := float64(c) / float64(totalChars)
					if p > 0 {
						entropy -= p * math.Log2(p)
					}
				}
			}
		}
		if parentBucketKey == "" {
			*out = append(*out,
				AggRow{AggName: fullAggName, BucketKey: "_sstats_count", DocCount: sCnt, Value: float64(sCnt)},
				AggRow{AggName: fullAggName, BucketKey: "_sstats_min", DocCount: int64(minLen), Value: minLen, Weight: w},
				AggRow{AggName: fullAggName, BucketKey: "_sstats_max", DocCount: int64(maxLen), Value: maxLen, Weight: w},
				AggRow{AggName: fullAggName, BucketKey: "_sstats_avg", DocCount: int64(avgLen), Value: avgLen, Weight: w},
				AggRow{AggName: fullAggName, BucketKey: "_sstats_entropy", DocCount: int64(entropy), Value: entropy, Weight: w},
			)
		} else {
			*out = append(*out,
				AggRow{AggName: fullAggName + "._sstats_count", BucketKey: parentBucketKey, DocCount: sCnt, Value: float64(sCnt)},
				AggRow{AggName: fullAggName + "._sstats_min", BucketKey: parentBucketKey, DocCount: int64(minLen), Value: minLen, Weight: w},
				AggRow{AggName: fullAggName + "._sstats_max", BucketKey: parentBucketKey, DocCount: int64(maxLen), Value: maxLen, Weight: w},
				AggRow{AggName: fullAggName + "._sstats_avg", BucketKey: parentBucketKey, DocCount: int64(avgLen), Value: avgLen, Weight: w},
				AggRow{AggName: fullAggName + "._sstats_entropy", BucketKey: parentBucketKey, DocCount: int64(entropy), Value: entropy, Weight: w},
			)
		}
	case subSpec.Rate != nil:
		var res float64
		isValCount := strings.EqualFold(strings.TrimSpace(subSpec.Rate.Mode), "value_count")
		if subSpec.Rate.Field != "" || subSpec.Rate.Script != nil {
			mSpec := &esast.MetricAggSpec{
				Field:  subSpec.Rate.Field,
				Script: subSpec.Rate.Script,
			}
			for _, d := range bDocs {
				if isValCount {
					for _, rv := range extractDocRawValuesForMetric(d, mSpec) {
						if rv != nil {
							res++
						}
					}
				} else {
					for _, v := range extractDocNumericValuesForMetric(d, mSpec) {
						res += v
					}
				}
			}
		} else {
			res = float64(len(bDocs))
		}
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: metricBucketKey,
			DocCount:  int64(res),
			Value:     res,
			Weight:    int64(len(bDocs)),
		})
	case subSpec.TopHits != nil || subSpec.TopMetrics != nil:
		for _, d := range bDocs {
			docKey := d.hit.ID
			if d.hit.Index != "" {
				docKey = d.hit.Index + "\x00" + d.hit.ID
			}
			bKey := docKey
			if parentBucketKey != "" {
				bKey = parentBucketKey + "\x1f" + docKey
			}
			*out = append(*out, AggRow{
				AggName:   fullAggName,
				BucketKey: bKey,
				DocCount:  1,
				Value:     1,
			})
		}
	case subSpec.ScriptedMetric != nil:
		smRes, smCombined := evalScriptedMetricCombineAndReduce(subSpec.ScriptedMetric, bDocs)
		rawJSON, _ := json.Marshal(smRes)
		rawCombJSON, _ := json.Marshal(smCombined)
		numVal, _ := toFloat64(smRes)
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: metricBucketKey + "\x00" + string(rawJSON) + "\x00" + string(rawCombJSON),
			DocCount:  int64(numVal),
			Value:     numVal,
		})
	case subSpec.WeightedAvg != nil:
		emitRuntimeWeightedAvgAggRows(fullAggName, metricBucketKey, subSpec.WeightedAvg, bDocs, out)
	case subSpec.MedianAbsoluteDeviation != nil:
		emitRuntimeMADAggRows(fullAggName, metricBucketKey, subSpec.MedianAbsoluteDeviation, bDocs, out)
	case subSpec.GeoBounds != nil:
		emitRuntimeGeoBoundsAggRows(fullAggName, metricBucketKey, subSpec.GeoBounds, bDocs, out)
	case subSpec.GeoCentroid != nil:
		emitRuntimeGeoCentroidAggRows(fullAggName, metricBucketKey, subSpec.GeoCentroid, bDocs, out)
	case subSpec.MatrixStats != nil:
		emitRuntimeMatrixStatsAggRows(fullAggName, metricBucketKey, subSpec.MatrixStats, bDocs, out)
	case subSpec.TTest != nil:
		emitRuntimeTTestAggRows(fullAggName, metricBucketKey, subSpec.TTest, bDocs, out)
	}
}

func emitRuntimeJSONMetricRow(fullAggName, metricBucketKey string, obj map[string]any, numVal float64, out *[]AggRow) {
	rawJSON, _ := json.Marshal(obj)
	*out = append(*out, AggRow{
		AggName:   fullAggName,
		BucketKey: metricBucketKey + "\x00" + string(rawJSON),
		DocCount:  1,
		Value:     numVal,
	})
}

func emitRuntimeWeightedAvgAggRows(fullAggName, metricBucketKey string, spec *esast.WeightedAvgAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	valSpec := &esast.MetricAggSpec{
		Field:   spec.Value.Field,
		Missing: spec.Value.Missing,
		Script:  spec.Value.Script,
	}
	weightSpec := &esast.MetricAggSpec{
		Field:   spec.Weight.Field,
		Missing: spec.Weight.Missing,
		Script:  spec.Weight.Script,
	}
	var weightedSum, weightTotal float64
	hasVal := false
	for _, md := range bDocs {
		vals := extractDocNumericValuesForMetric(md, valSpec)
		weights := extractDocNumericValuesForMetric(md, weightSpec)
		if len(vals) == 0 || len(weights) == 0 {
			continue
		}
		var w float64
		for _, wv := range weights {
			w += wv
		}
		w /= float64(len(weights))
		for _, v := range vals {
			weightedSum += v * w
			weightTotal += w
			hasVal = true
		}
	}
	if !hasVal || weightTotal == 0 {
		obj := map[string]any{"value": nil}
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, 0, out)
		return
	}
	val := weightedSum / weightTotal
	obj := map[string]any{"value": val}
	if spec.Format != "" {
		obj["value_as_string"] = strconv.FormatFloat(val, 'f', -1, 64)
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, val, out)
}

func emitRuntimeMADAggRows(fullAggName, metricBucketKey string, spec *esast.MetricAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var vals []float64
	for _, d := range bDocs {
		vals = append(vals, extractDocNumericValuesForMetric(d, spec)...)
	}
	if len(vals) == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": nil}, 0, out)
		return
	}
	sort.Float64s(vals)
	med := computeRuntimeInterpolatedPercentile(vals, 50.0)
	devs := make([]float64, len(vals))
	for i, v := range vals {
		devs[i] = math.Abs(v - med)
	}
	sort.Float64s(devs)
	mad := computeRuntimeInterpolatedPercentile(devs, 50.0)
	obj := map[string]any{"value": mad}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, mad, out)
}

func extractGeoBoundingBoxMapCoords(bounds map[string]any) (topLat, leftLon, botLat, rightLon float64, ok bool) {
	if len(bounds) == 0 {
		return 0, 0, 0, 0, false
	}
	if tl, hasTL := bounds["top_left"]; hasTL {
		if br, hasBR := bounds["bottom_right"]; hasBR {
			lat1, lon1, ok1 := parseGeoPointLatLon(tl)
			lat2, lon2, ok2 := parseGeoPointLatLon(br)
			if ok1 && ok2 {
				return lat1, lon1, lat2, lon2, true
			}
		}
	}
	if tr, hasTR := bounds["top_right"]; hasTR {
		if bl, hasBL := bounds["bottom_left"]; hasBL {
			lat1, lon2, ok1 := parseGeoPointLatLon(tr)
			lat2, lon1, ok2 := parseGeoPointLatLon(bl)
			if ok1 && ok2 {
				return lat1, lon1, lat2, lon2, true
			}
		}
	}
	tLat, okT := toFloat64(bounds["top"])
	lLon, okL := toFloat64(bounds["left"])
	bLat, okB := toFloat64(bounds["bottom"])
	rLon, okR := toFloat64(bounds["right"])
	if okT && okL && okB && okR {
		return tLat, lLon, bLat, rLon, true
	}
	return 0, 0, 0, 0, false
}

func geoPointInBox(lat, lon, topLat, leftLon, botLat, rightLon float64) bool {
	if lat > topLat || lat < botLat {
		return false
	}
	if leftLon <= rightLon {
		return lon >= leftLon && lon <= rightLon
	}
	return lon >= leftLon || lon <= rightLon
}

func extractDocGeoPoints(md runtimeMatchedDoc, field string) [][2]float64 {
	if field == "" {
		return nil
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
	pathSegs := strings.Split(clean, ".")
	if effSchema := md.EffectiveSchema(nil); effSchema != nil {
		if b := effSchema.ResolveField(field); len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
		}
	}
	return collectGeoPointsAtPath(md.doc, pathSegs)
}

func emitRuntimeGeoBoundsAggRows(fullAggName, metricBucketKey string, spec *esast.GeoBoundsAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var pts [][2]float64
	for _, md := range bDocs {
		pts = append(pts, extractDocGeoPoints(md, spec.Field)...)
	}
	if len(pts) == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{}, 0, out)
		return
	}
	minLat, maxLat := pts[0][0], pts[0][0]
	minLon, maxLon := pts[0][1], pts[0][1]
	var posMinLon, posMaxLon float64 = 180, -180
	var negMinLon, negMaxLon float64 = 180, -180
	hasPos, hasNeg := false, false
	for _, pt := range pts {
		lat, lon := pt[0], pt[1]
		if lat < minLat {
			minLat = lat
		}
		if lat > maxLat {
			maxLat = lat
		}
		if lon < minLon {
			minLon = lon
		}
		if lon > maxLon {
			maxLon = lon
		}
		if lon >= 0 {
			hasPos = true
			if lon < posMinLon {
				posMinLon = lon
			}
			if lon > posMaxLon {
				posMaxLon = lon
			}
		} else {
			hasNeg = true
			if lon < negMinLon {
				negMinLon = lon
			}
			if lon > negMaxLon {
				negMaxLon = lon
			}
		}
	}
	wrap := true
	if spec.WrapLongitude != nil {
		wrap = *spec.WrapLongitude
	}
	leftLon, rightLon := minLon, maxLon
	if wrap && hasPos && hasNeg {
		unwrappedSpan := maxLon - minLon
		wrappedSpan := (180.0 - posMinLon) + (negMaxLon + 180.0)
		if wrappedSpan < unwrappedSpan {
			leftLon = posMinLon
			rightLon = negMaxLon
		}
	}
	obj := map[string]any{
		"bounds": map[string]any{
			"top_left": map[string]any{
				"lat": maxLat,
				"lon": leftLon,
			},
			"bottom_right": map[string]any{
				"lat": minLat,
				"lon": rightLon,
			},
		},
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(len(pts)), out)
}

func emitRuntimeGeoCentroidAggRows(fullAggName, metricBucketKey string, spec *esast.MetricAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil {
		return
	}
	var sumLat, sumLon float64
	var cnt int64
	for _, md := range bDocs {
		pts := extractDocGeoPoints(md, spec.Field)
		for _, pt := range pts {
			sumLat += pt[0]
			sumLon += pt[1]
			cnt++
		}
	}
	if cnt == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"count": int64(0)}, 0, out)
		return
	}
	obj := map[string]any{
		"location": map[string]any{
			"lat": sumLat / float64(cnt),
			"lon": sumLon / float64(cnt),
		},
		"count": cnt,
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(cnt), out)
}

func emitRuntimeMatrixStatsAggRows(fullAggName, metricBucketKey string, spec *esast.MatrixStatsAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil || len(spec.Fields) == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"doc_count": int64(0), "fields": []any{}}, 0, out)
		return
	}
	fields := spec.Fields
	n := len(fields)
	var rows [][]float64
	for _, md := range bDocs {
		vec := make([]float64, n)
		complete := true
		for i, f := range fields {
			var missingVal any
			if spec.Missing != nil {
				missingVal = spec.Missing[f]
			}
			fvals := extractDocNumericValuesForMetric(md, &esast.MetricAggSpec{
				Field:   f,
				Missing: missingVal,
			})
			if len(fvals) == 0 {
				complete = false
				break
			}
			var s float64
			for _, v := range fvals {
				s += v
			}
			vec[i] = s / float64(len(fvals))
		}
		if complete {
			rows = append(rows, vec)
		}
	}
	docCount := int64(len(rows))
	if docCount == 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"doc_count": int64(0), "fields": []any{}}, 0, out)
		return
	}
	means := make([]float64, n)
	for _, r := range rows {
		for i := 0; i < n; i++ {
			means[i] += r[i]
		}
	}
	for i := 0; i < n; i++ {
		means[i] /= float64(docCount)
	}
	cov := make([][]float64, n)
	for i := 0; i < n; i++ {
		cov[i] = make([]float64, n)
	}
	m3 := make([]float64, n)
	m4 := make([]float64, n)
	for _, r := range rows {
		for i := 0; i < n; i++ {
			di := r[i] - means[i]
			m3[i] += di * di * di
			m4[i] += di * di * di * di
			for j := i; j < n; j++ {
				dj := r[j] - means[j]
				cov[i][j] += di * dj
			}
		}
	}
	denom := float64(docCount)
	if docCount > 1 {
		denom = float64(docCount - 1)
	}
	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			cov[i][j] /= denom
			cov[j][i] = cov[i][j]
		}
	}
	fieldStats := make([]map[string]any, n)
	for i, f := range fields {
		variance := cov[i][i]
		stddev := math.Sqrt(math.Max(0, variance))
		var skewness, kurtosis float64
		if stddev > 0 {
			popVar := variance * denom / float64(docCount)
			popStd := math.Sqrt(math.Max(0, popVar))
			if popStd > 0 {
				skewness = (m3[i] / float64(docCount)) / (popStd * popStd * popStd)
				kurtosis = (m4[i] / float64(docCount)) / (popVar * popVar)
			}
		}
		covMap := make(map[string]any, n)
		corrMap := make(map[string]any, n)
		for j, fj := range fields {
			covMap[fj] = cov[i][j]
			stdJ := math.Sqrt(math.Max(0, cov[j][j]))
			if stddev > 0 && stdJ > 0 {
				corrMap[fj] = cov[i][j] / (stddev * stdJ)
			} else if i == j {
				corrMap[fj] = 1.0
			} else {
				corrMap[fj] = 0.0
			}
		}
		fieldStats[i] = map[string]any{
			"name":        f,
			"count":       docCount,
			"mean":        means[i],
			"variance":    variance,
			"skewness":    skewness,
			"kurtosis":    kurtosis,
			"covariance":  covMap,
			"correlation": corrMap,
		}
	}
	obj := map[string]any{
		"doc_count": docCount,
		"fields":    fieldStats,
	}
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, obj, float64(docCount), out)
}

func emitRuntimeTTestAggRows(fullAggName, metricBucketKey string, spec *esast.TTestAggSpec, bDocs []runtimeMatchedDoc, out *[]AggRow) {
	if spec == nil || (spec.A.Field == "" && spec.A.Script == nil) || (spec.B.Field == "" && spec.B.Script == nil) {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": nil}, 0, out)
		return
	}
	aMetric := &esast.MetricAggSpec{
		Field:   spec.A.Field,
		Missing: spec.A.Missing,
		Script:  spec.A.Script,
	}
	bMetric := &esast.MetricAggSpec{
		Field:   spec.B.Field,
		Missing: spec.B.Missing,
		Script:  spec.B.Script,
	}
	isPaired := strings.EqualFold(strings.TrimSpace(spec.Type), "paired")
	if isPaired {
		var diffs []float64
		for _, md := range bDocs {
			aVals := extractDocNumericValuesForMetric(md, aMetric)
			bVals := extractDocNumericValuesForMetric(md, bMetric)
			if len(aVals) > 0 && len(bVals) > 0 {
				diffs = append(diffs, aVals[0]-bVals[0])
			}
		}
		if len(diffs) < 2 {
			emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": nil}, 0, out)
			return
		}
		var sum float64
		for _, d := range diffs {
			sum += d
		}
		mean := sum / float64(len(diffs))
		var sqDiff float64
		for _, d := range diffs {
			dd := d - mean
			sqDiff += dd * dd
		}
		variance := sqDiff / float64(len(diffs)-1)
		if variance <= 0 {
			emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": nil}, 0, out)
			return
		}
		tStat := mean / math.Sqrt(variance/float64(len(diffs)))
		pVal := approximateTwoSidedTTestPValue(tStat, float64(len(diffs)-1))
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": pVal, "t_stat": tStat}, pVal, out)
		return
	}
	var aSample, bSample []float64
	for _, md := range bDocs {
		if spec.A.Filter == nil || evalBranchMatchesDoc(md.EffectiveSchema(nil), md.doc, spec.A.Filter) {
			aSample = append(aSample, extractDocNumericValuesForMetric(md, aMetric)...)
		}
		if spec.B.Filter == nil || evalBranchMatchesDoc(md.EffectiveSchema(nil), md.doc, spec.B.Filter) {
			bSample = append(bSample, extractDocNumericValuesForMetric(md, bMetric)...)
		}
	}
	if len(aSample) < 2 || len(bSample) < 2 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": nil}, 0, out)
		return
	}
	meanVar := func(xs []float64) (float64, float64) {
		var s float64
		for _, x := range xs {
			s += x
		}
		m := s / float64(len(xs))
		var v float64
		for _, x := range xs {
			d := x - m
			v += d * d
		}
		return m, v / float64(len(xs)-1)
	}
	meanA, varA := meanVar(aSample)
	meanB, varB := meanVar(bSample)
	nA, nB := float64(len(aSample)), float64(len(bSample))
	var se, df float64
	if strings.EqualFold(strings.TrimSpace(spec.Type), "homoscedastic") {
		df = nA + nB - 2.0
		sp2 := ((nA-1.0)*varA + (nB-1.0)*varB) / df
		se = math.Sqrt(sp2 * (1.0/nA + 1.0/nB))
	} else {
		vnA := varA / nA
		vnB := varB / nB
		se = math.Sqrt(vnA + vnB)
		if se > 0 {
			num := (vnA + vnB) * (vnA + vnB)
			den := (vnA*vnA)/(nA-1.0) + (vnB*vnB)/(nB-1.0)
			if den > 0 {
				df = num / den
			}
		}
	}
	if se <= 0 {
		emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": nil}, 0, out)
		return
	}
	tStat := (meanA - meanB) / se
	pVal := approximateTwoSidedTTestPValue(tStat, df)
	emitRuntimeJSONMetricRow(fullAggName, metricBucketKey, map[string]any{"value": pVal, "t_stat": tStat}, pVal, out)
}

func approximateTwoSidedTTestPValue(tStat, df float64) float64 {
	x := math.Abs(tStat)
	if df > 0 {
		// Cornwallis-Peizer-Pratt normal approximation for Student's t tail
		z := x * (1.0 - 1.0/(4.0*df)) / math.Sqrt(1.0+(x*x)/(2.0*df))
		p := math.Erfc(z / math.Sqrt2)
		if p < 0 {
			return 0
		}
		if p > 1 {
			return 1
		}
		return p
	}
	return math.Erfc(x / math.Sqrt2)
}

func formatTermsNumericPattern(fv float64, fmtPattern string) string {
	fmtPattern = strings.TrimSpace(fmtPattern)
	if fmtPattern == "" {
		return strconv.FormatFloat(fv, 'f', -1, 64)
	}
	dotIdx := strings.IndexByte(fmtPattern, '.')
	decPlaces := 0
	minIntDigits := 0
	intPartPat := fmtPattern
	if dotIdx >= 0 {
		intPartPat = fmtPattern[:dotIdx]
		decPartPat := fmtPattern[dotIdx+1:]
		for i := 0; i < len(decPartPat); i++ {
			if decPartPat[i] == '0' || decPartPat[i] == '#' {
				decPlaces++
			}
		}
	}
	for i := 0; i < len(intPartPat); i++ {
		if intPartPat[i] == '0' {
			minIntDigits++
		}
	}
	formatted := strconv.FormatFloat(fv, 'f', decPlaces, 64)
	neg := strings.HasPrefix(formatted, "-")
	if neg {
		formatted = formatted[1:]
	}
	parts := strings.SplitN(formatted, ".", 2)
	for len(parts[0]) < minIntDigits {
		parts[0] = "0" + parts[0]
	}
	if len(parts) == 2 {
		formatted = parts[0] + "." + parts[1]
	} else {
		formatted = parts[0]
	}
	if neg {
		formatted = "-" + formatted
	}
	return formatted
}

func formatTermsBucketKeyAndString(rawKey string, termsSpec *esast.TermsAggSpec, idxSchema *schema.IndexSchema) (any, string, bool) {
	if rawKey == "__ES_MISSING_BUCKET__" {
		return nil, "", false
	}
	var esType string
	var isBool, isDate, isNum bool
	if termsSpec != nil {
		vt := strings.ToLower(strings.TrimSpace(termsSpec.ValueType))
		switch vt {
		case "boolean":
			isBool = true
		case "date":
			isDate = true
		case "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float", "number":
			isNum = true
		}
		if idxSchema != nil && strings.TrimSpace(termsSpec.Field) != "" {
			b := idxSchema.ResolveField(termsSpec.Field)
			esType = b.ESType
			if esType == "boolean" || b.DorisType == schema.DorisBoolean {
				isBool = true
			} else if esType == "date" || esType == "date_nanos" {
				isDate = true
			} else if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt || b.DorisType == schema.DorisDouble {
				isNum = true
			}
		}
	}
	if isBool {
		lower := strings.ToLower(strings.TrimSpace(rawKey))
		if lower == "true" || lower == "1" {
			if termsSpec != nil && strings.EqualFold(strings.TrimSpace(termsSpec.ValueType), "boolean") {
				return 1, "true", true
			}
			return "true", "true", true
		}
		if lower == "false" || lower == "0" {
			if termsSpec != nil && strings.EqualFold(strings.TrimSpace(termsSpec.ValueType), "boolean") {
				return 0, "false", true
			}
			return "false", "false", true
		}
	}
	if isDate {
		var ms int64
		hasMs := false
		if iv, err := strconv.ParseInt(strings.TrimSpace(rawKey), 10, 64); err == nil {
			ms = iv
			hasMs = true
		} else if parsedMs, ok := schema.ParseESDateToEpochMillis(rawKey, time.Now().UTC()); ok {
			ms = parsedMs
			hasMs = true
		}
		if hasMs {
			var fmtStr string
			if termsSpec != nil {
				fmtStr = termsSpec.Format
			}
			keyAsStr := formatDateHistogramKeyAsString(ms, &esast.DateHistogramAggSpec{Format: fmtStr})
			if termsSpec != nil && (strings.TrimSpace(termsSpec.Format) != "" || strings.EqualFold(strings.TrimSpace(termsSpec.ValueType), "date")) {
				return ms, keyAsStr, true
			}
			return rawKey, keyAsStr, true
		}
	}
	if termsSpec != nil && strings.TrimSpace(termsSpec.Format) != "" {
		if fv, ok := parseFiniteFloat(rawKey); ok {
			keyAsStr := formatTermsNumericPattern(fv, termsSpec.Format)
			if isNum {
				return rawKey, keyAsStr, true
			}
			return rawKey, keyAsStr, true
		}
	}
	return rawKey, "", false
}

func emitRuntimeMultiTermsAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	mt := aggSpec.MultiTerms
	if mt == nil || len(mt.Terms) == 0 {
		return
	}
	type tupleBucket struct {
		id         string
		keyTuple   []any
		keyAsStr   string
		matchedDoc []runtimeMatchedDoc
	}
	byTuple := make(map[string]*tupleBucket)
	var tupleOrder []string

	for _, md := range docs {
		effSchema := md.EffectiveSchema(idxSchema)
		termValueLists := make([][]any, len(mt.Terms))
		complete := true
		for i, ts := range mt.Terms {
			vals := extractDocRawValuesForMetric(md, &esast.MetricAggSpec{
				Field:   ts.Field,
				Missing: ts.Missing,
				Script:  ts.Script,
			})
			if len(vals) == 0 {
				complete = false
				break
			}
			termValueLists[i] = vals
		}
		if !complete {
			continue
		}
		tuples := [][]any{{}}
		for _, vList := range termValueLists {
			var next [][]any
			for _, prefix := range tuples {
				for _, v := range vList {
					cp := make([]any, len(prefix)+1)
					copy(cp, prefix)
					cp[len(prefix)] = v
					next = append(next, cp)
				}
			}
			tuples = next
		}
		seenDocTuple := make(map[string]bool, len(tuples))
		for _, tup := range tuples {
			strParts := make([]string, len(tup))
			normParts := make([]any, len(tup))
			for i, v := range tup {
				rawStr := fmt.Sprintf("%v", v)
				ts := mt.Terms[i]
				kv, kas, hasKAS := formatTermsBucketKeyAndString(rawStr, &esast.TermsAggSpec{
					Field:     ts.Field,
					ValueType: ts.ValueType,
					Format:    ts.Format,
				}, effSchema)
				if hasKAS && kas != "" {
					strParts[i] = kas
				} else {
					strParts[i] = fmt.Sprintf("%v", kv)
				}
				if fv, ok := toFloat64(v); ok {
					if fv == math.Trunc(fv) {
						normParts[i] = int64(fv)
					} else {
						normParts[i] = fv
					}
				} else {
					normParts[i] = v
				}
			}
			joined := strings.Join(strParts, "|")
			metaBytes, _ := json.Marshal(map[string]any{
				"key":           normParts,
				"key_as_string": joined,
			})
			tid := joined + "\x00" + string(metaBytes)
			if seenDocTuple[tid] {
				continue
			}
			seenDocTuple[tid] = true
			tb, exists := byTuple[tid]
			if !exists {
				tb = &tupleBucket{
					id:       tid,
					keyTuple: normParts,
					keyAsStr: joined,
				}
				byTuple[tid] = tb
				tupleOrder = append(tupleOrder, tid)
			}
			tb.matchedDoc = append(tb.matchedDoc, md)
		}
	}

	minCount := 1
	if mt.MinDocCount != nil && *mt.MinDocCount >= 0 {
		minCount = *mt.MinDocCount
	}
	var filtered []string
	for _, tid := range tupleOrder {
		if len(byTuple[tid].matchedDoc) >= minCount {
			filtered = append(filtered, tid)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		bi, bj := byTuple[filtered[i]], byTuple[filtered[j]]
		ci, cj := len(bi.matchedDoc), len(bj.matchedDoc)
		if ci != cj {
			return ci > cj
		}
		return bi.keyAsStr < bj.keyAsStr
	})
	sizeLimit := mt.Size
	if sizeLimit <= 0 {
		sizeLimit = 10
	}
	if len(filtered) > sizeLimit {
		filtered = filtered[:sizeLimit]
	}
	subAggs := aggSpec.SubAggs()
	for _, tid := range filtered {
		tb := byTuple[tid]
		rowKey := tid
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + tid
		}
		cnt := int64(len(tb.matchedDoc))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, tb.matchedDoc, out, idxSchema)
		}
	}
}

func emitRuntimeRareTermsAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	rt := aggSpec.RareTerms
	if rt == nil {
		return
	}
	maxDocCount := int64(rt.EffectiveMaxDocCount())
	synthTerms := &esast.TermsAggSpec{
		Field:   rt.Field,
		Missing: rt.Missing,
		Include: rt.Include,
		Exclude: rt.Exclude,
	}
	var incRe, excRe *regexp.Regexp
	if s, ok := rt.Include.(string); ok {
		incRe, _ = regexp.Compile("^(?:" + s + ")$")
	}
	if s, ok := rt.Exclude.(string); ok {
		excRe, _ = regexp.Compile("^(?:" + s + ")$")
	}
	byBucket, keys := computeRuntimeTermsScriptBucketDocsWithSchema(idxSchema, docs, synthTerms)
	var rareKeys []string
	for _, k := range keys {
		if int64(len(byBucket[k])) <= maxDocCount {
			if rt.Include != nil && !matchesTermsFilterPrecompiled(k, rt.Include, incRe) {
				continue
			}
			if rt.Exclude != nil && matchesTermsFilterPrecompiled(k, rt.Exclude, excRe) {
				continue
			}
			rareKeys = append(rareKeys, k)
		}
	}
	sort.Slice(rareKeys, func(i, j int) bool {
		ci, cj := len(byBucket[rareKeys[i]]), len(byBucket[rareKeys[j]])
		if ci != cj {
			return ci < cj
		}
		return rareKeys[i] < rareKeys[j]
	})
	subAggs := aggSpec.SubAggs()
	for _, k := range rareKeys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func selectAutoDateHistogramInterval(minTS, maxTS int64, targetBuckets int) (int64, string) {
	if targetBuckets <= 0 {
		targetBuckets = 10
	}
	span := maxTS - minTS
	if span <= 0 {
		return 1000, "1s"
	}
	candidates := []struct {
		ms    int64
		label string
	}{
		{1000, "1s"},
		{5000, "5s"},
		{10000, "10s"},
		{30000, "30s"},
		{60000, "1m"},
		{300000, "5m"},
		{600000, "10m"},
		{1800000, "30m"},
		{3600000, "1h"},
		{10800000, "3h"},
		{43200000, "12h"},
		{86400000, "1d"},
		{604800000, "7d"},
		{2592000000, "30d"},
		{7776000000, "90d"},
		{31536000000, "365d"},
	}
	for _, c := range candidates {
		firstB := int64(math.Floor(float64(minTS)/float64(c.ms))) * c.ms
		lastB := int64(math.Floor(float64(maxTS)/float64(c.ms))) * c.ms
		numB := (lastB-firstB)/c.ms + 1
		if numB <= int64(targetBuckets) {
			return c.ms, c.label
		}
	}
	last := candidates[len(candidates)-1]
	return last.ms, last.label
}

func emitRuntimeAutoDateHistogramAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	adh := aggSpec.AutoDateHistogram
	if adh == nil {
		return
	}
	targetBuckets := adh.EffectiveBuckets()
	dhHelper := esast.DateHistogramAggSpec{
		Field:    adh.Field,
		TimeZone: adh.TimeZone,
	}
	tzShiftMs := dhHelper.EffectiveTimeZoneOffsetMs()
	nowUTC := time.Now().UTC()
	var minTS, maxTS int64
	hasTS := false
	type docTS struct {
		md     runtimeMatchedDoc
		tsList []int64
	}
	var allDocTS []docTS
	for _, md := range docs {
		tsList := extractDocDateMillisForBucket(idxSchema, md, adh.Field, adh.Missing, adh.Script, nowUTC)
		if len(tsList) == 0 {
			continue
		}
		allDocTS = append(allDocTS, docTS{md: md, tsList: tsList})
		for _, ts := range tsList {
			if !hasTS || ts < minTS {
				minTS = ts
			}
			if !hasTS || ts > maxTS {
				maxTS = ts
			}
			hasTS = true
		}
	}
	if !hasTS {
		return
	}
	intervalMs, _ := selectAutoDateHistogramInterval(minTS+tzShiftMs, maxTS+tzShiftMs, targetBuckets)
	byBucket := make(map[string][]runtimeMatchedDoc)
	bucketTS := make(map[string]int64)
	for _, d := range allDocTS {
		seenDocB := make(map[string]bool, len(d.tsList))
		for _, ts := range d.tsList {
			b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
			k := strconv.FormatInt(b, 10)
			if !seenDocB[k] {
				seenDocB[k] = true
				bucketTS[k] = b
				byBucket[k] = append(byBucket[k], d.md)
			}
		}
	}
	keys := make([]string, 0, len(byBucket))
	for k := range byBucket {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bucketTS[keys[i]] < bucketTS[keys[j]]
	})
	if len(keys) >= 2 {
		firstTS := bucketTS[keys[0]]
		lastTS := bucketTS[keys[len(keys)-1]]
		if (lastTS-firstTS)/intervalMs+1 <= 10000 {
			for b := firstTS + intervalMs; b < lastTS; b += intervalMs {
				k := strconv.FormatInt(b, 10)
				if _, exists := byBucket[k]; !exists {
					byBucket[k] = nil
					bucketTS[k] = b
					keys = append(keys, k)
				}
			}
			sort.Slice(keys, func(i, j int) bool {
				return bucketTS[keys[i]] < bucketTS[keys[j]]
			})
		}
	}
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func emitRuntimeVariableWidthHistogramAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	vwh := aggSpec.VariableWidthHistogram
	if vwh == nil {
		return
	}
	targetBuckets := vwh.EffectiveBuckets()
	type docValPair struct {
		md  runtimeMatchedDoc
		val float64
	}
	var pairs []docValPair
	for _, md := range docs {
		vals := extractDocNumericValuesForBucket(md, vwh.Field, vwh.Missing, vwh.Script)
		for _, v := range vals {
			pairs = append(pairs, docValPair{md: md, val: v})
		}
	}
	if len(pairs) == 0 {
		return
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].val < pairs[j].val
	})
	if targetBuckets > len(pairs) {
		targetBuckets = len(pairs)
	}
	subAggs := aggSpec.SubAggs()
	for bIdx := 0; bIdx < targetBuckets; bIdx++ {
		start := (bIdx * len(pairs)) / targetBuckets
		end := ((bIdx + 1) * len(pairs)) / targetBuckets
		if start >= end {
			continue
		}
		slice := pairs[start:end]
		minV := slice[0].val
		maxV := slice[len(slice)-1].val
		var sumV float64
		var bDocs []runtimeMatchedDoc
		seenDoc := make(map[string]bool, len(slice))
		for idxInSlice, p := range slice {
			sumV += p.val
			docKey := p.md.hit.ID
			if docKey == "" {
				docKey = strconv.Itoa(start + idxInSlice)
			}
			if !seenDoc[docKey] {
				seenDoc[docKey] = true
				bDocs = append(bDocs, p.md)
			}
		}
		keyVal := sumV / float64(len(slice))
		metaObj := map[string]any{
			"min": minV,
			"key": keyVal,
			"max": maxV,
		}
		metaBytes, _ := json.Marshal(metaObj)
		leafKey := strconv.Itoa(bIdx) + "\x00" + string(metaBytes)
		rowKey := leafKey
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + leafKey
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func emitRuntimeGeoDistanceAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	gd := aggSpec.GeoDistance
	if gd == nil {
		return
	}
	origLat, origLon, ok := parseGeoPointLatLon(gd.Origin)
	if !ok {
		return
	}
	unitScale := parseGeoDistanceUnitMeters(gd.Unit)
	if unitScale <= 0 {
		unitScale = 1.0
	}
	subAggs := aggSpec.SubAggs()
	for _, rng := range gd.Ranges {
		rk := rng.EffectiveKey()
		fromVal, hasFrom := toFloat64(rng.From)
		toVal, hasTo := toFloat64(rng.To)
		var bDocs []runtimeMatchedDoc
		for _, md := range docs {
			pts := extractDocGeoPoints(md, gd.Field)
			matched := false
			for _, pt := range pts {
				distMeters := haversineDistanceMeters(origLat, origLon, pt[0], pt[1])
				distInUnit := distMeters / unitScale
				if (!hasFrom || distInUnit >= fromVal) && (!hasTo || distInUnit < toVal) {
					matched = true
					break
				}
			}
			if matched {
				bDocs = append(bDocs, md)
			}
		}
		rowKey := rk
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + rk
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func parseGeoDistanceUnitMeters(unit string) float64 {
	u := strings.ToLower(strings.TrimSpace(unit))
	switch u {
	case "", "m", "meters":
		return 1.0
	case "km", "kilometers":
		return 1000.0
	case "mi", "miles":
		return 1609.344
	case "yd", "yards":
		return 0.9144
	case "ft", "feet":
		return 0.3048
	case "in", "inch":
		return 0.0254
	case "cm", "centimeters":
		return 0.01
	case "mm", "millimeters":
		return 0.001
	case "nmi", "NM", "nauticalmiles":
		return 1852.0
	}
	return 1.0
}

func encodeGeohash(lat, lon float64, precision int) string {
	const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"
	if precision <= 0 {
		precision = 5
	}
	if precision > 12 {
		precision = 12
	}
	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0
	var hash strings.Builder
	hash.Grow(precision)
	isEven := true
	bit := 0
	ch := 0
	for hash.Len() < precision {
		if isEven {
			mid := (minLon + maxLon) / 2.0
			if lon >= mid {
				ch |= 1 << (4 - bit)
				minLon = mid
			} else {
				maxLon = mid
			}
		} else {
			mid := (minLat + maxLat) / 2.0
			if lat >= mid {
				ch |= 1 << (4 - bit)
				minLat = mid
			} else {
				maxLat = mid
			}
		}
		isEven = !isEven
		if bit < 4 {
			bit++
		} else {
			hash.WriteByte(base32[ch])
			bit = 0
			ch = 0
		}
	}
	return hash.String()
}

func encodeGeotile(lat, lon float64, zoom int) string {
	if zoom < 0 {
		zoom = 7
	}
	if zoom > 29 {
		zoom = 29
	}
	n := math.Pow(2.0, float64(zoom))
	xtile := int(math.Floor((lon + 180.0) / 360.0 * n))
	if xtile < 0 {
		xtile = 0
	}
	if float64(xtile) >= n {
		xtile = int(n) - 1
	}
	latRad := lat * math.Pi / 180.0
	ytile := int(math.Floor((1.0 - math.Log(math.Tan(latRad)+1.0/math.Cos(latRad))/math.Pi) / 2.0 * n))
	if ytile < 0 {
		ytile = 0
	}
	if float64(ytile) >= n {
		ytile = int(n) - 1
	}
	return fmt.Sprintf("%d/%d/%d", zoom, xtile, ytile)
}

func emitRuntimeGeoGridAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	isTile := aggSpec.GeotileGrid != nil
	spec := aggSpec.GeohashGrid
	if isTile {
		spec = aggSpec.GeotileGrid
	}
	if spec == nil {
		return
	}
	prec := 5
	if isTile {
		prec = 7
	}
	if spec.Precision != nil && *spec.Precision > 0 {
		prec = *spec.Precision
	}
	var bTopLat, bLeftLon, bBotLat, bRightLon float64
	hasBounds := false
	if spec.Bounds != nil {
		bTopLat, bLeftLon, bBotLat, bRightLon, hasBounds = extractGeoBoundingBoxMapCoords(spec.Bounds)
	}
	byBucket := make(map[string][]runtimeMatchedDoc)
	var keys []string
	for _, md := range docs {
		pts := extractDocGeoPoints(md, spec.Field)
		seenCell := make(map[string]bool, len(pts))
		for _, pt := range pts {
			if hasBounds && !geoPointInBox(pt[0], pt[1], bTopLat, bLeftLon, bBotLat, bRightLon) {
				continue
			}
			var cell string
			if isTile {
				cell = encodeGeotile(pt[0], pt[1], prec)
			} else {
				cell = encodeGeohash(pt[0], pt[1], prec)
			}
			if !seenCell[cell] {
				seenCell[cell] = true
				if _, exists := byBucket[cell]; !exists {
					keys = append(keys, cell)
				}
				byBucket[cell] = append(byBucket[cell], md)
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		ci, cj := len(byBucket[keys[i]]), len(byBucket[keys[j]])
		if ci != cj {
			return ci > cj
		}
		return keys[i] < keys[j]
	})
	maxSize := 10000
	if spec.Size > 0 {
		maxSize = spec.Size
	}
	if len(keys) > maxSize {
		keys = keys[:maxSize]
	}
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func emitRuntimeAdjacencyMatrixAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	am := aggSpec.AdjacencyMatrix
	if am == nil || len(am.Filters) == 0 {
		return
	}
	sep := am.EffectiveSeparator()
	fKeys := make([]string, 0, len(am.Filters))
	for k := range am.Filters {
		fKeys = append(fKeys, k)
	}
	sort.Strings(fKeys)
	matchedByFilter := make(map[string][]runtimeMatchedDoc, len(fKeys))
	matchedSetByFilter := make(map[string]map[int]bool, len(fKeys))
	for _, fk := range fKeys {
		fq := am.Filters[fk]
		set := make(map[int]bool)
		var mDocs []runtimeMatchedDoc
		for idx, md := range docs {
			if evalBranchMatchesDoc(idxSchema, md.doc, &fq) {
				set[idx] = true
				mDocs = append(mDocs, md)
			}
		}
		matchedByFilter[fk] = mDocs
		matchedSetByFilter[fk] = set
	}
	subAggs := aggSpec.SubAggs()
	emitBucket := func(bk string, bDocs []runtimeMatchedDoc) {
		if len(bDocs) == 0 {
			return
		}
		rowKey := bk
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + bk
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
	for i, k1 := range fKeys {
		emitBucket(k1, matchedByFilter[k1])
		for j := i + 1; j < len(fKeys); j++ {
			k2 := fKeys[j]
			set2 := matchedSetByFilter[k2]
			var pairDocs []runtimeMatchedDoc
			for idx, md := range docs {
				if matchedSetByFilter[k1][idx] && set2[idx] {
					pairDocs = append(pairDocs, md)
				}
			}
			emitBucket(k1+sep+k2, pairDocs)
		}
	}
}

func formatRuntimeJSONMetricAggObject(parentBucketKey string, aggSpec esast.AggSpec, rows []AggRow) map[string]any {
	expectedLogical := parentBucketKey
	if expectedLogical == "" {
		expectedLogical = "_metric"
	}
	for _, r := range rows {
		logicalBucket, reducedVal, _, ok := parseScriptedMetricBucketKey(r.BucketKey)
		if !ok || (logicalBucket != expectedLogical && logicalBucket != parentBucketKey) {
			continue
		}
		if m, ok := reducedVal.(map[string]any); ok {
			return m
		}
		return map[string]any{"value": reducedVal}
	}
	switch {
	case aggSpec.GeoBounds != nil:
		return map[string]any{}
	case aggSpec.GeoCentroid != nil:
		return map[string]any{"count": int64(0)}
	case aggSpec.MatrixStats != nil:
		return map[string]any{"doc_count": int64(0), "fields": []any{}}
	default:
		return map[string]any{"value": nil}
	}
}

func formatRuntimeBucketAggObjectWithSchema(
	indexName string,
	fullKey string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	rows []AggRow,
	bucketsByAgg map[string][]AggRow,
	docLookup func(string) *HitRow,
	idxSchema *schema.IndexSchema,
) map[string]any {
	subAggs := aggSpec.SubAggs()
	var buckets []map[string]any
	prefix := ""
	if parentBucketKey != "" {
		prefix = parentBucketKey + "\x1f"
	}
	for _, r := range rows {
		var leafKey string
		if prefix != "" {
			if !strings.HasPrefix(r.BucketKey, prefix) {
				continue
			}
			leafKey = r.BucketKey[len(prefix):]
		} else {
			leafKey = r.BucketKey
		}
		if strings.Contains(leafKey, "\x1f") {
			continue
		}
		bObj := map[string]any{
			"doc_count": r.DocCount,
		}
		switch {
		case aggSpec.VariableWidthHistogram != nil || aggSpec.MultiTerms != nil:
			if idx := strings.IndexByte(leafKey, '\x00'); idx >= 0 {
				var meta map[string]any
				if err := json.Unmarshal([]byte(leafKey[idx+1:]), &meta); err == nil {
					for mk, mv := range meta {
						bObj[mk] = mv
					}
				}
			}
		case aggSpec.AutoDateHistogram != nil:
			ts, _ := strconv.ParseInt(leafKey, 10, 64)
			bObj["key"] = ts
			fmtSpec := aggSpec.AutoDateHistogram.Format
			dh := esast.DateHistogramAggSpec{
				Format:   fmtSpec,
				TimeZone: aggSpec.AutoDateHistogram.TimeZone,
			}
			bObj["key_as_string"] = formatDateHistogramKeyAsString(ts, &dh)
		case aggSpec.GeoDistance != nil:
			for _, rng := range aggSpec.GeoDistance.Ranges {
				if rng.EffectiveKey() == leafKey {
					bObj["key"] = leafKey
					if f, ok := toFloat64(rng.From); ok {
						bObj["from"] = f
					} else {
						bObj["from"] = 0.0
					}
					if t, ok := toFloat64(rng.To); ok {
						bObj["to"] = t
					}
					break
				}
			}
			if _, hasK := bObj["key"]; !hasK {
				bObj["key"] = leafKey
			}
		default:
			bObj["key"] = leafKey
		}
		if len(subAggs) > 0 {
			attachSubAggsToBucketWithSchema(indexName, bObj, fullKey, r.BucketKey, subAggs, bucketsByAgg, docLookup, idxSchema)
			evaluateSiblingPipelineAggs(subAggs, bObj)
		}
		buckets = append(buckets, bObj)
	}
	if len(subAggs) > 0 {
		buckets = evaluateChildPipelineAggs(buckets, subAggs)
	}
	if buckets == nil {
		buckets = []map[string]any{}
	}
	if aggSpec.GeoDistance != nil && aggSpec.GeoDistance.Keyed {
		return formatKeyedBuckets(buckets, true, "key")
	}
	if aggSpec.AdjacencyMatrix != nil && aggSpec.AdjacencyMatrix.Keyed {
		return formatKeyedBuckets(buckets, true, "key")
	}
	out := map[string]any{
		"buckets": buckets,
	}
	if aggSpec.MultiTerms != nil {
		out["doc_count_error_upper_bound"] = 0
		out["sum_other_doc_count"] = 0
	}
	if aggSpec.AutoDateHistogram != nil {
		targetB := aggSpec.AutoDateHistogram.EffectiveBuckets()
		if len(buckets) >= 2 {
			k0, _ := toFloat64(buckets[0]["key"])
			kLast, _ := toFloat64(buckets[len(buckets)-1]["key"])
			_, label := selectAutoDateHistogramInterval(int64(k0), int64(kLast), targetB)
			out["interval"] = label
		} else {
			out["interval"] = "1s"
		}
	}
	return out
}

func parseScriptedMetricBucketKey(bk string) (logicalBucket string, reducedVal any, combinedVal any, ok bool) {
	idx1 := strings.IndexByte(bk, '\x00')
	if idx1 < 0 {
		return bk, nil, nil, false
	}
	logicalBucket = bk[:idx1]
	rest := bk[idx1+1:]
	idx2 := strings.IndexByte(rest, '\x00')
	if idx2 < 0 {
		_ = json.Unmarshal([]byte(rest), &reducedVal)
		return logicalBucket, reducedVal, reducedVal, true
	}
	_ = json.Unmarshal([]byte(rest[:idx2]), &reducedVal)
	_ = json.Unmarshal([]byte(rest[idx2+1:]), &combinedVal)
	return logicalBucket, reducedVal, combinedVal, true
}

func evalScriptedMetricCombineAndReduce(sm *esast.ScriptedMetricAggSpec, bDocs []runtimeMatchedDoc) (any, any) {
	if sm == nil {
		return nil, nil
	}
	state := make(map[string]any)
	baseParams := make(map[string]any)
	for k, v := range sm.Params {
		baseParams[k] = v
	}
	buildParams := func(extra map[string]any) map[string]any {
		cp := make(map[string]any, len(baseParams)+len(extra)+3)
		for k, v := range baseParams {
			cp[k] = v
		}
		for k, v := range extra {
			cp[k] = v
		}
		cp["state"] = state
		cp["_agg"] = state
		return cp
	}
	if sm.InitScript != nil {
		initSrc, initP := extractScriptSourceAndParams(sm.InitScript)
		if initSrc != "" {
			_, _ = painless.Eval(map[string]any{}, initSrc, buildParams(initP))
		}
	}
	if sm.MapScript != nil {
		mapSrc, mapP := extractScriptSourceAndParams(sm.MapScript)
		if mapSrc != "" {
			for _, md := range bDocs {
				effSchema := md.EffectiveSchema(nil)
				evalDoc := prepareDocForRuntimeScript(effSchema, md.doc)
				p := buildParams(mapP)
				p["_score"] = md.hit.Score
				_, _ = painless.Eval(evalDoc, mapSrc, p)
			}
		}
	}
	var combined any = state
	if sm.CombineScript != nil {
		combSrc, combP := extractScriptSourceAndParams(sm.CombineScript)
		if combSrc != "" {
			cp := buildParams(combP)
			if v, err := painless.Eval(map[string]any{}, combSrc, cp); err == nil {
				if _, hadExplicitReturn := cp["__had_explicit_return"]; v != nil || hadExplicitReturn {
					combined = v
				}
			}
		}
	}
	reduced := evalScriptedMetricReduce(sm, []any{combined})
	return reduced, combined
}

func evalScriptedMetricReduce(sm *esast.ScriptedMetricAggSpec, states []any) any {
	if sm == nil {
		return nil
	}
	if sm.ReduceScript != nil {
		redSrc, redP := extractScriptSourceAndParams(sm.ReduceScript)
		if redSrc != "" {
			p := make(map[string]any, len(sm.Params)+len(redP)+2)
			for k, v := range sm.Params {
				p[k] = v
			}
			for k, v := range redP {
				p[k] = v
			}
			p["states"] = states
			p["_aggs"] = states
			if v, err := painless.Eval(map[string]any{}, redSrc, p); err == nil {
				return v
			}
		}
	}
	if len(states) == 1 {
		return states[0]
	}
	return states
}

func extractDocNumericValuesForBucket(md runtimeMatchedDoc, field string, missing any, script any) []float64 {
	return extractDocNumericValuesForMetric(md, &esast.MetricAggSpec{
		Field:   field,
		Missing: missing,
		Script:  script,
	})
}

func extractDocDateMillisForBucket(idxSchema *schema.IndexSchema, md runtimeMatchedDoc, field string, missing any, script any, nowUTC time.Time) []int64 {
	isDateNanos := false
	if idxSchema != nil && field != "" {
		if b := idxSchema.ResolveField(field); b.ESType == "date_nanos" {
			isDateNanos = true
		}
	}
	rawVals := extractDocRawValuesForMetric(md, &esast.MetricAggSpec{
		Field:   field,
		Missing: missing,
		Script:  script,
	})
	var out []int64
	for _, rv := range rawVals {
		if s, ok := rv.(string); ok {
			if ts, hasTS := schema.ParseESDateToEpochMillis(s, nowUTC); hasTS {
				out = append(out, ts)
			}
		} else if f, ok := toFloat64(rv); ok {
			ts := int64(f)
			if (isDateNanos && script == nil) || math.Abs(f) >= 1e15 {
				ts /= 1_000_000
			}
			out = append(out, ts)
		}
	}
	return out
}

func emitRuntimeHistogramAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	hSpec := aggSpec.Histogram
	if hSpec == nil {
		return
	}
	interval := hSpec.Interval
	if interval <= 0 {
		interval = 1.0
	}
	offset := hSpec.Offset
	byBucket := make(map[string][]runtimeMatchedDoc)
	bucketNum := make(map[string]float64)
	for _, md := range docs {
		vals := extractDocNumericValuesForBucket(md, hSpec.Field, hSpec.Missing, hSpec.Script)
		seenDocB := make(map[string]bool, len(vals))
		for _, f := range vals {
			b := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
			k := strconv.FormatFloat(b, 'f', -1, 64)
			if !seenDocB[k] {
				seenDocB[k] = true
				bucketNum[k] = b
				byBucket[k] = append(byBucket[k], md)
			}
		}
	}
	keys := make([]string, 0, len(byBucket))
	for k := range byBucket {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bucketNum[keys[i]] < bucketNum[keys[j]]
	})
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		if hSpec.MinDocCount != nil && len(bDocs) < *hSpec.MinDocCount {
			continue
		}
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func emitRuntimeDateHistogramAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	dh := aggSpec.DateHistogram
	if dh == nil {
		return
	}
	intervalMs := dh.EffectiveIntervalMs()
	if intervalMs <= 0 {
		intervalMs = 86400000
	}
	tzShiftMs := dh.EffectiveTimeZoneOffsetMs() - dh.EffectiveOffsetMs()
	nowUTC := time.Now().UTC()
	byBucket := make(map[string][]runtimeMatchedDoc)
	bucketTS := make(map[string]int64)
	for _, md := range docs {
		tsList := extractDocDateMillisForBucket(idxSchema, md, dh.Field, dh.Missing, dh.Script, nowUTC)
		seenDocB := make(map[string]bool, len(tsList))
		for _, ts := range tsList {
			b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
			k := strconv.FormatInt(b, 10)
			if !seenDocB[k] {
				seenDocB[k] = true
				bucketTS[k] = b
				byBucket[k] = append(byBucket[k], md)
			}
		}
	}
	keys := make([]string, 0, len(byBucket))
	for k := range byBucket {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bucketTS[keys[i]] < bucketTS[keys[j]]
	})
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		if dh.MinDocCount != nil && len(bDocs) < *dh.MinDocCount {
			continue
		}
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func hasExplicitTZInDateString(s string) bool {
	trimmed := strings.TrimSpace(s)
	if strings.HasSuffix(trimmed, "Z") || strings.HasSuffix(trimmed, "z") {
		return true
	}
	if idx := strings.IndexAny(trimmed, "Tt "); idx > 0 {
		timePart := trimmed[idx+1:]
		if strings.ContainsAny(timePart, "+-") {
			return true
		}
	}
	return false
}

func parseRuntimeDateRangeBoundMillis(bound any, rngSpec *esast.RangeAggSpec, nowUTC time.Time) (int64, bool) {
	if bound == nil {
		return 0, false
	}
	isEpochSecond := rngSpec != nil && strings.EqualFold(strings.TrimSpace(rngSpec.Format), "epoch_second")
	var tzOffsetMs int64
	if rngSpec != nil && strings.TrimSpace(rngSpec.TimeZone) != "" {
		dh := esast.DateHistogramAggSpec{TimeZone: rngSpec.TimeZone}
		tzOffsetMs = dh.EffectiveTimeZoneOffsetMs()
	}
	if s, ok := bound.(string); ok {
		trimmed := strings.TrimSpace(s)
		if isEpochSecond {
			if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return int64(fv * 1000.0), true
			}
		}
		var fmtSpec string
		if rngSpec != nil {
			fmtSpec = rngSpec.Format
		}
		if ts, ok := schema.ParseESDateWithFormatToEpochMillis(trimmed, fmtSpec, nowUTC); ok {
			if tzOffsetMs != 0 && !hasExplicitTZInDateString(trimmed) {
				ts -= tzOffsetMs
			}
			return ts, true
		}
		if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			if isEpochSecond {
				return int64(fv * 1000.0), true
			}
			return int64(fv), true
		}
		return 0, false
	}
	if f, ok := toFloat64(bound); ok {
		if isEpochSecond {
			return int64(f * 1000.0), true
		}
		return int64(f), true
	}
	return 0, false
}

func filterDocsMatchingRangeEntry(
	idxSchema *schema.IndexSchema,
	docs []runtimeMatchedDoc,
	aggSpec esast.AggSpec,
	rngSpec *esast.RangeAggSpec,
	rng esast.RangeAggBucket,
	nowUTC time.Time,
) []runtimeMatchedDoc {
	var out []runtimeMatchedDoc
	if aggSpec.IPRange != nil {
		clean := strings.TrimSuffix(strings.TrimSuffix(rngSpec.Field, ".keyword"), ".ngram")
		var fromIP, toIP uint32
		hasFrom, hasTo := false, false
		isCIDR := false
		if rng.Mask != "" {
			if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(rng.Mask)); err == nil && ipNet != nil {
				startIP := ipNet.IP.To4()
				mask := ipNet.Mask
				if len(startIP) == 4 && len(mask) == 4 {
					fromIP = uint32(startIP[0])<<24 | uint32(startIP[1])<<16 | uint32(startIP[2])<<8 | uint32(startIP[3])
					endIP := net.IPv4(
						startIP[0]|^mask[0],
						startIP[1]|^mask[1],
						startIP[2]|^mask[2],
						startIP[3]|^mask[3],
					).To4()
					toIP = uint32(endIP[0])<<24 | uint32(endIP[1])<<16 | uint32(endIP[2])<<8 | uint32(endIP[3])
					hasFrom, hasTo, isCIDR = true, true, true
				}
			}
		} else {
			if s, ok := rng.From.(string); ok && s != "" {
				fromIP, hasFrom = parseIPv4SortUint32(s)
			}
			if s, ok := rng.To.(string); ok && s != "" {
				toIP, hasTo = parseIPv4SortUint32(s)
			}
		}
		for _, md := range docs {
			effSchema := md.EffectiveSchema(idxSchema)
			pathSegs := strings.Split(clean, ".")
			if effSchema != nil {
				if b := effSchema.ResolveField(rngSpec.Field); len(b.SourceJSONPath) > 0 {
					pathSegs = b.SourceJSONPath
				}
			}
			for _, rv := range collectSchemaAwareScalarValues(md.doc, rngSpec.Field, pathSegs, effSchema) {
				if ipUint, ok := parseIPv4SortUint32(fmt.Sprintf("%v", rv)); ok {
					matchTo := !hasTo || ipUint < toIP
					if isCIDR && hasTo {
						matchTo = ipUint <= toIP
					}
					if (!hasFrom || ipUint >= fromIP) && matchTo {
						out = append(out, md)
						break
					}
				}
			}
		}
		return out
	}
	isDateField := aggSpec.DateRange != nil
	if !isDateField && idxSchema != nil && rngSpec.Field != "" {
		b := idxSchema.ResolveField(rngSpec.Field)
		if b.ESType == "date" || b.ESType == "date_nanos" {
			isDateField = true
		}
	}
	if isDateField {
		fromMs, hasFrom := parseRuntimeDateRangeBoundMillis(rng.From, rngSpec, nowUTC)
		toMs, hasTo := parseRuntimeDateRangeBoundMillis(rng.To, rngSpec, nowUTC)
		for _, md := range docs {
			for _, ts := range extractDocDateMillisForBucket(idxSchema, md, rngSpec.Field, rngSpec.Missing, rngSpec.Script, nowUTC) {
				if (!hasFrom || ts >= fromMs) && (!hasTo || ts < toMs) {
					out = append(out, md)
					break
				}
			}
		}
		return out
	}
	fromVal, hasFrom := toFloat64(rng.From)
	toVal, hasTo := toFloat64(rng.To)
	for _, md := range docs {
		for _, f := range extractDocNumericValuesForBucket(md, rngSpec.Field, rngSpec.Missing, rngSpec.Script) {
			if (!hasFrom || f >= fromVal) && (!hasTo || f < toVal) {
				out = append(out, md)
				break
			}
		}
	}
	return out
}

func emitRuntimeRangeAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	rngSpec := aggSpec.EffectiveRange()
	if rngSpec == nil {
		return
	}
	nowUTC := time.Now().UTC()
	subAggs := aggSpec.SubAggs()
	for _, rng := range rngSpec.Ranges {
		rk := rng.EffectiveKey()
		bDocs := filterDocsMatchingRangeEntry(idxSchema, docs, aggSpec, rngSpec, rng, nowUTC)
		rowKey := rk
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + rk
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func isDirectUnprefixedNestedSubAgg(ss esast.AggSpec) bool {
	return ss.EffectiveTerms() != nil || ss.Cardinality != nil || ss.ValueCount != nil ||
		ss.Avg != nil || ss.Sum != nil || ss.Min != nil || ss.Max != nil ||
		ss.EffectiveStats() != nil || ss.StringStats != nil || ss.Percentiles != nil ||
		ss.PercentileRanks != nil || ss.Boxplot != nil || ss.ReverseNested != nil ||
		ss.ScriptedMetric != nil || ss.WeightedAvg != nil || ss.MedianAbsoluteDeviation != nil ||
		ss.GeoBounds != nil || ss.GeoCentroid != nil || ss.MatrixStats != nil || ss.TTest != nil
}

func splitNestedSubAggsByBucketKeyMode(subAggs map[string]esast.AggSpec) (map[string]esast.AggSpec, map[string]esast.AggSpec) {
	var direct, grouped map[string]esast.AggSpec
	for k, v := range subAggs {
		if isDirectUnprefixedNestedSubAgg(v) {
			if direct == nil {
				direct = make(map[string]esast.AggSpec)
			}
			direct[k] = v
		} else {
			if grouped == nil {
				grouped = make(map[string]esast.AggSpec)
			}
			grouped[k] = v
		}
	}
	return direct, grouped
}

func restoreRootDocsForReverseNested(docs []runtimeMatchedDoc, targetPath string, fallbackSchema *schema.IndexSchema) ([]runtimeMatchedDoc, *schema.IndexSchema) {
	seenID := make(map[string]bool, len(docs))
	out := make([]runtimeMatchedDoc, 0, len(docs))
	outSchema := fallbackSchema
	if targetPath != "" {
		for _, md := range docs {
			anc, ok := md.nestedAncestors[targetPath]
			if !ok {
				continue
			}
			if anc.elemID != "" {
				if seenID[anc.elemID] {
					continue
				}
				seenID[anc.elemID] = true
			}
			if anc.schema != nil {
				outSchema = anc.schema
			}
			hitCopy := md.hit
			hitCopy.Schema = outSchema
			out = append(out, runtimeMatchedDoc{
				hit:             hitCopy,
				doc:             anc.doc,
				rootDoc:         md.rootDoc,
				rootSchema:      md.rootSchema,
				nestedAncestors: md.nestedAncestors,
			})
		}
		return out, outSchema
	}
	for _, md := range docs {
		if md.hit.ID != "" {
			if seenID[md.hit.ID] {
				continue
			}
			seenID[md.hit.ID] = true
		}
		rDoc := md.rootDoc
		if rDoc == nil {
			rDoc = md.doc
		}
		if md.rootSchema != nil {
			outSchema = md.rootSchema
		}
		hitCopy := md.hit
		hitCopy.Schema = outSchema
		out = append(out, runtimeMatchedDoc{
			hit:        hitCopy,
			doc:        rDoc,
			rootDoc:    rDoc,
			rootSchema: outSchema,
		})
	}
	return out, outSchema
}

func emitRuntimeAllSubAggRows(
	parentFullKey string,
	parentBucketKey string,
	subAggs map[string]esast.AggSpec,
	bDocs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	for subName, subSpec := range subAggs {
		subFullKey := subName
		if parentFullKey != "" {
			subFullKey = parentFullKey + "." + subName
		}
		switch {
		case subSpec.EffectiveTerms() != nil:
			emitRuntimeTermsScriptAggRowsWithSchema(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.RareTerms != nil:
			emitRuntimeRareTermsAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.MultiTerms != nil:
			emitRuntimeMultiTermsAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.Histogram != nil:
			emitRuntimeHistogramAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.DateHistogram != nil:
			emitRuntimeDateHistogramAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.AutoDateHistogram != nil:
			emitRuntimeAutoDateHistogramAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.VariableWidthHistogram != nil:
			emitRuntimeVariableWidthHistogramAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.EffectiveRange() != nil:
			emitRuntimeRangeAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.GeoDistance != nil:
			emitRuntimeGeoDistanceAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.GeohashGrid != nil || subSpec.GeotileGrid != nil:
			emitRuntimeGeoGridAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.AdjacencyMatrix != nil:
			emitRuntimeAdjacencyMatrixAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.Composite != nil:
			emitRuntimeCompositeAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.Global != nil:
			gBucketKey := "_global"
			if parentBucketKey != "" {
				gBucketKey = parentBucketKey
			}
			*out = append(*out, AggRow{
				AggName:   subFullKey,
				BucketKey: gBucketKey,
				DocCount:  int64(len(bDocs)),
				Value:     float64(len(bDocs)),
			})
			if len(subSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(subFullKey, parentBucketKey, subSpec.SubAggs(), bDocs, out, idxSchema)
			}
		case subSpec.Filter != nil:
			var fDocs []runtimeMatchedDoc
			for _, md := range bDocs {
				if evalBranchMatchesDoc(idxSchema, md.doc, subSpec.Filter) {
					fDocs = append(fDocs, md)
				}
			}
			fBucketKey := "_filter"
			if parentBucketKey != "" {
				fBucketKey = parentBucketKey
			}
			*out = append(*out, AggRow{
				AggName:   subFullKey,
				BucketKey: fBucketKey,
				DocCount:  int64(len(fDocs)),
				Value:     float64(len(fDocs)),
			})
			if len(subSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(subFullKey, parentBucketKey, subSpec.SubAggs(), fDocs, out, idxSchema)
			}
		case subSpec.Filters != nil:
			emitRuntimeFiltersAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out, idxSchema)
		case subSpec.Missing != nil:
			clean := strings.TrimSuffix(strings.TrimSuffix(subSpec.Missing.Field, ".keyword"), ".ngram")
			var mDocs []runtimeMatchedDoc
			for _, md := range bDocs {
				effSchema := md.EffectiveSchema(idxSchema)
				pathSegs := strings.Split(clean, ".")
				if effSchema != nil {
					if b := effSchema.ResolveField(subSpec.Missing.Field); len(b.SourceJSONPath) > 0 {
						pathSegs = b.SourceJSONPath
					}
				}
				if len(collectSchemaAwareScalarValues(md.doc, subSpec.Missing.Field, pathSegs, effSchema)) == 0 {
					mDocs = append(mDocs, md)
				}
			}
			mBucketKey := "_missing"
			if parentBucketKey != "" {
				mBucketKey = parentBucketKey
			}
			*out = append(*out, AggRow{
				AggName:   subFullKey,
				BucketKey: mBucketKey,
				DocCount:  int64(len(mDocs)),
				Value:     float64(len(mDocs)),
			})
			if len(subSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(subFullKey, parentBucketKey, subSpec.SubAggs(), mDocs, out, idxSchema)
			}
		case subSpec.Nested != nil:
			pathSegs := strings.Split(subSpec.Nested.Path, ".")
			nSchema := deriveNestedEvalSchema(idxSchema, subSpec.Nested.Path)
			var nDocs []runtimeMatchedDoc
			for _, md := range bDocs {
				rDoc := md.rootDoc
				if rDoc == nil {
					rDoc = md.doc
				}
				rSchema := md.rootSchema
				if rSchema == nil {
					rSchema = md.EffectiveSchema(idxSchema)
				}
				for _, cand := range extractNestedElementsAtPath(md.doc, pathSegs) {
					elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
					if idStr, ok := rDoc["__meta_id"].(string); ok && idStr != "" {
						elemDoc["__meta_id"] = idStr
					} else if md.hit.ID != "" {
						elemDoc["__meta_id"] = md.hit.ID
					}
					ancs := make(map[string]runtimeNestedAncestor, len(md.nestedAncestors)+1)
					for k, v := range md.nestedAncestors {
						ancs[k] = v
					}
					ancs[subSpec.Nested.Path] = runtimeNestedAncestor{
						doc:    elemDoc,
						schema: nSchema,
						elemID: fmt.Sprintf("%s#%s#%d", md.hit.ID, subSpec.Nested.Path, len(nDocs)),
					}
					hitCopy := md.hit
					hitCopy.Schema = nSchema
					nDocs = append(nDocs, runtimeMatchedDoc{
						hit:             hitCopy,
						doc:             elemDoc,
						rootDoc:         rDoc,
						rootSchema:      rSchema,
						nestedAncestors: ancs,
					})
				}
			}
			nBucketKey := "_nested_doc_count"
			if parentBucketKey != "" {
				nBucketKey = parentBucketKey
			}
			*out = append(*out, AggRow{
				AggName:   subFullKey,
				BucketKey: nBucketKey,
				DocCount:  int64(len(nDocs)),
				Value:     float64(len(nDocs)),
			})
			if len(subSpec.SubAggs()) > 0 {
				if parentBucketKey == "" {
					directSub, groupedSub := splitNestedSubAggsByBucketKeyMode(subSpec.SubAggs())
					if len(directSub) > 0 {
						emitRuntimeAllSubAggRows(subFullKey, "", directSub, nDocs, out, nSchema)
					}
					if len(groupedSub) > 0 {
						emitRuntimeAllSubAggRows(subFullKey, "_nested_doc_count", groupedSub, nDocs, out, nSchema)
					}
				} else {
					emitRuntimeAllSubAggRows(subFullKey, parentBucketKey, subSpec.SubAggs(), nDocs, out, nSchema)
				}
			}
		case subSpec.ReverseNested != nil:
			rnDocs, rnSchema := restoreRootDocsForReverseNested(bDocs, reverseNestedPath(subSpec.ReverseNested), idxSchema)
			rnBucketKey := "_reverse_nested"
			if parentBucketKey != "" {
				rnBucketKey = parentBucketKey
			}
			*out = append(*out, AggRow{
				AggName:   subFullKey,
				BucketKey: rnBucketKey,
				DocCount:  int64(len(rnDocs)),
				Value:     float64(len(rnDocs)),
			})
			if len(subSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(subFullKey, parentBucketKey, subSpec.SubAggs(), rnDocs, out, rnSchema)
			}
		case subSpec.EffectiveSampler() != nil:
			sampledDocs := sampleDocsForSampler(bDocs, subSpec, idxSchema)
			sBucketKey := "_sampler"
			if parentBucketKey != "" {
				sBucketKey = parentBucketKey
			}
			*out = append(*out, AggRow{
				AggName:   subFullKey,
				BucketKey: sBucketKey,
				DocCount:  int64(len(sampledDocs)),
				Value:     float64(len(sampledDocs)),
			})
			if len(subSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(subFullKey, parentBucketKey, subSpec.SubAggs(), sampledDocs, out, idxSchema)
			}
		default:
			emitRuntimeMetricAggRows(subFullKey, parentBucketKey, subSpec, bDocs, out)
		}
	}
}

func emitRuntimeFiltersAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	if aggSpec.Filters == nil {
		return
	}
	matchedDocIdx := make([]bool, len(docs))
	if aggSpec.Filters.IsAnonymous {
		for i, fq := range aggSpec.Filters.AnonymousFilters {
			q := fq
			fk := strconv.Itoa(i)
			var fDocs []runtimeMatchedDoc
			for docIdx, md := range docs {
				if evalBranchMatchesDoc(idxSchema, md.doc, &q) {
					fDocs = append(fDocs, md)
					matchedDocIdx[docIdx] = true
				}
			}
			rowKey := fk
			if parentBucketKey != "" {
				rowKey = parentBucketKey + "\x1f" + fk
			}
			*out = append(*out, AggRow{
				AggName:   fullAggName,
				BucketKey: rowKey,
				DocCount:  int64(len(fDocs)),
				Value:     float64(len(fDocs)),
			})
			if len(aggSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(fullAggName, rowKey, aggSpec.SubAggs(), fDocs, out, idxSchema)
			}
		}
	} else {
		fKeys := make([]string, 0, len(aggSpec.Filters.Filters))
		for fk := range aggSpec.Filters.Filters {
			fKeys = append(fKeys, fk)
		}
		sort.Strings(fKeys)
		for _, fk := range fKeys {
			fq := aggSpec.Filters.Filters[fk]
			var fDocs []runtimeMatchedDoc
			for docIdx, md := range docs {
				if evalBranchMatchesDoc(idxSchema, md.doc, &fq) {
					fDocs = append(fDocs, md)
					matchedDocIdx[docIdx] = true
				}
			}
			rowKey := fk
			if parentBucketKey != "" {
				rowKey = parentBucketKey + "\x1f" + fk
			}
			*out = append(*out, AggRow{
				AggName:   fullAggName,
				BucketKey: rowKey,
				DocCount:  int64(len(fDocs)),
				Value:     float64(len(fDocs)),
			})
			if len(aggSpec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(fullAggName, rowKey, aggSpec.SubAggs(), fDocs, out, idxSchema)
			}
		}
	}
	if aggSpec.Filters.OtherBucket {
		otherKey := aggSpec.Filters.EffectiveOtherBucketKey()
		var otherDocs []runtimeMatchedDoc
		for docIdx, md := range docs {
			if !matchedDocIdx[docIdx] {
				otherDocs = append(otherDocs, md)
			}
		}
		rowKey := otherKey
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + otherKey
		}
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  int64(len(otherDocs)),
			Value:     float64(len(otherDocs)),
		})
		if len(aggSpec.SubAggs()) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, aggSpec.SubAggs(), otherDocs, out, idxSchema)
		}
	}
}

func emitRuntimeCompositeAggRows(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	comp := aggSpec.Composite
	if comp == nil || len(comp.Sources) == 0 {
		return
	}
	var srcSpecs []esast.AggSpec
	for _, srcMap := range comp.Sources {
		var ks []string
		for k := range srcMap {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			srcSpecs = append(srcSpecs, srcMap[k])
		}
	}
	nowUTC := time.Now().UTC()
	extractDocSourceKeys := func(md runtimeMatchedDoc, src esast.AggSpec) []string {
		switch {
		case src.Terms != nil:
			tSpec := src.Terms
			mSpec := &esast.MetricAggSpec{
				Field:   tSpec.Field,
				Missing: tSpec.Missing,
				Script:  tSpec.Script,
			}
			rawVals := extractDocRawValuesForMetric(md, mSpec)
			if len(rawVals) == 0 && tSpec.MissingBucket {
				return []string{"__ES_MISSING_BUCKET__"}
			}
			var keys []string
			seen := make(map[string]bool, len(rawVals))
			effSchema := md.EffectiveSchema(idxSchema)
			isBool := false
			isLower := false
			isDate := false
			isDateNanos := false
			if effSchema != nil && tSpec.Field != "" && tSpec.Script == nil {
				b := effSchema.ResolveField(tSpec.Field)
				if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
					isBool = true
				}
				if b.ESType == "date" || b.ESType == "date_nanos" {
					isDate = true
					isDateNanos = b.ESType == "date_nanos"
				}
				if b.EffectiveLowercase(true) {
					isLower = true
				}
			}
			for _, rv := range rawVals {
				if rv == nil {
					if tSpec.MissingBucket {
						if !seen["__ES_MISSING_BUCKET__"] {
							seen["__ES_MISSING_BUCKET__"] = true
							keys = append(keys, "__ES_MISSING_BUCKET__")
						}
					}
					continue
				}
				ks := fmt.Sprintf("%v", rv)
				if isDate {
					trimmed := strings.TrimSpace(ks)
					if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
						if isDateNanos && (iv > 1_000_000_000_000_000 || iv < -1_000_000_000_000_000) {
							iv /= 1_000_000
						}
						ks = strconv.FormatInt(iv, 10)
					} else if ms, ok := schema.ParseESDateToEpochMillis(trimmed, nowUTC); ok {
						ks = strconv.FormatInt(ms, 10)
					}
				} else if isBool {
					switch strings.ToLower(strings.TrimSpace(ks)) {
					case "true", "1":
						ks = "true"
					case "false", "0":
						ks = "false"
					}
				} else if isLower {
					ks = strings.ToLower(ks)
				}
				if !seen[ks] {
					seen[ks] = true
					keys = append(keys, ks)
				}
			}
			return keys
		case src.Histogram != nil:
			hSpec := src.Histogram
			interval := hSpec.Interval
			if interval <= 0 {
				interval = 1.0
			}
			offset := hSpec.Offset
			vals := extractDocNumericValuesForBucket(md, hSpec.Field, hSpec.Missing, hSpec.Script)
			if len(vals) == 0 && hSpec.MissingBucket {
				return []string{"__ES_MISSING_BUCKET__"}
			}
			var keys []string
			seen := make(map[string]bool, len(vals))
			for _, f := range vals {
				b := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				ks := strconv.FormatFloat(b, 'f', -1, 64)
				if !seen[ks] {
					seen[ks] = true
					keys = append(keys, ks)
				}
			}
			return keys
		case src.DateHistogram != nil:
			dh := src.DateHistogram
			intervalMs := dh.EffectiveIntervalMs()
			if intervalMs <= 0 {
				intervalMs = 86400000
			}
			tzShiftMs := dh.EffectiveTimeZoneOffsetMs() - dh.EffectiveOffsetMs()
			tsList := extractDocDateMillisForBucket(idxSchema, md, dh.Field, dh.Missing, dh.Script, nowUTC)
			if len(tsList) == 0 && dh.MissingBucket {
				return []string{"__ES_MISSING_BUCKET__"}
			}
			var keys []string
			seen := make(map[string]bool, len(tsList))
			for _, ts := range tsList {
				b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
				ks := strconv.FormatInt(b, 10)
				if !seen[ks] {
					seen[ks] = true
					keys = append(keys, ks)
				}
			}
			return keys
		}
		return nil
	}

	byBucket := make(map[string][]runtimeMatchedDoc)
	var keys []string
	for _, md := range docs {
		combos := [][]string{{}}
		valid := true
		for _, src := range srcSpecs {
			sKeys := extractDocSourceKeys(md, src)
			if len(sKeys) == 0 {
				valid = false
				break
			}
			var nextCombos [][]string
			for _, prefix := range combos {
				for _, sk := range sKeys {
					cp := make([]string, len(prefix)+1)
					copy(cp, prefix)
					cp[len(prefix)] = sk
					nextCombos = append(nextCombos, cp)
				}
			}
			combos = nextCombos
		}
		if !valid {
			continue
		}
		seenDocCombo := make(map[string]bool, len(combos))
		for _, c := range combos {
			ck := strings.Join(c, "\x1f")
			if !seenDocCombo[ck] {
				seenDocCombo[ck] = true
				if _, exists := byBucket[ck]; !exists {
					keys = append(keys, ck)
				}
				byBucket[ck] = append(byBucket[ck], md)
			}
		}
	}
	sort.Strings(keys)
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowKey := k
		if parentBucketKey != "" {
			rowKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func emitRuntimeTermsScriptAggRowsWithSchema(
	fullAggName string,
	parentBucketKey string,
	aggSpec esast.AggSpec,
	docs []runtimeMatchedDoc,
	out *[]AggRow,
	idxSchema *schema.IndexSchema,
) {
	tSpec := aggSpec.EffectiveTerms()
	if tSpec == nil {
		return
	}
	byBucket, keys := computeRuntimeTermsScriptBucketDocsWithSchema(idxSchema, docs, tSpec)
	subAggs := aggSpec.SubAggs()
	for _, k := range keys {
		bDocs := byBucket[k]
		rowBucketKey := k
		if parentBucketKey != "" {
			rowBucketKey = parentBucketKey + "\x1f" + k
		}
		cnt := int64(len(bDocs))
		*out = append(*out, AggRow{
			AggName:   fullAggName,
			BucketKey: rowBucketKey,
			DocCount:  cnt,
			Value:     float64(cnt),
		})
		if len(subAggs) > 0 {
			emitRuntimeAllSubAggRows(fullAggName, rowBucketKey, subAggs, bDocs, out, idxSchema)
		}
	}
}

func dropRuntimeAggRows(aggRows []AggRow, fullKey, parentBucketKey string) []AggRow {
	kept := make([]AggRow, 0, len(aggRows))
	prefix := fullKey + "."
	for _, r := range aggRows {
		if r.AggName == fullKey || strings.HasPrefix(r.AggName, prefix) {
			if parentBucketKey == "" || r.BucketKey == parentBucketKey || strings.HasPrefix(r.BucketKey, parentBucketKey+"\x1f") || strings.HasPrefix(r.BucketKey, parentBucketKey+"\x00") {
				continue
			}
		}
		kept = append(kept, r)
	}
	return kept
}

func partitionDocsByParentBucket(idxSchema *schema.IndexSchema, docs []runtimeMatchedDoc, spec esast.AggSpec, pbKey string) []runtimeMatchedDoc {
	leafKey := pbKey
	if idx := strings.LastIndex(pbKey, "\x1f"); idx >= 0 {
		leafKey = pbKey[idx+1:]
	}
	switch {
	case spec.EffectiveTerms() != nil:
		byB, _ := computeRuntimeTermsScriptBucketDocsWithSchema(idxSchema, docs, spec.EffectiveTerms())
		return byB[leafKey]
	case spec.Histogram != nil:
		hSpec := spec.Histogram
		interval := hSpec.Interval
		if interval <= 0 {
			interval = 1.0
		}
		offset := hSpec.Offset
		if lf, ok := parseFiniteFloat(leafKey); ok {
			leafKey = strconv.FormatFloat(math.Round(lf*1e12)/1e12, 'f', -1, 64)
		}
		var out []runtimeMatchedDoc
		for _, md := range docs {
			vals := extractDocNumericValuesForBucket(md, hSpec.Field, hSpec.Missing, hSpec.Script)
			if leafKey == "__ES_MISSING_BUCKET__" {
				if len(vals) == 0 {
					out = append(out, md)
				}
				continue
			}
			for _, f := range vals {
				b := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				if strconv.FormatFloat(b, 'f', -1, 64) == leafKey {
					out = append(out, md)
					break
				}
			}
		}
		return out
	case spec.DateHistogram != nil:
		dh := spec.DateHistogram
		intervalMs := dh.EffectiveIntervalMs()
		if intervalMs <= 0 {
			intervalMs = 86400000
		}
		tzShiftMs := dh.EffectiveTimeZoneOffsetMs() - dh.EffectiveOffsetMs()
		nowUTC := time.Now().UTC()
		var out []runtimeMatchedDoc
		for _, md := range docs {
			tsList := extractDocDateMillisForBucket(idxSchema, md, dh.Field, dh.Missing, dh.Script, nowUTC)
			if leafKey == "__ES_MISSING_BUCKET__" {
				if len(tsList) == 0 {
					out = append(out, md)
				}
				continue
			}
			for _, ts := range tsList {
				b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
				if strconv.FormatInt(b, 10) == leafKey {
					out = append(out, md)
					break
				}
			}
		}
		return out
	case spec.EffectiveRange() != nil:
		rngSpec := spec.EffectiveRange()
		nowUTC := time.Now().UTC()
		for _, rng := range rngSpec.Ranges {
			if rng.EffectiveKey() != leafKey {
				continue
			}
			return filterDocsMatchingRangeEntry(idxSchema, docs, spec, rngSpec, rng, nowUTC)
		}
	case spec.Composite != nil:
		allParts := splitCompositeBucketKey(pbKey)
		nSrc := len(spec.Composite.Sources)
		if len(allParts) < nSrc {
			return docs
		}
		compParts := allParts[len(allParts)-nSrc:]
		cur := docs
		for i, srcMap := range spec.Composite.Sources {
			partKey := compParts[i]
			for _, srcSpec := range srcMap {
				var subSpec esast.AggSpec
				if srcSpec.Terms != nil {
					subSpec.Terms = srcSpec.Terms
				} else if srcSpec.Histogram != nil {
					subSpec.Histogram = srcSpec.Histogram
				} else if srcSpec.DateHistogram != nil {
					subSpec.DateHistogram = srcSpec.DateHistogram
				}
				cur = partitionDocsByParentBucket(idxSchema, cur, subSpec, partKey)
				break
			}
		}
		return cur
	}
	return docs
}

func applyRuntimeScriptAggsForMap(
	prefix string,
	parentBucketKey string,
	aggs map[string]esast.AggSpec,
	docs []runtimeMatchedDoc,
	globalDocs []runtimeMatchedDoc,
	aggRows []AggRow,
	idxSchema *schema.IndexSchema,
) []AggRow {
	for aggName, spec := range aggs {
		fullKey := aggName
		if prefix != "" {
			fullKey = prefix + "." + aggName
		}
		switch {
		case spec.EffectiveTerms() != nil && spec.EffectiveTerms().Script != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeTermsScriptAggRowsWithSchema(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.RareTerms != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeRareTermsAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.MultiTerms != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeMultiTermsAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.Histogram != nil && spec.Histogram.Script != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeHistogramAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.DateHistogram != nil && spec.DateHistogram.Script != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeDateHistogramAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.AutoDateHistogram != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeAutoDateHistogramAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.VariableWidthHistogram != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeVariableWidthHistogramAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.EffectiveRange() != nil && spec.EffectiveRange().Script != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeRangeAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.GeoDistance != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeGeoDistanceAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.GeohashGrid != nil || spec.GeotileGrid != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeGeoGridAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.AdjacencyMatrix != nil:
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeAdjacencyMatrixAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.Composite != nil && aggSpecHasDirectRuntimeScript(spec):
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeCompositeAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
		case spec.Filter != nil && (queryHasRuntimeScript(spec.Filter) || aggsHaveRuntimeScript(spec.SubAggs())):
			var fDocs []runtimeMatchedDoc
			for _, md := range docs {
				if evalBranchMatchesDoc(idxSchema, md.doc, spec.Filter) {
					fDocs = append(fDocs, md)
				}
			}
			if queryHasRuntimeScript(spec.Filter) {
				aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
				fBucketKey := "_filter"
				if parentBucketKey != "" {
					fBucketKey = parentBucketKey
				}
				aggRows = append(aggRows, AggRow{
					AggName:   fullKey,
					BucketKey: fBucketKey,
					DocCount:  int64(len(fDocs)),
					Value:     float64(len(fDocs)),
				})
				if len(spec.SubAggs()) > 0 {
					emitRuntimeAllSubAggRows(fullKey, parentBucketKey, spec.SubAggs(), fDocs, &aggRows, idxSchema)
				}
			} else {
				aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), fDocs, globalDocs, aggRows, idxSchema)
			}
		case spec.Filters != nil && (aggSpecHasDirectRuntimeScript(spec) || aggsHaveRuntimeScript(spec.SubAggs())):
			if aggSpecHasDirectRuntimeScript(spec) {
				aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
				emitRuntimeFiltersAggRows(fullKey, parentBucketKey, spec, docs, &aggRows, idxSchema)
			} else {
				matchedDocIdx := make([]bool, len(docs))
				if spec.Filters.IsAnonymous {
					for i, fq := range spec.Filters.AnonymousFilters {
						q := fq
						fk := strconv.Itoa(i)
						var fDocs []runtimeMatchedDoc
						for docIdx, md := range docs {
							if evalBranchMatchesDoc(idxSchema, md.doc, &q) {
								fDocs = append(fDocs, md)
								matchedDocIdx[docIdx] = true
							}
						}
						rowKey := fk
						if parentBucketKey != "" {
							rowKey = parentBucketKey + "\x1f" + fk
						}
						aggRows = applyRuntimeScriptAggsForMap(fullKey, rowKey, spec.SubAggs(), fDocs, globalDocs, aggRows, idxSchema)
					}
				} else {
					for fk, fq := range spec.Filters.Filters {
						q := fq
						var fDocs []runtimeMatchedDoc
						for docIdx, md := range docs {
							if evalBranchMatchesDoc(idxSchema, md.doc, &q) {
								fDocs = append(fDocs, md)
								matchedDocIdx[docIdx] = true
							}
						}
						rowKey := fk
						if parentBucketKey != "" {
							rowKey = parentBucketKey + "\x1f" + fk
						}
						aggRows = applyRuntimeScriptAggsForMap(fullKey, rowKey, spec.SubAggs(), fDocs, globalDocs, aggRows, idxSchema)
					}
				}
				if spec.Filters.OtherBucket {
					otherKey := spec.Filters.EffectiveOtherBucketKey()
					var otherDocs []runtimeMatchedDoc
					for docIdx, md := range docs {
						if !matchedDocIdx[docIdx] {
							otherDocs = append(otherDocs, md)
						}
					}
					rowKey := otherKey
					if parentBucketKey != "" {
						rowKey = parentBucketKey + "\x1f" + otherKey
					}
					aggRows = applyRuntimeScriptAggsForMap(fullKey, rowKey, spec.SubAggs(), otherDocs, globalDocs, aggRows, idxSchema)
				}
			}
		case spec.ReverseNested != nil && (reverseNestedPath(spec.ReverseNested) != "" || aggsHaveRuntimeScript(spec.SubAggs())):
			rnDocs, rnSchema := restoreRootDocsForReverseNested(docs, reverseNestedPath(spec.ReverseNested), idxSchema)
			if reverseNestedPath(spec.ReverseNested) != "" {
				aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
				rnBucketKey := "_reverse_nested"
				if parentBucketKey != "" {
					rnBucketKey = parentBucketKey
				}
				aggRows = append(aggRows, AggRow{
					AggName:   fullKey,
					BucketKey: rnBucketKey,
					DocCount:  int64(len(rnDocs)),
					Value:     float64(len(rnDocs)),
				})
				if len(spec.SubAggs()) > 0 {
					emitRuntimeAllSubAggRows(fullKey, parentBucketKey, spec.SubAggs(), rnDocs, &aggRows, rnSchema)
				}
			} else {
				aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), rnDocs, globalDocs, aggRows, rnSchema)
			}
		case spec.EffectiveSampler() != nil:
			sampledDocs := sampleDocsForSampler(docs, spec, idxSchema)
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			sBucketKey := "_sampler"
			if parentBucketKey != "" {
				sBucketKey = parentBucketKey
			}
			aggRows = append(aggRows, AggRow{
				AggName:   fullKey,
				BucketKey: sBucketKey,
				DocCount:  int64(len(sampledDocs)),
				Value:     float64(len(sampledDocs)),
			})
			if len(spec.SubAggs()) > 0 {
				emitRuntimeAllSubAggRows(fullKey, parentBucketKey, spec.SubAggs(), sampledDocs, &aggRows, idxSchema)
			}
		case aggSpecHasDirectRuntimeScript(spec):
			aggRows = dropRuntimeAggRows(aggRows, fullKey, parentBucketKey)
			emitRuntimeMetricAggRows(fullKey, parentBucketKey, spec, docs, &aggRows)
		case aggsHaveRuntimeScript(spec.SubAggs()):
			switch {
			case spec.Global != nil:
				gDocs := globalDocs
				if len(gDocs) == 0 {
					gDocs = docs
				}
				aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), gDocs, globalDocs, aggRows, idxSchema)
			case spec.ReverseNested != nil:
				rnDocs, rnSchema := restoreRootDocsForReverseNested(docs, reverseNestedPath(spec.ReverseNested), idxSchema)
				aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), rnDocs, globalDocs, aggRows, rnSchema)
			case spec.EffectiveSampler() != nil:
				aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), docs, globalDocs, aggRows, idxSchema)
			case spec.Missing != nil:
				clean := strings.TrimSuffix(strings.TrimSuffix(spec.Missing.Field, ".keyword"), ".ngram")
				var mDocs []runtimeMatchedDoc
				for _, md := range docs {
					effSchema := md.EffectiveSchema(idxSchema)
					pathSegs := strings.Split(clean, ".")
					if effSchema != nil {
						if b := effSchema.ResolveField(spec.Missing.Field); len(b.SourceJSONPath) > 0 {
							pathSegs = b.SourceJSONPath
						}
					}
					if len(collectSchemaAwareScalarValues(md.doc, spec.Missing.Field, pathSegs, effSchema)) == 0 {
						mDocs = append(mDocs, md)
					}
				}
				aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), mDocs, globalDocs, aggRows, idxSchema)
			case spec.Nested != nil:
				pathSegs := strings.Split(spec.Nested.Path, ".")
				nSchema := deriveNestedEvalSchema(idxSchema, spec.Nested.Path)
				var nDocs []runtimeMatchedDoc
				for _, md := range docs {
					rDoc := md.rootDoc
					if rDoc == nil {
						rDoc = md.doc
					}
					rSchema := md.rootSchema
					if rSchema == nil {
						rSchema = md.EffectiveSchema(idxSchema)
					}
					for _, cand := range extractNestedElementsAtPath(md.doc, pathSegs) {
						elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
						if idStr, ok := rDoc["__meta_id"].(string); ok && idStr != "" {
							elemDoc["__meta_id"] = idStr
						} else if md.hit.ID != "" {
							elemDoc["__meta_id"] = md.hit.ID
						}
						ancs := make(map[string]runtimeNestedAncestor, len(md.nestedAncestors)+1)
						for k, v := range md.nestedAncestors {
							ancs[k] = v
						}
						ancs[spec.Nested.Path] = runtimeNestedAncestor{
							doc:    elemDoc,
							schema: nSchema,
							elemID: fmt.Sprintf("%s#%s#%d", md.hit.ID, spec.Nested.Path, len(nDocs)),
						}
						hitCopy := md.hit
						hitCopy.Schema = nSchema
						nDocs = append(nDocs, runtimeMatchedDoc{
							hit:             hitCopy,
							doc:             elemDoc,
							rootDoc:         rDoc,
							rootSchema:      rSchema,
							nestedAncestors: ancs,
						})
					}
				}
				if parentBucketKey == "" {
					directSub, groupedSub := splitNestedSubAggsByBucketKeyMode(spec.SubAggs())
					if len(directSub) > 0 {
						aggRows = applyRuntimeScriptAggsForMap(fullKey, "", directSub, nDocs, globalDocs, aggRows, nSchema)
					}
					if len(groupedSub) > 0 {
						aggRows = applyRuntimeScriptAggsForMap(fullKey, "_nested_doc_count", groupedSub, nDocs, globalDocs, aggRows, nSchema)
					}
				} else {
					aggRows = applyRuntimeScriptAggsForMap(fullKey, parentBucketKey, spec.SubAggs(), nDocs, globalDocs, aggRows, nSchema)
				}
			default:
				var parentBuckets []string
				seenPB := make(map[string]bool)
				for _, r := range aggRows {
					if r.AggName == fullKey && (parentBucketKey == "" || strings.HasPrefix(r.BucketKey, parentBucketKey+"\x1f")) {
						if !seenPB[r.BucketKey] {
							seenPB[r.BucketKey] = true
							parentBuckets = append(parentBuckets, r.BucketKey)
						}
					}
				}
				for _, pbKey := range parentBuckets {
					pbDocs := partitionDocsByParentBucket(idxSchema, docs, spec, pbKey)
					aggRows = applyRuntimeScriptAggsForMap(fullKey, pbKey, spec.SubAggs(), pbDocs, globalDocs, aggRows, idxSchema)
				}
			}
		}
	}
	return aggRows
}

func hitsToRuntimeMatchedDocs(hits []HitRow, idxSchema *schema.IndexSchema) []runtimeMatchedDoc {
	out := make([]runtimeMatchedDoc, 0, len(hits))
	for _, h := range hits {
		var doc map[string]any
		src := h.EffectiveSource()
		if len(src) > 0 {
			dec := json.NewDecoder(bytes.NewReader(src))
			dec.UseNumber()
			_ = dec.Decode(&doc)
		}
		if doc == nil {
			doc = make(map[string]any)
		}
		doc["__meta_id"] = h.ID
		if h.Index != "" {
			doc["__meta_index"] = h.Index
		}
		if h.Version > 0 {
			doc["__meta_version"] = h.Version
		} else {
			doc["__meta_version"] = int64(1)
		}
		out = append(out, runtimeMatchedDoc{
			hit:        h,
			doc:        doc,
			rootDoc:    doc,
			rootSchema: idxSchema,
		})
	}
	return out
}

func applyRuntimeScriptAggsOnlyWithGlobal(matchedQueryHits []HitRow, globalHits []HitRow, aggRows []AggRow, idxTotal int64, req *esast.SearchRequest, idxSchema *schema.IndexSchema) []AggRow {
	foundTotalMeta := false
	foundQueryMeta := false
	prePostQueryTotal := int64(len(matchedQueryHits))
	if prePostQueryTotal < idxTotal {
		prePostQueryTotal = idxTotal
	}
	for i := range aggRows {
		switch aggRows[i].AggName {
		case "__meta_total":
			aggRows[i].DocCount = idxTotal
			aggRows[i].Value = float64(idxTotal)
			foundTotalMeta = true
		case "__meta_query_total":
			if req != nil && req.PostFilter != nil {
				aggRows[i].DocCount = prePostQueryTotal
				aggRows[i].Value = float64(prePostQueryTotal)
				foundQueryMeta = true
			}
		}
	}
	if !foundTotalMeta {
		aggRows = append(aggRows, AggRow{
			AggName:   "__meta_total",
			BucketKey: "_count",
			DocCount:  idxTotal,
			Value:     float64(idxTotal),
		})
	}
	if req != nil && req.PostFilter != nil && !foundQueryMeta {
		aggRows = append(aggRows, AggRow{
			AggName:   "__meta_query_total",
			BucketKey: "_count",
			DocCount:  prePostQueryTotal,
			Value:     float64(prePostQueryTotal),
		})
	}
	effAggs := req.EffectiveAggs()
	hasRuntimeMappings := req != nil && len(effectiveRuntimeMappings(idxSchema, req.RuntimeMappings)) > 0
	if req != nil && req.AliasFilter != nil {
		afQ := esast.Query(*req.AliasFilter)
		if queryHasRuntimeScript(&afQ) || hasRuntimeMappings {
			for aggName, spec := range effAggs {
				if spec.Global != nil {
					for i := range aggRows {
						if aggRows[i].AggName == aggName && aggRows[i].BucketKey == "_global" {
							aggRows[i].DocCount = int64(len(globalHits))
							aggRows[i].Value = float64(len(globalHits))
						}
					}
				}
			}
		}
	}
	if !aggsHaveRuntimeScript(effAggs) && !hasRuntimeMappings {
		return aggRows
	}
	matchedDocs := hitsToRuntimeMatchedDocs(matchedQueryHits, idxSchema)
	var globalDocs []runtimeMatchedDoc
	if len(globalHits) > 0 {
		globalDocs = hitsToRuntimeMatchedDocs(globalHits, idxSchema)
	}
	if hasRuntimeMappings && len(effAggs) > 0 {
		var metaRows []AggRow
		for _, r := range aggRows {
			if strings.HasPrefix(r.AggName, "__meta_") {
				metaRows = append(metaRows, r)
			}
		}
		aggRows = metaRows
		for aggName, spec := range effAggs {
			single := map[string]esast.AggSpec{aggName: spec}
			if spec.Global != nil {
				gDocs := globalDocs
				if len(gDocs) == 0 {
					gDocs = matchedDocs
				}
				emitRuntimeAllSubAggRows("", "", single, gDocs, &aggRows, idxSchema)
			} else {
				emitRuntimeAllSubAggRows("", "", single, matchedDocs, &aggRows, idxSchema)
			}
		}
		return aggRows
	}
	return applyRuntimeScriptAggsForMap("", "", effAggs, matchedDocs, globalDocs, aggRows, idxSchema)
}

func applyRuntimeSearchScripts(hits []HitRow, aggRows []AggRow, idxTotal int64, req *esast.SearchRequest, idxSchema *schema.IndexSchema, isMultiIndex bool) ([]HitRow, []AggRow, int64) {
	outHits, outAggs, outTotal, _ := applyRuntimeSearchScriptsWithMatched(hits, aggRows, idxTotal, req, idxSchema, isMultiIndex)
	return outHits, outAggs, outTotal
}

func applyRuntimeSearchScriptsWithMatched(hits []HitRow, aggRows []AggRow, idxTotal int64, req *esast.SearchRequest, idxSchema *schema.IndexSchema, isMultiIndex bool) ([]HitRow, []AggRow, int64, []HitRow) {
	outHits, outAggs, outTotal, matchedHits, _ := applyRuntimeSearchScriptsWithMatchedAndGlobal(hits, nil, aggRows, idxTotal, req, idxSchema, isMultiIndex)
	return outHits, outAggs, outTotal, matchedHits
}

func applyRuntimeSearchScriptsWithMatchedAndGlobal(hits []HitRow, globalHits []HitRow, aggRows []AggRow, idxTotal int64, req *esast.SearchRequest, idxSchema *schema.IndexSchema, isMultiIndex bool) ([]HitRow, []AggRow, int64, []HitRow, []HitRow) {
	if req == nil {
		return hits, aggRows, idxTotal, hits, hits
	}
	hasRuntimeMappings := len(effectiveRuntimeMappings(idxSchema, req.RuntimeMappings)) > 0
	hasQueryScript := queryHasRuntimeScript(req.Query)
	hasNestedScoring := queryHasNestedScoring(req.Query)
	var aliasFilterQ *esast.Query
	if req.AliasFilter != nil {
		q := esast.Query(*req.AliasFilter)
		aliasFilterQ = &q
	}
	hasAliasScript := queryHasRuntimeScript(aliasFilterQ)
	hasNestedMinScore := queryHasMinScore(req.Query) && (req.Query == nil || req.Query.FunctionScore == nil || queryHasMinScore(req.Query.FunctionScore.Query))
	hasMinScore := req.MinScore != nil || queryHasMinScore(req.Query) || queryHasMinScore(aliasFilterQ)
	hasPostScript := queryHasRuntimeScript(req.PostFilter)
	filteredQueryHits := make([]HitRow, 0, len(hits))
	postFilteredHits := make([]HitRow, 0, len(hits))

	for _, h := range hits {
		var doc map[string]any
		src := h.EffectiveSource()
		if len(src) > 0 {
			dec := json.NewDecoder(bytes.NewReader(src))
			dec.UseNumber()
			_ = dec.Decode(&doc)
		}
		if doc == nil {
			doc = make(map[string]any)
		}
		doc["__meta_id"] = h.ID
		if h.Index != "" {
			doc["__meta_index"] = h.Index
		}
		if h.Version > 0 {
			doc["__meta_version"] = h.Version
		} else {
			doc["__meta_version"] = int64(1)
		}
		if hasRuntimeMappings {
			if aliasFilterQ != nil && !evalBranchMatchesDoc(idxSchema, doc, aliasFilterQ) {
				continue
			}
			if req.Query != nil && !evalBranchMatchesDoc(idxSchema, doc, req.Query) {
				continue
			}
		} else {
			if (hasAliasScript || queryHasMinScore(aliasFilterQ)) && !evalQueryScriptFilterOnDocWithSchema(idxSchema, doc, aliasFilterQ) {
				continue
			}
			baseScore := h.Score
			if req.Query != nil && ((req.Query.ScriptScore != nil && req.Query.ScriptScore.Query == nil) || (req.Query.FunctionScore != nil && req.Query.FunctionScore.Query == nil)) {
				baseScore = 1.0
			}
			if (hasQueryScript || hasNestedMinScore) && !evalQueryScriptFilterOnDocWithScore(idxSchema, doc, req.Query, baseScore) {
				continue
			}
		}
		baseScore := h.Score
		if req.Query != nil && ((req.Query.ScriptScore != nil && req.Query.ScriptScore.Query == nil) || (req.Query.FunctionScore != nil && req.Query.FunctionScore.Query == nil)) {
			baseScore = 1.0
		}
		if hasRuntimeMappings {
			if hasQueryScript || hasNestedScoring {
				h.Score = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, req.Query, baseScore)
			} else if req.Query != nil {
				h.Score = scoreNonScriptClauseOnDoc(idxSchema, doc, req.Query)
			}
		} else if hasQueryScript || hasNestedScoring || hasNestedMinScore {
			h.Score = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, req.Query, baseScore)
		}
		if req.IndicesBoost != nil {
			if ib, ok := req.IndicesBoost["__current_index__"]; ok {
				h.Score *= ib
			} else if ib, ok := req.IndicesBoost[h.Index]; ok {
				h.Score *= ib
			}
		}
		if req.MinScore != nil && h.Score < *req.MinScore {
			continue
		}
		if req.Query != nil && req.Query.FunctionScore != nil && req.Query.FunctionScore.MinScore != nil && h.Score < *req.Query.FunctionScore.MinScore {
			continue
		}
		if req.Query != nil && req.Query.ScriptScore != nil && req.Query.ScriptScore.MinScore != nil && h.Score < *req.Query.ScriptScore.MinScore {
			continue
		}
		filteredQueryHits = append(filteredQueryHits, h)
		if req.PostFilter != nil {
			if hasPostScript || hasRuntimeMappings {
				if !evalBranchMatchesDoc(idxSchema, doc, req.PostFilter) {
					continue
				}
			} else if !docMatchesNonScriptClause(idxSchema, doc, req.PostFilter) {
				continue
			}
		}
		postFilteredHits = append(postFilteredHits, h)
	}

	var filteredGlobalHits []HitRow
	if len(globalHits) > 0 {
		for _, gh := range globalHits {
			if hasAliasScript || (hasRuntimeMappings && aliasFilterQ != nil) || queryHasMinScore(aliasFilterQ) {
				var gdoc map[string]any
				src := gh.EffectiveSource()
				if len(src) > 0 {
					dec := json.NewDecoder(bytes.NewReader(src))
					dec.UseNumber()
					_ = dec.Decode(&gdoc)
				}
				if gdoc == nil {
					gdoc = make(map[string]any)
				}
				gdoc["__meta_id"] = gh.ID
				if hasRuntimeMappings {
					if !evalBranchMatchesDoc(idxSchema, gdoc, aliasFilterQ) {
						continue
					}
				} else if !evalQueryScriptFilterOnDocWithSchema(idxSchema, gdoc, aliasFilterQ) {
					continue
				}
			}
			filteredGlobalHits = append(filteredGlobalHits, gh)
		}
	}

	if hasQueryScript || hasAliasScript || hasMinScore || hasRuntimeMappings {
		idxTotal = int64(len(filteredQueryHits))
	}
	prePostQueryTotal := idxTotal
	if len(filteredQueryHits) > 0 && int64(len(filteredQueryHits)) > prePostQueryTotal {
		prePostQueryTotal = int64(len(filteredQueryHits))
	}
	aggRows = applyRuntimeScriptAggsOnlyWithGlobal(filteredQueryHits, filteredGlobalHits, aggRows, idxTotal, req, idxSchema)
	if req.PostFilter != nil {
		idxTotal = int64(len(postFilteredHits))
		foundTotalMeta := false
		foundQueryMeta := false
		for i := range aggRows {
			switch aggRows[i].AggName {
			case "__meta_total":
				aggRows[i].DocCount = idxTotal
				aggRows[i].Value = float64(idxTotal)
				foundTotalMeta = true
			case "__meta_query_total":
				aggRows[i].DocCount = prePostQueryTotal
				aggRows[i].Value = float64(prePostQueryTotal)
				foundQueryMeta = true
			}
		}
		if !foundTotalMeta {
			aggRows = append(aggRows, AggRow{
				AggName:   "__meta_total",
				BucketKey: "_count",
				DocCount:  idxTotal,
				Value:     float64(idxTotal),
			})
		}
		if !foundQueryMeta {
			aggRows = append(aggRows, AggRow{
				AggName:   "__meta_query_total",
				BucketKey: "_count",
				DocCount:  prePostQueryTotal,
				Value:     float64(prePostQueryTotal),
			})
		}
	}

	effSorts := transpiler.EffectiveSortsForRequest(req)
	outHits := postFilteredHits
	if len(outHits) > 1 && (sortsHaveScript(effSorts) || hasQueryScript || hasNestedScoring || hasRuntimeMappings || hasMinScore) {
		sort.SliceStable(outHits, func(i, j int) bool {
			if len(effSorts) > 0 {
				if cmp := compareHitRowsBySort(outHits[i], outHits[j], effSorts, idxSchema); cmp != 0 {
					return cmp < 0
				}
			}
			if outHits[i].Score != outHits[j].Score {
				return outHits[i].Score > outHits[j].Score
			}
			return outHits[i].ID < outHits[j].ID
		})
	}
	if !isMultiIndex && len(req.Rescore) == 0 && req.Collapse != nil && req.Collapse.Field != "" && len(outHits) > 0 {
		seenCollapse := make(map[string]struct{}, len(outHits))
		deduped := make([]HitRow, 0, len(outHits))
		collapseSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: req.Collapse.Field}}}
		for _, h := range outHits {
			vals := extractHitSortValues(h, collapseSort, idxSchema)
			if len(vals) > 0 && vals[0] != nil {
				ck := normalizeCollapseGroupKey(vals[0], req.Collapse.Field, idxSchema, idxSchema)
				if _, exists := seenCollapse[ck]; exists {
					continue
				}
				seenCollapse[ck] = struct{}{}
			}
			if len(req.SearchAfter) > 0 && !hitIsAfterSearchAfter(h, effSorts, req.SearchAfter, idxSchema) {
				continue
			}
			deduped = append(deduped, h)
		}
		outHits = deduped
	} else if !isMultiIndex && len(req.Rescore) == 0 && len(req.SearchAfter) > 0 {
		afterFiltered := make([]HitRow, 0, len(outHits))
		for _, h := range outHits {
			if hitIsAfterSearchAfter(h, effSorts, req.SearchAfter, idxSchema) {
				afterFiltered = append(afterFiltered, h)
			}
		}
		outHits = afterFiltered
	}
	if !isMultiIndex {
		if req.TerminateAfter != nil && *req.TerminateAfter > 0 && len(outHits) > *req.TerminateAfter {
			outHits = outHits[:*req.TerminateAfter]
		}
		if len(req.Rescore) == 0 {
			from := 0
			if req.From != nil && *req.From > 0 && len(req.SearchAfter) == 0 {
				from = *req.From
			}
			size := 10
			if req.Size != nil {
				size = *req.Size
			}
			if from >= len(outHits) {
				outHits = nil
			} else {
				end := from + size
				if end > len(outHits) {
					end = len(outHits)
				}
				outHits = outHits[from:end]
			}
		}
	}
	for i := range outHits {
		outHits[i].TotalHits = idxTotal
	}
	return outHits, aggRows, idxTotal, filteredQueryHits, postFilteredHits
}

func maxRescoreWindow(req *esast.SearchRequest, defaultWin int) int {
	if req == nil || len(req.Rescore) == 0 {
		return 0
	}
	if defaultWin < 10 {
		defaultWin = 10
	}
	maxW := defaultWin
	for _, rs := range req.Rescore {
		if rs.Query == nil || rs.Query.RescoreQuery == nil {
			continue
		}
		if rs.WindowSize != nil && *rs.WindowSize > maxW {
			maxW = *rs.WindowSize
		}
	}
	return maxW
}

func (s *Server) applyRescoreToHits(
	req *esast.SearchRequest,
	hits []HitRow,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
	defaultWin int,
) []HitRow {
	if req == nil || len(req.Rescore) == 0 || len(hits) == 0 {
		return hits
	}
	if defaultWin < 10 {
		defaultWin = 10
	}
	effSorts := transpiler.EffectiveSortsForRequest(req)
	for _, rs := range req.Rescore {
		if rs.Query == nil || rs.Query.RescoreQuery == nil {
			continue
		}
		win := defaultWin
		if rs.WindowSize != nil && *rs.WindowSize > 0 {
			win = *rs.WindowSize
		}
		if win > len(hits) {
			win = len(hits)
		}
		qWeight := 1.0
		if rs.Query.QueryWeight != nil {
			qWeight = *rs.Query.QueryWeight
		}
		rWeight := 1.0
		if rs.Query.RescoreQueryWeight != nil {
			rWeight = *rs.Query.RescoreQueryWeight
		}
		mode := strings.ToLower(strings.TrimSpace(rs.Query.ScoreMode))
		for i := 0; i < win; i++ {
			hSchema := schemasByIndex[hits[i].Index]
			if hSchema == nil {
				hSchema = primarySchema
			}
			rScore, matched := s.evalHitRescoreQuery(hits[i], rs.Query.RescoreQuery, hSchema)
			weightedOrig := hits[i].Score * qWeight
			if !matched {
				hits[i].Score = weightedOrig
				continue
			}
			weightedRescore := rScore * rWeight
			switch mode {
			case "multiply":
				hits[i].Score = weightedOrig * weightedRescore
			case "avg":
				hits[i].Score = (weightedOrig + weightedRescore) / 2.0
			case "max":
				hits[i].Score = math.Max(weightedOrig, weightedRescore)
			case "min":
				hits[i].Score = math.Min(weightedOrig, weightedRescore)
			default: // "", "total"
				hits[i].Score = weightedOrig + weightedRescore
			}
		}
		windowSlice := hits[:win]
		sort.SliceStable(windowSlice, func(i, j int) bool {
			if len(effSorts) > 0 {
				sI := schemasByIndex[windowSlice[i].Index]
				if sI == nil {
					sI = primarySchema
				}
				sJ := schemasByIndex[windowSlice[j].Index]
				if sJ == nil {
					sJ = primarySchema
				}
				if cmp := compareHitRowsBySortWithSchemas(windowSlice[i], windowSlice[j], effSorts, sI, sJ); cmp != 0 {
					return cmp < 0
				}
			}
			if windowSlice[i].Score != windowSlice[j].Score {
				return windowSlice[i].Score > windowSlice[j].Score
			}
			return windowSlice[i].ID < windowSlice[j].ID
		})
	}
	return hits
}

func (s *Server) evalHitRescoreQuery(h HitRow, rq *esast.Query, hSchema *schema.IndexSchema) (float64, bool) {
	if rq == nil {
		return 0, false
	}
	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	if doc == nil {
		doc = make(map[string]any)
	}
	doc["__meta_id"] = h.ID
	hSchema = resolveRuntimeEvalSchema(hSchema, doc, rq, src)
	shredBytes, err := schema.ShredDocument(hSchema, h.ID, 1, false, src)
	if err != nil {
		return 0, false
	}
	var row map[string]any
	rDec := json.NewDecoder(bytes.NewReader(shredBytes))
	rDec.UseNumber()
	if err := rDec.Decode(&row); err != nil {
		return 0, false
	}
	row["_doc"] = doc
	tr := transpiler.NewTranspiler(hSchema, s.transpileOpts)
	cq := tr.CompileQuery(rq, true, nil)
	if cq.WhereSQL != "" && cq.WhereSQL != "TRUE" && !evalWhereExpr(row, cq.WhereSQL) {
		return 0, false
	}
	if queryHasRuntimeScript(rq) && !evalQueryScriptFilterOnDocWithSchema(hSchema, doc, rq) {
		return 0, false
	}
	rScore := 1.0
	if cq.ScoreSQL != "" {
		rScore = evalNumericExpr(row, cq.ScoreSQL)
		if rScore == 0 && cq.ScoreSQL == "1.0" {
			rScore = 1.0
		}
	}
	if queryHasRuntimeScript(rq) || queryHasNestedScoring(rq) || (rq.FunctionScore != nil && rq.FunctionScore.Query == nil) {
		baseScore := rScore
		if rq.ScriptScore != nil && rq.ScriptScore.Query == nil {
			baseScore = h.Score
		} else if rq.FunctionScore != nil {
			if rq.FunctionScore.Query == nil {
				baseScore = h.Score
			} else {
				subCQ := tr.CompileQuery(rq.FunctionScore.Query, true, nil)
				if subCQ.ScoreSQL != "" {
					baseScore = evalNumericExpr(row, subCQ.ScoreSQL)
				} else {
					baseScore = 1.0
				}
			}
		}
		rScore = evalQueryScriptScoreOnDocWithSchema(hSchema, doc, rq, baseScore)
	}
	if rq.FunctionScore != nil && rq.FunctionScore.MinScore != nil && rScore < *rq.FunctionScore.MinScore {
		return 0, false
	}
	if rq.ScriptScore != nil && rq.ScriptScore.MinScore != nil && rScore < *rq.ScriptScore.MinScore {
		return 0, false
	}
	return rScore, true
}

func evalHitScriptFields(h HitRow, scriptFields map[string]any, idxSchema *schema.IndexSchema) map[string][]any {
	if len(scriptFields) == 0 {
		return nil
	}
	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	if doc == nil {
		doc = make(map[string]any)
	}
	if h.ID != "" {
		doc["__meta_id"] = h.ID
	}
	if h.Index != "" {
		doc["__meta_index"] = h.Index
	}
	if h.Version > 0 {
		doc["__meta_version"] = h.Version
	} else {
		doc["__meta_version"] = int64(1)
	}
	if idxSchema == nil && h.Schema != nil {
		idxSchema = h.Schema
	}
	out := make(map[string][]any, len(scriptFields))
	for fieldName, sfSpec := range scriptFields {
		srcStr, params := extractScriptSourceAndParams(sfSpec)
		if srcStr == "" {
			continue
		}
		docForField := doc
		if len(scriptFields) > 1 {
			docForField = deepCloneDocMap(doc)
			if docForField == nil {
				docForField = make(map[string]any)
			}
		}
		evalDoc := prepareDocForRuntimeScript(idxSchema, docForField)
		cp := make(map[string]any, len(params)+1)
		for k, v := range params {
			cp[k] = v
		}
		cp["_score"] = h.Score
		val, err := painless.Eval(evalDoc, srcStr, cp)
		if err != nil || val == nil {
			continue
		}
		if arr, ok := val.([]any); ok {
			out[fieldName] = arr
		} else {
			out[fieldName] = []any{val}
		}
	}
	return out
}
