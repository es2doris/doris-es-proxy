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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	ID        string
	Version   int64
	Source    json.RawMessage
	Score     float64
	TotalHits int64
}

// AggRow represents a single facet bucket row returned by Doris for Query 2 (AggsSQL).
type AggRow struct {
	AggName   string
	BucketKey string
	DocCount  int64
}

// DorisBackend abstracts the execution of DDL, SQL queries, point lookups, and Stream Loads
// against Apache Doris so the proxy can run against either a live Doris FE+BE cluster or an
// in-memory test harness.
type DorisBackend interface {
	ExecDDL(ctx context.Context, ddl string) error
	QueryHits(ctx context.Context, sql string) ([]HitRow, error)
	QueryAggs(ctx context.Context, sql string) ([]AggRow, error)
	GetDocByID(ctx context.Context, db, table, id string) (*HitRow, bool, error)
	StreamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error
}

// Server implements the Elasticsearch / OpenSearch HTTP REST API adapter backed by Apache Doris.
type Server struct {
	dorisDB       string
	backend       DorisBackend
	transpileOpts transpiler.TranspilerOptions

	mu      sync.RWMutex
	indices map[string]*schema.IndexSchema
	aliases map[string]string // aliasName -> indexName
}

func NewServer(dorisDB string, backend DorisBackend, opts transpiler.TranspilerOptions) *Server {
	if dorisDB == "" {
		dorisDB = "es_compat"
	}
	return &Server{
		dorisDB:       dorisDB,
		backend:       backend,
		transpileOpts: opts,
		indices:       make(map[string]*schema.IndexSchema),
		aliases:       make(map[string]string),
	}
}

// Handler returns an `http.Handler` that routes Elasticsearch / OpenSearch REST endpoints
// without `http.ServeMux` wildcard ambiguity between `/_alias/{name}` and `/{index}/_search`.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.Trim(r.URL.Path, "/")
		if trimmed == "" {
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
			case "_aliases":
				if r.Method == http.MethodPost {
					s.handleUpdateAliases(w, r)
				} else {
					s.handleGetAliases(w, r)
				}
			case "_alias":
				s.handleGetAliases(w, r)
			case "_refresh":
				s.handleRefresh(w, r)
			case "_nodes":
				s.handleNodes(w, r)
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
			case segs[0] == "_cat" && segs[1] == "indices":
				s.handleCatIndices(w, r)
			case segs[0] == "_alias":
				r.SetPathValue("name", segs[1])
				s.handleGetAliases(w, r)
			default:
				r.SetPathValue("index", segs[0])
				switch segs[1] {
				case "_mapping":
					if r.Method == http.MethodGet {
						s.handleGetMapping(w, r)
					} else {
						s.handlePutMapping(w, r)
					}
				case "_search":
					s.handleSearch(w, r)
				case "_count":
					s.handleCount(w, r)
				case "_bulk":
					s.handleBulk(w, r)
				case "_refresh":
					s.handleRefresh(w, r)
				case "_update_by_query":
					s.handleUpdateByQuery(w, r)
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
			r.SetPathValue("index", segs[0])
			r.SetPathValue("id", segs[2])
			switch segs[1] {
			case "_doc", "_create":
				switch r.Method {
				case http.MethodPut, http.MethodPost:
					s.handlePutDoc(w, r)
				case http.MethodGet:
					s.handleGetDoc(w, r)
				case http.MethodDelete:
					s.handleDeleteDoc(w, r)
				default:
					writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
				}
			case "_update":
				s.handleUpdateDoc(w, r)
			case "_source":
				s.handleGetDoc(w, r)
			default:
				writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
			}

		default:
			writeESError(w, http.StatusNotFound, "invalid_index_name_exception", "unknown endpoint: "+r.URL.Path)
		}
	})
}

func (s *Server) handleRootHandshake(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         "doris-es-proxy",
		"cluster_name": "apache-doris-search-cluster",
		"cluster_uuid": "doris-es-0000-0000-0000-000000000001",
		"version": map[string]any{
			"number":                              "7.10.2",
			"build_flavor":                        "oss",
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

	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_name":                    "apache-doris-search-cluster",
		"status":                          "green",
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
		"Active_shards_percent_as_number": 100.0,
	})
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []map[string]any
	for name := range s.indices {
		list = append(list, map[string]any{
			"health": "green",
			"status": "open",
			"index":  name,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
	})
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

	compiled := schema.CompileIndexSchema(s.dorisDB, indexName, req.Mappings)
	ddl := schema.GenerateCreateTableDDL(compiled)
	if err := s.backend.ExecDDL(r.Context(), ddl); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_ddl_exception", err.Error())
		return
	}

	s.mu.Lock()
	s.indices[indexName] = compiled
	for alias := range req.Aliases {
		s.aliases[alias] = indexName
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"index":               indexName,
	})
}

func (s *Server) handleGetIndex(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	s.mu.RLock()
	idx, ok := s.indices[indexName]
	s.mu.RUnlock()
	if !ok {
		writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+indexName+"]")
		return
	}
	mappings := map[string]any{}
	if idx.RawMapping != nil {
		mappings["properties"] = idx.RawMapping.Properties
	}
	writeJSON(w, http.StatusOK, map[string]any{
		indexName: map[string]any{
			"aliases":  map[string]any{},
			"mappings": mappings,
			"settings": map[string]any{"index": map[string]any{"number_of_shards": "1", "number_of_replicas": "0"}},
		},
	})
}

func (s *Server) handleHeadIndex(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	s.mu.RLock()
	_, ok := s.indices[indexName]
	s.mu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteIndex(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	s.mu.Lock()
	idx, ok := s.indices[indexName]
	delete(s.indices, indexName)
	for alias, target := range s.aliases {
		if target == indexName {
			delete(s.aliases, alias)
		}
	}
	s.mu.Unlock()

	if ok {
		ddl := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`;", idx.DorisDB, idx.DorisTable)
		_ = s.backend.ExecDDL(r.Context(), ddl)
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleGetMapping(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
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

func (s *Server) handlePutMapping(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	var spec esast.MappingSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}
	s.mu.Lock()
	oldSchema := s.indices[indexName]
	newSchema := schema.CompileIndexSchema(s.dorisDB, indexName, &spec)
	s.indices[indexName] = newSchema
	s.mu.Unlock()

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
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleGetAliases(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]any)
	for idxName := range s.indices {
		idxAliases := make(map[string]any)
		for alias, target := range s.aliases {
			if target == idxName {
				idxAliases[alias] = map[string]any{}
			}
		}
		out[idxName] = map[string]any{"aliases": idxAliases}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpdateAliases(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Actions []map[string]struct {
			Index string `json:"index"`
			Alias string `json:"alias"`
		} `json:"actions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	s.mu.Lock()
	for _, action := range payload.Actions {
		if add, ok := action["add"]; ok {
			s.aliases[add.Alias] = add.Index
		}
		if rem, ok := action["remove"]; ok {
			delete(s.aliases, rem.Alias)
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handlePutDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	rawDoc, err := io.ReadAll(r.Body)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}

	idxSchema := s.ensureIndexSchema(r.Context(), indexName)
	shredded, err := schema.ShredDocument(idxSchema, docID, time.Now().UnixNano(), false, json.RawMessage(rawDoc))
	if err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}

	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	if err := s.backend.StreamLoad(r.Context(), idxSchema.DorisTable, append(shredded, '\n'), syncRefresh); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"_index":   indexName,
		"_type":    "_doc",
		"_id":      docID,
		"_version": 1,
		"result":   "created",
		"_shards":  map[string]any{"total": 1, "successful": 1, "failed": 0},
	})
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
	writeJSON(w, http.StatusOK, map[string]any{
		"_index":   indexName,
		"_type":    "_doc",
		"_id":      hit.ID,
		"_version": hit.Version,
		"found":    true,
		"_source":  hit.Source,
	})
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
	if err := s.backend.StreamLoad(r.Context(), idxSchema.DorisTable, append(tombstone, '\n'), syncRefresh); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_index":   indexName,
		"_type":    "_doc",
		"_id":      docID,
		"_version": 2,
		"result":   "deleted",
	})
}

func (s *Server) handleUpdateDoc(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	docID := r.PathValue("id")
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	var updReq painless.UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updReq); err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}

	existingHit, found, err := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, docID)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	if !found && !updReq.DocAsUpsert {
		writeESError(w, http.StatusNotFound, "document_missing_exception", fmt.Sprintf("[%s]: document missing", docID))
		return
	}

	var baseSource json.RawMessage
	nextVersion := time.Now().UnixNano()
	if found {
		baseSource = existingHit.Source
		nextVersion = existingHit.Version + 1
	}

	mutatedSource, err := painless.ApplyUpdate(baseSource, &updReq)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
		return
	}

	shredded, err := schema.ShredDocument(idxSchema, docID, nextVersion, false, mutatedSource)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
		return
	}
	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	if err := s.backend.StreamLoad(r.Context(), idxSchema.DorisTable, append(shredded, '\n'), syncRefresh); err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"_index":   indexName,
		"_type":    "_doc",
		"_id":      docID,
		"_version": nextVersion,
		"result":   "updated",
	})
}

func (s *Server) handleUpdateByQuery(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	var body struct {
		Query  *esast.Query        `json:"query,omitempty"`
		Script *painless.ScriptSpec `json:"script,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return
	}

	tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
	size := 10000
	plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Query: body.Query,
		Size:  &size,
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

	var batchBuf bytes.Buffer
	updSpec := &painless.UpdateRequest{Script: body.Script}
	for _, h := range hits {
		mutated, err := painless.ApplyUpdate(h.Source, updSpec)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
			return
		}
		shredded, err := schema.ShredDocument(idxSchema, h.ID, h.Version+1, false, mutated)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "mapper_parsing_exception", err.Error())
			return
		}
		batchBuf.Write(shredded)
		batchBuf.WriteByte('\n')
	}

	if batchBuf.Len() > 0 {
		if err := s.backend.StreamLoad(r.Context(), idxSchema.DorisTable, batchBuf.Bytes(), true); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"took":    5,
		"timed_out": false,
		"total":   len(hits),
		"updated": len(hits),
		"deleted": 0,
		"batches": 1,
		"failures": []any{},
	})
}

func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	defaultIndex := s.resolveIndexName(r.PathValue("index"))
	ops, err := esast.ParseBulkNDJSON(r.Body, defaultIndex)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", err.Error())
		return
	}

	byIndex := make(map[string]*bytes.Buffer)
	var items []map[string]any
	seqBase := time.Now().UnixNano()

	for i, op := range ops {
		targetIndex := s.resolveIndexName(op.Index)
		idxSchema := s.ensureIndexSchema(r.Context(), targetIndex)
		buf, ok := byIndex[idxSchema.DorisTable]
		if !ok {
			buf = &bytes.Buffer{}
			byIndex[idxSchema.DorisTable] = buf
		}

		deleted := op.Action == "delete"
		sourceToShred := op.Source
		if op.Action == "update" {
			var upd painless.UpdateRequest
			if err := json.Unmarshal(op.Source, &upd); err == nil {
				var baseSrc json.RawMessage
				if existing, found, _ := s.backend.GetDocByID(r.Context(), idxSchema.DorisDB, idxSchema.DorisTable, op.ID); found {
					baseSrc = existing.Source
				}
				if merged, err := painless.ApplyUpdate(baseSrc, &upd); err == nil {
					sourceToShred = merged
				}
			}
		}

		shredded, err := schema.ShredDocument(idxSchema, op.ID, seqBase+int64(i), deleted, sourceToShred)
		if err != nil {
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
				"_index":   targetIndex,
				"_type":    "_doc",
				"_id":      op.ID,
				"_version": 1,
				"result":   result,
				"status":   status,
			},
		})
	}

	syncRefresh := r.URL.Query().Get("refresh") == "true" || r.URL.Query().Get("refresh") == "wait_for"
	for dorisTable, buf := range byIndex {
		if err := s.backend.StreamLoad(r.Context(), dorisTable, buf.Bytes(), syncRefresh); err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"took":   4,
		"errors": false,
		"items":  items,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

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

	tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "search_phase_execution_exception", err.Error())
		return
	}

	var hits []HitRow
	var aggRows []AggRow
	if plan.HitsSQL != "" {
		hits, err = s.backend.QueryHits(r.Context(), plan.HitsSQL)
		if err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
			return
		}
	}
	if plan.AggsSQL != "" {
		aggRows, err = s.backend.QueryAggs(r.Context(), plan.AggsSQL)
		if err != nil {
			writeESError(w, http.StatusInternalServerError, "doris_aggs_exception", err.Error())
			return
		}
	}

	resp := buildESResponse(indexName, &req, hits, aggRows)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCount(w http.ResponseWriter, r *http.Request) {
	indexName := s.resolveIndexName(r.PathValue("index"))
	idxSchema := s.ensureIndexSchema(r.Context(), indexName)

	var req esast.SearchRequest
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			_ = json.Unmarshal(bodyBytes, &req)
		}
	}
	zero := 0
	req.Size = &zero
	tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "search_phase_execution_exception", err.Error())
		return
	}

	aggRows, err := s.backend.QueryAggs(r.Context(), plan.AggsSQL)
	if err != nil {
		writeESError(w, http.StatusInternalServerError, "doris_query_exception", err.Error())
		return
	}
	var count int64
	for _, row := range aggRows {
		if row.AggName == "__meta_total" {
			count = row.DocCount
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   count,
		"_shards": map[string]any{"total": 1, "successful": 1, "skipped": 0, "failed": 0},
	})
}

func buildESResponse(indexName string, req *esast.SearchRequest, hits []HitRow, aggRows []AggRow) map[string]any {
	var totalHits int64
	var maxScore float64
	esHits := make([]map[string]any, 0, len(hits))

	for _, h := range hits {
		if h.TotalHits > totalHits {
			totalHits = h.TotalHits
		}
		if h.Score > maxScore {
			maxScore = h.Score
		}
		esHits = append(esHits, map[string]any{
			"_index":  indexName,
			"_type":   "_doc",
			"_id":     h.ID,
			"_score":  h.Score,
			"_source": h.Source,
		})
	}

	aggsOut := make(map[string]any)
	bucketsByAgg := make(map[string][]map[string]any)
	for _, row := range aggRows {
		if row.AggName == "__meta_total" {
			if totalHits == 0 {
				totalHits = row.DocCount
			}
			continue
		}
		bucketsByAgg[row.AggName] = append(bucketsByAgg[row.AggName], map[string]any{
			"key":       row.BucketKey,
			"doc_count": row.DocCount,
		})
	}

	for aggName, spec := range req.EffectiveAggs() {
		switch {
		case spec.Terms != nil:
			b := bucketsByAgg[aggName]
			if b == nil {
				b = []map[string]any{}
			}
			aggsOut[aggName] = map[string]any{
				"doc_count_error_upper_bound": 0,
				"sum_other_doc_count":         0,
				"buckets":                     b,
			}
		case spec.Nested != nil:
			nestedObj := map[string]any{"doc_count": totalHits}
			for subName := range spec.SubAggs() {
				b := bucketsByAgg[aggName+"."+subName]
				if b == nil {
					b = []map[string]any{}
				}
				nestedObj[subName] = map[string]any{
					"doc_count_error_upper_bound": 0,
					"sum_other_doc_count":         0,
					"buckets":                     b,
				}
			}
			aggsOut[aggName] = nestedObj
		case spec.Filter != nil || spec.Missing != nil:
			var cnt int64
			if b := bucketsByAgg[aggName]; len(b) > 0 {
				if c, ok := b[0]["doc_count"].(int64); ok {
					cnt = c
				}
			}
			aggsOut[aggName] = map[string]any{"doc_count": cnt}
		}
	}

	res := map[string]any{
		"took":      3,
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

func (s *Server) resolveIndexName(nameOrAlias string) string {
	if nameOrAlias == "" {
		return "default_index"
	}
	// Strip comma-separated multi-index patterns to first index for MVP
	if idx := strings.IndexByte(nameOrAlias, ','); idx > 0 {
		nameOrAlias = nameOrAlias[:idx]
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if target, ok := s.aliases[nameOrAlias]; ok {
		return target
	}
	return nameOrAlias
}

func (s *Server) ensureIndexSchema(ctx context.Context, indexName string) *schema.IndexSchema {
	s.mu.RLock()
	idx, ok := s.indices[indexName]
	s.mu.RUnlock()
	if ok {
		return idx
	}

	compiled := schema.CompileIndexSchema(s.dorisDB, indexName, nil)
	_ = s.backend.ExecDDL(ctx, schema.GenerateCreateTableDDL(compiled))
	s.mu.Lock()
	s.indices[indexName] = compiled
	s.mu.Unlock()
	return compiled
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
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
