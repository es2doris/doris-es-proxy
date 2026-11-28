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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

const (
	defaultCatalogTombstoneRetentionR67 = 5 * time.Minute
	minCatalogTombstonePurgeIntervalR67 = 30 * time.Second
)

type catalogEntryDigestR67 struct {
	epochMs     int64
	payloadHash string
}

type catalogCompiledIndexDeltaR67 struct {
	entityKey             string
	deleted               bool
	compiled              *schema.IndexSchema
	defaultPipeline       string
	finalPipeline         string
	customSettings        map[string]any
	closed                bool
	legacyTypeName        string
	es8Mode               *bool
	fieldAddedAtSeqNo     map[string]int64
	adoptedConstantFields []string
}

type catalogParsedDeltaR67 struct {
	entityType string
	entityKey  string
	deleted    bool
	idxDelta   *catalogCompiledIndexDeltaR67
	tpl        esast.IndexTemplateRequest
	comp       map[string]any
	pipe       map[string]any
	pol        map[string]any
	aliasTgt   []string
	aliasMeta  map[string]AliasMetadata
	ds         map[string]any
	ilmPol     map[string]any
	script     map[string]any
	seqState   persistedIndexSeqState
}

// CatalogSyncer manages watermark-based incremental catalog synchronization,
// outside-lock schema compilation, targeted cache invalidation, periodic sync ticks,
// tombstone purging, and per-index DDL serialization.
type CatalogSyncer struct {
	server *Server

	sf          sfGroupR67
	stateMu     sync.Mutex
	seenDigests map[string]catalogEntryDigestR67
	lastEpochMs atomic.Int64
	syncedOnce  atomic.Bool

	ddlMu      sync.Mutex
	indexDDLMu map[string]*sync.Mutex

	tickerMu        sync.Mutex
	stopCh          chan struct{}
	doneCh          chan struct{}
	lastPurgeAt     time.Time
	tombstoneRetent time.Duration
}

func newCatalogSyncer(s *Server) *CatalogSyncer {
	return &CatalogSyncer{
		server:          s,
		seenDigests:     make(map[string]catalogEntryDigestR67),
		indexDDLMu:      make(map[string]*sync.Mutex),
		tombstoneRetent: defaultCatalogTombstoneRetentionR67,
	}
}

// LastEpochMs returns the highest monotonic catalog entry watermark seen by this syncer.
func (cs *CatalogSyncer) LastEpochMs() int64 {
	if cs == nil {
		return 0
	}
	return cs.lastEpochMs.Load()
}

// LockIndexDDL acquires a per-index DDL mutex and returns an unlock function so dynamic
// ALTER TABLE operations on the same index cannot race concurrently.
func (cs *CatalogSyncer) LockIndexDDL(indexName string) func() {
	if cs == nil {
		return func() {}
	}
	key := strings.TrimSpace(indexName)
	if key == "" {
		key = "_default"
	}
	cs.ddlMu.Lock()
	mu, ok := cs.indexDDLMu[key]
	if !ok {
		mu = &sync.Mutex{}
		cs.indexDDLMu[key] = mu
	}
	cs.ddlMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// LockIndexDDL acquires the Server's per-index DDL lock and returns an unlock function.
func (s *Server) LockIndexDDL(indexName string) func() {
	if s == nil || s.catalogSyncer == nil {
		return func() {}
	}
	return s.catalogSyncer.LockIndexDDL(indexName)
}

func hashCatalogPayloadR67(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:8])
}

func compileCatalogIndexDeltaR67(dorisDB string, e CatalogEntry) *catalogCompiledIndexDeltaR67 {
	out := &catalogCompiledIndexDeltaR67{
		entityKey: e.EntityKey,
		deleted:   e.PayloadJSON == "__DELETED__",
	}
	if out.deleted {
		return out
	}

	var spec esast.MappingSpec
	var metaEnv struct {
		DefaultPipeline       string           `json:"_default_pipeline,omitempty"`
		FinalPipeline         string           `json:"_final_pipeline,omitempty"`
		CustomSettings        map[string]any   `json:"_custom_settings,omitempty"`
		Closed                bool             `json:"_closed,omitempty"`
		LegacyTypeName        string           `json:"_legacy_type_name,omitempty"`
		ES8Mode               *bool            `json:"_es8_mode,omitempty"`
		FieldAddedAtSeqNo     map[string]int64 `json:"_field_added_seq_no,omitempty"`
		AdoptedConstantFields []string         `json:"_adopted_constant_fields,omitempty"`
	}
	if len(strings.TrimSpace(e.PayloadJSON)) > 0 && e.PayloadJSON != "null" {
		_ = json.Unmarshal([]byte(e.PayloadJSON), &spec)
		_ = json.Unmarshal([]byte(e.PayloadJSON), &metaEnv)
	}
	var specPtr *esast.MappingSpec
	if len(spec.Properties) > 0 || len(spec.Runtime) > 0 || spec.Dynamic != nil || spec.Subobjects != nil || spec.Routing != nil ||
		len(spec.DynamicTemplates) > 0 || spec.DateDetection != nil || spec.NumericDetection != nil || len(spec.DynamicDateFormats) > 0 ||
		len(spec.Meta) > 0 || len(spec.Source) > 0 || len(spec.Size) > 0 || spec.Enabled != nil {
		specPtr = &spec
	}

	compiled := schema.CompileIndexSchema(dorisDB, e.EntityKey, specPtr)
	if len(metaEnv.CustomSettings) > 0 {
		_ = parseAndApplyIndexMappingSettingsRound59(metaEnv.CustomSettings, compiled)
		if compiled.AnalysisConfig == nil {
			_ = compiled.SetAnalysisSettings(normalizeJSONNumbersForAnalysisR65(metaEnv.CustomSettings))
		}
		tsMode, tsRoutingPath, tsStart, tsEnd, tsErr := schema.ExtractTSDBSettings(metaEnv.CustomSettings)
		if tsErr == nil && tsMode == "time_series" {
			compiled.IndexMode = "time_series"
			compiled.RoutingPath = tsRoutingPath
			compiled.TimeSeriesStartTime = tsStart
			compiled.TimeSeriesEndTime = tsEnd
			compiled.SyntheticSource = true
		}
	}

	out.compiled = compiled
	out.defaultPipeline = metaEnv.DefaultPipeline
	out.finalPipeline = metaEnv.FinalPipeline
	out.customSettings = metaEnv.CustomSettings
	out.closed = metaEnv.Closed
	out.legacyTypeName = metaEnv.LegacyTypeName
	out.es8Mode = metaEnv.ES8Mode
	out.fieldAddedAtSeqNo = metaEnv.FieldAddedAtSeqNo
	out.adoptedConstantFields = metaEnv.AdoptedConstantFields
	return out
}

// Sync synchronizes catalog metadata from the backing store using watermarks,
// incremental polling when supported, zero-alloc fast path on no-op polls,
// and outside-lock schema compilation.
func (cs *CatalogSyncer) Sync(ctx context.Context) error {
	if cs == nil || cs.server == nil {
		return nil
	}
	s := cs.server
	cb, ok := s.backend.(CatalogBackend)
	if !ok {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	_, err, _ := cs.sf.Do("catalog-sync", func() (any, error) {
		return nil, cs.syncOnce(ctx, cb)
	})
	return err
}

func (cs *CatalogSyncer) syncOnce(ctx context.Context, cb CatalogBackend) error {
	s := cs.server
	since := cs.lastEpochMs.Load()
	var (
		entries []CatalogEntry
		err     error
	)
	if inc, okInc := s.backend.(IncrementalCatalogBackend); okInc && cs.syncedOnce.Load() && since > 0 {
		entries, err = inc.LoadCatalogEntriesSince(ctx, s.dorisDB, since)
	} else {
		entries, err = cb.LoadCatalogEntries(ctx, s.dorisDB)
	}
	if err != nil {
		s.RecordCatalogSyncMetric("error")
		return err
	}
	cs.syncedOnce.Store(true)

	if len(entries) == 0 {
		s.RecordCatalogSyncMetric("noop")
		return nil
	}

	cs.stateMu.Lock()
	var changed []CatalogEntry
	var purgeCandidates []CatalogEntry
	maxEpoch := since
	nowMs := time.Now().UnixMilli()
	retentMs := cs.tombstoneRetent.Milliseconds()
	if retentMs <= 0 {
		retentMs = defaultCatalogTombstoneRetentionR67.Milliseconds()
	}
	shouldPurge := time.Since(cs.lastPurgeAt) >= minCatalogTombstonePurgeIntervalR67

	for _, e := range entries {
		if e.UpdatedEpochMs > maxEpoch {
			maxEpoch = e.UpdatedEpochMs
		}
		if e.PayloadJSON == "__DELETED__" && shouldPurge && e.UpdatedEpochMs > 0 && nowMs-e.UpdatedEpochMs >= retentMs {
			purgeCandidates = append(purgeCandidates, e)
		}
		digestKey := e.EntityType + "\x00" + e.EntityKey
		payloadHash := hashCatalogPayloadR67(e.PayloadJSON)
		prev, seen := cs.seenDigests[digestKey]
		if seen && prev.epochMs == e.UpdatedEpochMs && prev.payloadHash == payloadHash {
			continue
		}
		if seen && e.UpdatedEpochMs < prev.epochMs {
			continue
		}
		changed = append(changed, e)
	}
	cs.stateMu.Unlock()

	if len(purgeCandidates) > 0 {
		for _, pe := range purgeCandidates {
			if delErr := cb.DeleteCatalogEntry(ctx, s.dorisDB, pe.EntityType, pe.EntityKey); delErr != nil {
				s.logWarn("failed to purge expired catalog tombstone", "entity_type", pe.EntityType, "entity_key", pe.EntityKey, "error", delErr.Error())
			} else {
				cs.stateMu.Lock()
				delete(cs.seenDigests, pe.EntityType+"\x00"+pe.EntityKey)
				cs.stateMu.Unlock()
			}
		}
		cs.stateMu.Lock()
		cs.lastPurgeAt = time.Now()
		cs.stateMu.Unlock()
	}

	if len(changed) == 0 {
		if maxEpoch > cs.lastEpochMs.Load() {
			cs.lastEpochMs.Store(maxEpoch)
		}
		s.RecordCatalogSyncMetric("noop")
		return nil
	}

	// Parse & compile all changed schemas OUTSIDE s.mu.Lock().
	parsed := make([]catalogParsedDeltaR67, 0, len(changed))

	for _, e := range changed {
		isDeleted := e.PayloadJSON == "__DELETED__"
		pd := catalogParsedDeltaR67{
			entityType: e.EntityType,
			entityKey:  e.EntityKey,
			deleted:    isDeleted,
		}
		switch e.EntityType {
		case "template":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.tpl); err != nil {
					continue
				}
			}
		case "legacy_template":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.tpl); err != nil {
					continue
				}
				pd.tpl.Legacy = true
			}
		case "component_template":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.comp); err != nil || pd.comp == nil {
					continue
				}
			}
		case "index":
			pd.idxDelta = compileCatalogIndexDeltaR67(s.dorisDB, e)
		case "pipeline":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.pipe); err != nil || pd.pipe == nil {
					continue
				}
			}
		case "enrich_policy":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.pol); err != nil || pd.pol == nil {
					continue
				}
			}
		case "alias":
			if !isDeleted {
				var targets []string
				if err := json.Unmarshal([]byte(e.PayloadJSON), &targets); err == nil {
					pd.aliasTgt = targets
				} else {
					var env struct {
						Targets []string                 `json:"targets"`
						Meta    map[string]AliasMetadata `json:"meta,omitempty"`
					}
					if err := json.Unmarshal([]byte(e.PayloadJSON), &env); err != nil {
						continue
					}
					pd.aliasTgt = env.Targets
					pd.aliasMeta = env.Meta
				}
			}
		case "data_stream":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.ds); err != nil || len(pd.ds) == 0 {
					continue
				}
			}
		case "ilm_policy":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.ilmPol); err != nil || len(pd.ilmPol) == 0 {
					continue
				}
			}
		case "script":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.script); err != nil || len(pd.script) == 0 {
					continue
				}
			}
		case "index_seq_state":
			if !isDeleted {
				if err := json.Unmarshal([]byte(e.PayloadJSON), &pd.seqState); err != nil {
					continue
				}
			}
		default:
			continue
		}
		parsed = append(parsed, pd)
	}

	// Apply delta updates under s.mu.Lock() and invalidate caches only when live in-memory state actually changes.
	affectedIndices := make([]string, 0, len(parsed))
	stateChangedForCache := false
	s.mu.Lock()
	for _, pd := range parsed {
		switch pd.entityType {
		case "template":
			if pd.deleted {
				delete(s.templates, pd.entityKey)
			} else {
				s.templates[pd.entityKey] = pd.tpl
			}
		case "legacy_template":
			if pd.deleted {
				delete(s.legacyTemplates, pd.entityKey)
			} else {
				if s.legacyTemplates == nil {
					s.legacyTemplates = make(map[string]esast.IndexTemplateRequest)
				}
				s.legacyTemplates[pd.entityKey] = pd.tpl
			}
		case "component_template":
			if pd.deleted {
				delete(s.componentTemplates, pd.entityKey)
			} else {
				if s.componentTemplates == nil {
					s.componentTemplates = make(map[string]map[string]any)
				}
				s.componentTemplates[pd.entityKey] = pd.comp
			}
		case "index":
			if pd.deleted {
				if _, existed := s.indices[pd.entityKey]; existed {
					stateChangedForCache = true
					affectedIndices = append(affectedIndices, pd.entityKey)
				}
				delete(s.indices, pd.entityKey)
				delete(s.indexDefaultPipelines, pd.entityKey)
				delete(s.indexFinalPipelines, pd.entityKey)
				delete(s.indexCustomSettings, pd.entityKey)
				delete(s.closedIndices, pd.entityKey)
				delete(s.indexNextSeqNo, pd.entityKey)
				delete(s.docSeqNos, pd.entityKey)
				delete(s.docDeleted, pd.entityKey)
				delete(s.docExtTombstones, pd.entityKey)
				delete(s.unrefreshedDocs, pd.entityKey)
				delete(s.indexStats, pd.entityKey)
				continue
			}
			d := pd.idxDelta
			if d == nil || d.compiled == nil {
				continue
			}
			compiled := d.compiled
			prevSchema := s.indices[pd.entityKey]
			prevClosed := s.closedIndices[pd.entityKey]
			prevCustom := s.indexCustomSettings[pd.entityKey]
			if prevSchema != nil {
				if d.legacyTypeName == "" {
					compiled.LegacyTypeName = prevSchema.LegacyTypeName
				}
				if d.es8Mode == nil {
					compiled.ES8Mode = prevSchema.ES8Mode
				}
				if compiled.IndexMode == "" {
					compiled.IndexMode = prevSchema.IndexMode
					compiled.RoutingPath = prevSchema.RoutingPath
					compiled.TimeSeriesStartTime = prevSchema.TimeSeriesStartTime
					compiled.TimeSeriesEndTime = prevSchema.TimeSeriesEndTime
					compiled.SyntheticSource = prevSchema.SyntheticSource
				}
				// Re-copy base index settings from prevSchema when custom settings weren't explicitly re-supplied.
				tmpCopy := *compiled
				tmpCopy.CopyIndexMappingSettingsFrom(prevSchema)
				if len(d.customSettings) == 0 {
					compiled.CopyIndexMappingSettingsFrom(&tmpCopy)
				} else {
					if compiled.AnalysisConfig == nil && prevSchema.AnalysisConfig != nil {
						compiled.AnalysisConfig = prevSchema.AnalysisConfig
					}
				}
				if len(prevSchema.FieldAddedAtSeqNo) > 0 {
					compiled.FieldAddedAtSeqNo = make(map[string]int64, len(prevSchema.FieldAddedAtSeqNo)+len(d.fieldAddedAtSeqNo))
					for k, v := range prevSchema.FieldAddedAtSeqNo {
						compiled.FieldAddedAtSeqNo[k] = v
					}
				}
				for fn, pfb := range prevSchema.Fields {
					if pfb.AdoptedConstantValue {
						if cfb, ok := compiled.Fields[fn]; ok {
							cfb.AdoptedConstantValue = true
							compiled.Fields[fn] = cfb
						}
					}
				}
			}
			for _, fn := range d.adoptedConstantFields {
				if cfb, ok := compiled.Fields[fn]; ok {
					cfb.AdoptedConstantValue = true
					compiled.Fields[fn] = cfb
				}
			}
			if d.legacyTypeName != "" {
				compiled.LegacyTypeName = d.legacyTypeName
			}
			if d.es8Mode != nil {
				compiled.ES8Mode = *d.es8Mode
			}
			if len(d.fieldAddedAtSeqNo) > 0 {
				if compiled.FieldAddedAtSeqNo == nil {
					compiled.FieldAddedAtSeqNo = make(map[string]int64, len(d.fieldAddedAtSeqNo))
				}
				for k, v := range d.fieldAddedAtSeqNo {
					compiled.FieldAddedAtSeqNo[k] = v
				}
			}
			compiled.RefreshMappingHash()
			if prevSchema == nil || prevSchema.MappingHash != compiled.MappingHash || prevClosed != d.closed || !catalogJSONEqualR67(prevCustom, d.customSettings) {
				stateChangedForCache = true
				affectedIndices = append(affectedIndices, pd.entityKey)
			}
			s.indices[pd.entityKey] = compiled
			if d.defaultPipeline != "" {
				s.indexDefaultPipelines[pd.entityKey] = d.defaultPipeline
			} else {
				delete(s.indexDefaultPipelines, pd.entityKey)
			}
			if d.finalPipeline != "" {
				s.indexFinalPipelines[pd.entityKey] = d.finalPipeline
			} else {
				delete(s.indexFinalPipelines, pd.entityKey)
			}
			if len(d.customSettings) > 0 {
				if s.indexCustomSettings == nil {
					s.indexCustomSettings = make(map[string]map[string]any)
				}
				s.indexCustomSettings[pd.entityKey] = d.customSettings
			} else {
				delete(s.indexCustomSettings, pd.entityKey)
			}
			if d.closed {
				if s.closedIndices == nil {
					s.closedIndices = make(map[string]bool)
				}
				s.closedIndices[pd.entityKey] = true
			} else {
				delete(s.closedIndices, pd.entityKey)
			}
		case "pipeline":
			if pd.deleted {
				delete(s.pipelines, pd.entityKey)
			} else {
				if s.pipelines == nil {
					s.pipelines = make(map[string]map[string]any)
				}
				s.pipelines[pd.entityKey] = pd.pipe
			}
		case "enrich_policy":
			if pd.deleted {
				delete(s.enrichPolicies, pd.entityKey)
			} else {
				if s.enrichPolicies == nil {
					s.enrichPolicies = make(map[string]map[string]any)
				}
				s.enrichPolicies[pd.entityKey] = pd.pol
			}
		case "alias":
			prevTgt := s.aliases[pd.entityKey]
			prevMeta := s.aliasMeta[pd.entityKey]
			if pd.deleted || len(pd.aliasTgt) == 0 {
				if len(prevTgt) > 0 || len(prevMeta) > 0 {
					stateChangedForCache = true
				}
				delete(s.aliases, pd.entityKey)
				delete(s.aliasMeta, pd.entityKey)
			} else {
				if !catalogJSONEqualR67(prevTgt, pd.aliasTgt) || !catalogJSONEqualR67(prevMeta, pd.aliasMeta) {
					stateChangedForCache = true
				}
				s.aliases[pd.entityKey] = pd.aliasTgt
				if len(pd.aliasMeta) > 0 {
					s.aliasMeta[pd.entityKey] = pd.aliasMeta
				} else {
					delete(s.aliasMeta, pd.entityKey)
				}
			}
		case "data_stream":
			prevDS := s.dataStreams[pd.entityKey]
			if pd.deleted {
				if prevDS != nil {
					stateChangedForCache = true
				}
				delete(s.dataStreams, pd.entityKey)
			} else {
				if !catalogJSONEqualR67(prevDS, pd.ds) {
					stateChangedForCache = true
				}
				if s.dataStreams == nil {
					s.dataStreams = make(map[string]map[string]any)
				}
				s.dataStreams[pd.entityKey] = pd.ds
			}
		case "ilm_policy":
			if pd.deleted {
				delete(s.ilmPolicies, pd.entityKey)
			} else {
				if s.ilmPolicies == nil {
					s.ilmPolicies = make(map[string]map[string]any)
				}
				s.ilmPolicies[pd.entityKey] = pd.ilmPol
			}
		case "script":
			if pd.deleted {
				delete(s.scripts, pd.entityKey)
			} else {
				if s.scripts == nil {
					s.scripts = make(map[string]map[string]any)
				}
				s.scripts[pd.entityKey] = pd.script
			}
		case "index_seq_state":
			if pd.deleted {
				if _, existed := s.indexNextSeqNo[pd.entityKey]; existed {
					stateChangedForCache = true
				}
				delete(s.indexNextSeqNo, pd.entityKey)
			} else {
				if s.indexNextSeqNo == nil {
					s.indexNextSeqNo = make(map[string]int64)
				}
				if pd.seqState.NextSeqNo > s.indexNextSeqNo[pd.entityKey] {
					s.indexNextSeqNo[pd.entityKey] = pd.seqState.NextSeqNo
					stateChangedForCache = true
				}
			}
		}
	}
	s.mu.Unlock()

	cs.stateMu.Lock()
	for _, e := range changed {
		cs.seenDigests[e.EntityType+"\x00"+e.EntityKey] = catalogEntryDigestR67{
			epochMs:     e.UpdatedEpochMs,
			payloadHash: hashCatalogPayloadR67(e.PayloadJSON),
		}
	}
	if maxEpoch > cs.lastEpochMs.Load() {
		cs.lastEpochMs.Store(maxEpoch)
	}
	cs.stateMu.Unlock()

	if stateChangedForCache {
		s.queryCache.InvalidateAll()
		s.invalidateShardRequestCacheR63()
	}
	for _, idxName := range affectedIndices {
		s.invalidateBM25ForIndexR67(idxName)
	}
	s.RecordCatalogSyncMetric("applied")
	return nil
}

func catalogJSONEqualR67(a, b any) bool {
	if isEmptyCatalogAnyR67(a) && isEmptyCatalogAnyR67(b) {
		return true
	}
	ba, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(ba, bb)
}

func isEmptyCatalogAnyR67(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case map[string]any:
		return len(x) == 0
	case map[string]AliasMetadata:
		return len(x) == 0
	case []string:
		return len(x) == 0
	}
	return false
}

// Start configures or restarts background periodic catalog synchronization every interval (<=0 disables).
func (cs *CatalogSyncer) Start(interval time.Duration) {
	if cs == nil {
		return
	}
	cs.Stop()
	if interval <= 0 {
		return
	}
	cs.tickerMu.Lock()
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	cs.stopCh = stopCh
	cs.doneCh = doneCh
	cs.tickerMu.Unlock()

	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), interval)
				if err := cs.Sync(ctx); err != nil && cs.server != nil {
					cs.server.logWarn("background catalog sync failed", "error", err.Error())
				}
				cancel()
			}
		}
	}()
}

// Stop halts any active background catalog synchronization goroutine and waits for exit.
func (cs *CatalogSyncer) Stop() {
	if cs == nil {
		return
	}
	cs.tickerMu.Lock()
	stopCh := cs.stopCh
	doneCh := cs.doneCh
	cs.stopCh = nil
	cs.doneCh = nil
	cs.tickerMu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if doneCh != nil {
		<-doneCh
	}
}

// SetCatalogSyncInterval starts or stops background periodic catalog synchronization (`<=0` stops).
func (s *Server) SetCatalogSyncInterval(d time.Duration) {
	if s == nil || s.catalogSyncer == nil {
		return
	}
	s.catalogSyncer.Start(d)
}

func appendBoundedStringMapEntry(outer map[string]map[string]string, key1, key2, val string, capPerKey int) {
	inner, ok := outer[key1]
	if !ok {
		inner = make(map[string]string)
		outer[key1] = inner
	}
	if _, exists := inner[key2]; !exists && capPerKey > 0 && len(inner) >= capPerKey {
		evict := len(inner) - capPerKey + 1
		for k := range inner {
			delete(inner, k)
			evict--
			if evict <= 0 {
				break
			}
		}
	}
	inner[key2] = val
}

func appendBoundedInt64MapEntry(outer map[string]map[string]int64, key1, key2 string, val int64, capPerKey int) {
	inner, ok := outer[key1]
	if !ok {
		inner = make(map[string]int64)
		outer[key1] = inner
	}
	if _, exists := inner[key2]; !exists && capPerKey > 0 && len(inner) >= capPerKey {
		evict := len(inner) - capPerKey + 1
		for k := range inner {
			delete(inner, k)
			evict--
			if evict <= 0 {
				break
			}
		}
	}
	inner[key2] = val
}
