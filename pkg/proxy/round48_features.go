package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// ============================================================================
// F3: Stored Scripts CRUD (`/_scripts/{id}`) & Painless Execute (`/_scripts/painless/_execute`)
// ============================================================================

func (s *Server) persistStoredScript(ctx context.Context, id string, scriptObj map[string]any) {
	activeStoredScriptsServerMu.Lock()
	activeStoredScriptsServer = s
	activeStoredScriptsServerMu.Unlock()
	if cb, ok := s.backend.(CatalogBackend); ok {
		if raw, err := json.Marshal(scriptObj); err == nil {
			_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
				EntityType:     "script",
				EntityKey:      id,
				PayloadJSON:    string(raw),
				UpdatedEpochMs: s.allocVersion(0),
			})
		}
	}
}

func (s *Server) deleteStoredScriptCatalog(ctx context.Context, id string) {
	s.deleteCatalogEntity(ctx, "script", id)
}

func (s *Server) lookupStoredScript(id string) (map[string]any, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false
	}
	s.mu.RLock()
	sc, ok := s.scripts[id]
	if ok && sc != nil {
		cp := deepCloneDocMap(sc)
		s.mu.RUnlock()
		return cp, true
	}
	s.mu.RUnlock()
	return nil, false
}

func (s *Server) handleScriptsAPI(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	id := strings.TrimSpace(r.PathValue("id"))
	ctxOrId := strings.TrimSpace(r.PathValue("context"))
	if (id == "painless" || id == "mustache" || id == "expression") && ctxOrId != "" && ctxOrId != "_execute" {
		// Support legacy PUT/GET/DELETE /_scripts/{lang}/{id}
		id = ctxOrId
	}
	if id == "" {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: script id is missing;")
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		bodyBytes, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var payload map[string]any
		if len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
				return
			}
		}
		scriptRaw, hasScript := payload["script"]
		if !hasScript || scriptRaw == nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "script must be specified")
			return
		}
		scriptMap, ok := scriptRaw.(map[string]any)
		if !ok {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "script must be an object")
			return
		}
		src, _ := scriptMap["source"].(string)
		if src == "" {
			if inl, okI := scriptMap["inline"].(string); okI && inl != "" {
				src = inl
			} else if scriptMap["source"] != nil {
				if b, err := json.Marshal(scriptMap["source"]); err == nil {
					src = string(b)
				}
			}
		}
		if strings.TrimSpace(src) == "" {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "script.source must be specified")
			return
		}
		lang, _ := scriptMap["lang"].(string)
		if strings.TrimSpace(lang) == "" {
			lang = "painless"
		}
		stored := map[string]any{
			"lang":   lang,
			"source": src,
		}
		if opts, okO := scriptMap["options"].(map[string]any); okO && len(opts) > 0 {
			stored["options"] = opts
		}
		if params, okP := scriptMap["params"].(map[string]any); okP && len(params) > 0 {
			stored["params"] = params
		}
		s.mu.Lock()
		if s.scripts == nil {
			s.scripts = make(map[string]map[string]any)
		}
		s.scripts[id] = stored
		s.mu.Unlock()
		s.persistStoredScript(r.Context(), id, stored)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	case http.MethodHead:
		if id == "" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if _, found := s.lookupStoredScript(id); !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		sc, found := s.lookupStoredScript(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"_id":   id,
				"found": false,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"_id":    id,
			"found":  true,
			"script": sc,
		})

	case http.MethodDelete:
		s.mu.Lock()
		_, existed := s.scripts[id]
		delete(s.scripts, id)
		s.mu.Unlock()
		if !existed {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("script [%s] is missing", id))
			return
		}
		s.deleteStoredScriptCatalog(r.Context(), id)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
	}
}

func (s *Server) handlePainlessExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var payload map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	rawScript, hasScript := payload["script"]
	if !hasScript || rawScript == nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "script is required")
		return
	}
	if missingID := s.findMissingStoredScriptInSpec(rawScript); missingID != "" {
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("cannot execute stored script [%s] because it does not exist", missingID))
		return
	}
	resolvedScript := s.resolveStoredScriptSpec(rawScript)
	src, params := extractScriptSourceAndParams(resolvedScript)
	if strings.TrimSpace(src) == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "script source or stored script id is required")
		return
	}

	ctxName, _ := payload["context"].(string)
	ctxName = strings.ToLower(strings.TrimSpace(ctxName))

	docMap := make(map[string]any)
	var indexName string
	if cs, okCS := payload["context_setup"].(map[string]any); okCS {
		if idx, okI := cs["index"].(string); okI {
			indexName = strings.TrimSpace(idx)
		}
		if d, okD := cs["document"].(map[string]any); okD {
			docMap = deepCloneDocMap(d)
		}
	}
	var idxSchema *schema.IndexSchema
	if indexName != "" {
		idxSchema = s.getOrCompileReadOnlySchema(r.Context(), indexName)
	}
	evalDoc := prepareDocForRuntimeScript(idxSchema, docMap)
	if params == nil {
		params = make(map[string]any)
	}
	if _, hasSrc := params["_source"]; !hasSrc {
		params["_source"] = evalDoc
	}

	switch ctxName {
	case "score":
		if _, hasScore := params["_score"]; !hasScore {
			params["_score"] = 1.0
		}
		score, okScore, err := painless.EvalNumber(evalDoc, src, params)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
			return
		}
		if !okScore {
			score = 0.0
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": score})
	case "filter":
		matched, err := painless.EvalFilter(evalDoc, src, params)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": matched})
	case "ingest", "processor", "update":
		if ctxName == "ingest" || ctxName == "processor" {
			src = rewriteIngestCtxReferencesWithOp(src, true)
		}
		val, err := painless.Eval(evalDoc, src, params)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
			return
		}
		if _, hadExplicitReturn := params["__had_explicit_return"]; hadExplicitReturn {
			if m, okM := val.(map[string]any); okM {
				writeJSON(w, http.StatusOK, map[string]any{"result": m})
				return
			}
			if val != nil {
				writeJSON(w, http.StatusOK, map[string]any{"result": val})
				return
			}
		}
		cleaned := make(map[string]any, len(evalDoc))
		for k, v := range evalDoc {
			switch k {
			case "__doc_values", "__fields", "__meta_id", "_ingest", "__internal_ingest_orig":
				continue
			}
			cleaned[k] = v
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": cleaned})
	default:
		val, err := painless.Eval(evalDoc, src, params)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "script_exception", err.Error())
			return
		}
		switch val.(type) {
		case nil, bool, int, int64, float64, json.Number, string:
			writeJSON(w, http.StatusOK, map[string]any{"result": val})
		default:
			if b, errM := json.Marshal(val); errM == nil {
				var decoded any
				dec := json.NewDecoder(bytes.NewReader(b))
				dec.UseNumber()
				if errU := dec.Decode(&decoded); errU == nil {
					if strVal, isStr := decoded.(string); isStr {
						writeJSON(w, http.StatusOK, map[string]any{"result": strVal})
						return
					}
				}
				writeJSON(w, http.StatusOK, map[string]any{"result": string(b)})
			} else {
				writeJSON(w, http.StatusOK, map[string]any{"result": fmt.Sprintf("%v", val)})
			}
		}
	}
}

func (s *Server) resolveStoredScriptSpec(raw any) any {
	if raw == nil || s == nil {
		return raw
	}
	switch v := raw.(type) {
	case map[string]any:
		src, _ := v["source"].(string)
		if src == "" {
			src, _ = v["inline"].(string)
		}
		if src != "" {
			return v
		}
		id, _ := v["id"].(string)
		if id == "" {
			return v
		}
		stored, ok := s.lookupStoredScript(id)
		if !ok {
			return v
		}
		cp := make(map[string]any, len(v)+2)
		for k, val := range v {
			cp[k] = val
		}
		if storedSrc, okS := stored["source"].(string); okS {
			cp["source"] = storedSrc
		}
		if _, hasLang := cp["lang"]; !hasLang {
			if storedLang, okL := stored["lang"].(string); okL && storedLang != "" {
				cp["lang"] = storedLang
			}
		}
		if storedParams, okP := stored["params"].(map[string]any); okP && len(storedParams) > 0 {
			mergedParams := make(map[string]any, len(storedParams))
			for pk, pv := range storedParams {
				mergedParams[pk] = pv
			}
			if reqParams, okRP := cp["params"].(map[string]any); okRP {
				for pk, pv := range reqParams {
					mergedParams[pk] = pv
				}
			}
			cp["params"] = mergedParams
		}
		return cp
	}
	return raw
}

func (s *Server) resolvePainlessScriptSpecFromRaw(spec **painless.ScriptSpec, rawBody []byte) {
	if s == nil || spec == nil {
		return
	}
	if *spec != nil && strings.TrimSpace((*spec).Source) != "" {
		return
	}
	if len(bytes.TrimSpace(rawBody)) == 0 {
		return
	}
	var rawMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.UseNumber()
	if err := dec.Decode(&rawMap); err != nil {
		return
	}
	rawScript, ok := rawMap["script"]
	if !ok || rawScript == nil {
		return
	}
	resolved := s.resolveStoredScriptSpec(rawScript)
	src, params := extractScriptSourceAndParams(resolved)
	if strings.TrimSpace(src) == "" {
		return
	}
	if *spec == nil {
		*spec = &painless.ScriptSpec{}
	}
	(*spec).Source = src
	if len(params) > 0 {
		if (*spec).Params == nil {
			(*spec).Params = params
		} else {
			for k, v := range params {
				if _, exists := (*spec).Params[k]; !exists {
					(*spec).Params[k] = v
				}
			}
		}
	}
}

func (s *Server) resolveStoredScriptsInSearchRequest(req *esast.SearchRequest) {
	if s == nil || req == nil {
		return
	}
	if req.Query != nil {
		s.resolveStoredScriptsInQuery(req.Query)
	}
	if req.PostFilter != nil {
		s.resolveStoredScriptsInQuery(req.PostFilter)
	}
	for i := range req.Sort {
		if req.Sort[i].Entry.Script != nil {
			req.Sort[i].Entry.Script = s.resolveStoredScriptSpec(req.Sort[i].Entry.Script)
		}
	}
	for k, sf := range req.ScriptFields {
		if sfMap, ok := sf.(map[string]any); ok {
			if rawSc, hasSc := sfMap["script"]; hasSc && rawSc != nil {
				sfMap["script"] = s.resolveStoredScriptSpec(rawSc)
				req.ScriptFields[k] = sfMap
			} else {
				req.ScriptFields[k] = s.resolveStoredScriptSpec(sfMap)
			}
		}
	}
	for k, prop := range req.RuntimeMappings {
		if prop.Script != nil {
			prop.Script = s.resolveStoredScriptSpec(prop.Script)
			req.RuntimeMappings[k] = prop
		}
	}
	if len(req.Aggs) > 0 {
		s.resolveStoredScriptsInAggs(req.Aggs)
	}
	if len(req.Aggregations) > 0 {
		s.resolveStoredScriptsInAggs(req.Aggregations)
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil && req.Rescore[i].Query.RescoreQuery != nil {
			s.resolveStoredScriptsInQuery(req.Rescore[i].Query.RescoreQuery)
		}
	}
}

func (s *Server) resolveStoredScriptsInQuery(q *esast.Query) {
	if s == nil || q == nil {
		return
	}
	if q.Script != nil && q.Script.Script != nil {
		q.Script.Script = s.resolveStoredScriptSpec(q.Script.Script)
	}
	if q.ScriptScore != nil {
		if q.ScriptScore.Script != nil {
			q.ScriptScore.Script = s.resolveStoredScriptSpec(q.ScriptScore.Script)
		}
		if q.ScriptScore.Query != nil {
			s.resolveStoredScriptsInQuery(q.ScriptScore.Query)
		}
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil {
			s.resolveStoredScriptsInQuery(q.FunctionScore.Query)
		}
		if q.FunctionScore.ScriptScore != nil && q.FunctionScore.ScriptScore.Script != nil {
			q.FunctionScore.ScriptScore.Script = s.resolveStoredScriptSpec(q.FunctionScore.ScriptScore.Script)
		}
		for i := range q.FunctionScore.Functions {
			fn := &q.FunctionScore.Functions[i]
			if fn.Filter != nil {
				s.resolveStoredScriptsInQuery(fn.Filter)
			}
			if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
				fn.ScriptScore.Script = s.resolveStoredScriptSpec(fn.ScriptScore.Script)
			}
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			s.resolveStoredScriptsInQuery(&q.Bool.Must[i])
		}
		for i := range q.Bool.Should {
			s.resolveStoredScriptsInQuery(&q.Bool.Should[i])
		}
		for i := range q.Bool.Filter {
			s.resolveStoredScriptsInQuery(&q.Bool.Filter[i])
		}
		for i := range q.Bool.MustNot {
			s.resolveStoredScriptsInQuery(&q.Bool.MustNot[i])
		}
	}
	if q.ConstantScore != nil {
		s.resolveStoredScriptsInQuery(&q.ConstantScore.Filter)
	}
	if q.Boosting != nil {
		s.resolveStoredScriptsInQuery(&q.Boosting.Positive)
		s.resolveStoredScriptsInQuery(&q.Boosting.Negative)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			s.resolveStoredScriptsInQuery(&q.DisMax.Queries[i])
		}
	}
	if q.Nested != nil {
		s.resolveStoredScriptsInQuery(&q.Nested.Query)
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		s.resolveStoredScriptsInQuery(q.Wrapper.Decoded)
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		s.resolveStoredScriptsInQuery(q.Pinned.Organic)
	}
	if q.HasChild != nil {
		s.resolveStoredScriptsInQuery(&q.HasChild.Query)
	}
	if q.HasParent != nil {
		s.resolveStoredScriptsInQuery(&q.HasParent.Query)
	}
	for k, ts := range q.TermsSet {
		if ts.MinimumShouldMatchScript != nil {
			ts.MinimumShouldMatchScript = s.resolveStoredScriptSpec(ts.MinimumShouldMatchScript)
			q.TermsSet[k] = ts
		}
	}
}

func (s *Server) resolveStoredScriptsInAggs(aggs map[string]esast.AggSpec) {
	for k, spec := range aggs {
		if t := spec.EffectiveTerms(); t != nil && t.Script != nil {
			t.Script = s.resolveStoredScriptSpec(t.Script)
		}
		if spec.Histogram != nil && spec.Histogram.Script != nil {
			spec.Histogram.Script = s.resolveStoredScriptSpec(spec.Histogram.Script)
		}
		if spec.DateHistogram != nil && spec.DateHistogram.Script != nil {
			spec.DateHistogram.Script = s.resolveStoredScriptSpec(spec.DateHistogram.Script)
		}
		if r := spec.EffectiveRange(); r != nil && r.Script != nil {
			r.Script = s.resolveStoredScriptSpec(r.Script)
		}
		if spec.Filter != nil {
			s.resolveStoredScriptsInQuery(spec.Filter)
		}
		if spec.Filters != nil {
			for fk, fq := range spec.Filters.Filters {
				q := fq
				s.resolveStoredScriptsInQuery(&q)
				spec.Filters.Filters[fk] = q
			}
			for i := range spec.Filters.AnonymousFilters {
				s.resolveStoredScriptsInQuery(&spec.Filters.AnonymousFilters[i])
			}
		}
		for _, m := range []*esast.MetricAggSpec{
			spec.Avg, spec.Sum, spec.Min, spec.Max,
			spec.Stats, spec.ExtendedStats, spec.ValueCount, spec.Cardinality, spec.Boxplot,
		} {
			if m != nil && m.Script != nil {
				m.Script = s.resolveStoredScriptSpec(m.Script)
			}
		}
		if spec.Percentiles != nil && spec.Percentiles.Script != nil {
			spec.Percentiles.Script = s.resolveStoredScriptSpec(spec.Percentiles.Script)
		}
		if spec.PercentileRanks != nil && spec.PercentileRanks.Script != nil {
			spec.PercentileRanks.Script = s.resolveStoredScriptSpec(spec.PercentileRanks.Script)
		}
		if spec.StringStats != nil && spec.StringStats.Script != nil {
			spec.StringStats.Script = s.resolveStoredScriptSpec(spec.StringStats.Script)
		}
		if spec.Rate != nil && spec.Rate.Script != nil {
			spec.Rate.Script = s.resolveStoredScriptSpec(spec.Rate.Script)
		}
		if spec.BucketScript != nil && spec.BucketScript.Script != nil {
			spec.BucketScript.Script = s.resolveStoredScriptSpec(spec.BucketScript.Script)
		}
		if spec.ScriptedMetric != nil {
			if spec.ScriptedMetric.InitScript != nil {
				spec.ScriptedMetric.InitScript = s.resolveStoredScriptSpec(spec.ScriptedMetric.InitScript)
			}
			if spec.ScriptedMetric.MapScript != nil {
				spec.ScriptedMetric.MapScript = s.resolveStoredScriptSpec(spec.ScriptedMetric.MapScript)
			}
			if spec.ScriptedMetric.CombineScript != nil {
				spec.ScriptedMetric.CombineScript = s.resolveStoredScriptSpec(spec.ScriptedMetric.CombineScript)
			}
			if spec.ScriptedMetric.ReduceScript != nil {
				spec.ScriptedMetric.ReduceScript = s.resolveStoredScriptSpec(spec.ScriptedMetric.ReduceScript)
			}
		}
		if len(spec.Aggs) > 0 {
			s.resolveStoredScriptsInAggs(spec.Aggs)
		}
		if len(spec.Aggregations) > 0 {
			s.resolveStoredScriptsInAggs(spec.Aggregations)
		}
		aggs[k] = spec
	}
}

func (s *Server) findMissingStoredScriptInSpec(raw any) string {
	if raw == nil || s == nil {
		return ""
	}
	if v, ok := raw.(map[string]any); ok {
		src, _ := v["source"].(string)
		if src == "" {
			src, _ = v["inline"].(string)
		}
		if strings.TrimSpace(src) != "" {
			return ""
		}
		id, _ := v["id"].(string)
		id = strings.TrimSpace(id)
		if id != "" {
			if _, ok := s.lookupStoredScript(id); !ok {
				return id
			}
		}
	}
	return ""
}

func (s *Server) findMissingStoredScriptInRawBody(rawBody []byte) string {
	if s == nil || len(bytes.TrimSpace(rawBody)) == 0 {
		return ""
	}
	var rawMap map[string]any
	if err := json.Unmarshal(rawBody, &rawMap); err != nil {
		return ""
	}
	return s.findMissingStoredScriptInSpec(rawMap["script"])
}

func (s *Server) validateStoredScriptsInSearchRequest(req *esast.SearchRequest) string {
	if s == nil || req == nil {
		return ""
	}
	if m := s.validateStoredScriptsInQuery(req.Query); m != "" {
		return m
	}
	if m := s.validateStoredScriptsInQuery(req.PostFilter); m != "" {
		return m
	}
	for i := range req.Sort {
		if m := s.findMissingStoredScriptInSpec(req.Sort[i].Entry.Script); m != "" {
			return m
		}
	}
	for _, sf := range req.ScriptFields {
		if sfMap, ok := sf.(map[string]any); ok {
			if rawSc, hasSc := sfMap["script"]; hasSc && rawSc != nil {
				if m := s.findMissingStoredScriptInSpec(rawSc); m != "" {
					return m
				}
			} else if m := s.findMissingStoredScriptInSpec(sfMap); m != "" {
				return m
			}
		}
	}
	for _, prop := range req.RuntimeMappings {
		if m := s.findMissingStoredScriptInSpec(prop.Script); m != "" {
			return m
		}
	}
	if m := s.validateStoredScriptsInAggs(req.Aggs); m != "" {
		return m
	}
	if m := s.validateStoredScriptsInAggs(req.Aggregations); m != "" {
		return m
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil && req.Rescore[i].Query.RescoreQuery != nil {
			if m := s.validateStoredScriptsInQuery(req.Rescore[i].Query.RescoreQuery); m != "" {
				return m
			}
		}
	}
	return ""
}

func (s *Server) validateStoredScriptsInQuery(q *esast.Query) string {
	if s == nil || q == nil {
		return ""
	}
	if q.Script != nil {
		if m := s.findMissingStoredScriptInSpec(q.Script.Script); m != "" {
			return m
		}
	}
	if q.ScriptScore != nil {
		if m := s.findMissingStoredScriptInSpec(q.ScriptScore.Script); m != "" {
			return m
		}
		if m := s.validateStoredScriptsInQuery(q.ScriptScore.Query); m != "" {
			return m
		}
	}
	if q.FunctionScore != nil {
		if m := s.validateStoredScriptsInQuery(q.FunctionScore.Query); m != "" {
			return m
		}
		if q.FunctionScore.ScriptScore != nil {
			if m := s.findMissingStoredScriptInSpec(q.FunctionScore.ScriptScore.Script); m != "" {
				return m
			}
		}
		for i := range q.FunctionScore.Functions {
			fn := &q.FunctionScore.Functions[i]
			if m := s.validateStoredScriptsInQuery(fn.Filter); m != "" {
				return m
			}
			if fn.ScriptScore != nil {
				if m := s.findMissingStoredScriptInSpec(fn.ScriptScore.Script); m != "" {
					return m
				}
			}
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if m := s.validateStoredScriptsInQuery(&q.Bool.Must[i]); m != "" {
				return m
			}
		}
		for i := range q.Bool.Should {
			if m := s.validateStoredScriptsInQuery(&q.Bool.Should[i]); m != "" {
				return m
			}
		}
		for i := range q.Bool.Filter {
			if m := s.validateStoredScriptsInQuery(&q.Bool.Filter[i]); m != "" {
				return m
			}
		}
		for i := range q.Bool.MustNot {
			if m := s.validateStoredScriptsInQuery(&q.Bool.MustNot[i]); m != "" {
				return m
			}
		}
	}
	if q.ConstantScore != nil {
		if m := s.validateStoredScriptsInQuery(&q.ConstantScore.Filter); m != "" {
			return m
		}
	}
	if q.Boosting != nil {
		if m := s.validateStoredScriptsInQuery(&q.Boosting.Positive); m != "" {
			return m
		}
		if m := s.validateStoredScriptsInQuery(&q.Boosting.Negative); m != "" {
			return m
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if m := s.validateStoredScriptsInQuery(&q.DisMax.Queries[i]); m != "" {
				return m
			}
		}
	}
	if q.Nested != nil {
		if m := s.validateStoredScriptsInQuery(&q.Nested.Query); m != "" {
			return m
		}
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		if m := s.validateStoredScriptsInQuery(q.Wrapper.Decoded); m != "" {
			return m
		}
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		if m := s.validateStoredScriptsInQuery(q.Pinned.Organic); m != "" {
			return m
		}
	}
	if q.HasChild != nil {
		if m := s.validateStoredScriptsInQuery(&q.HasChild.Query); m != "" {
			return m
		}
	}
	if q.HasParent != nil {
		if m := s.validateStoredScriptsInQuery(&q.HasParent.Query); m != "" {
			return m
		}
	}
	for _, ts := range q.TermsSet {
		if m := s.findMissingStoredScriptInSpec(ts.MinimumShouldMatchScript); m != "" {
			return m
		}
	}
	return ""
}

func (s *Server) validateStoredScriptsInAggs(aggs map[string]esast.AggSpec) string {
	for _, spec := range aggs {
		if t := spec.EffectiveTerms(); t != nil {
			if m := s.findMissingStoredScriptInSpec(t.Script); m != "" {
				return m
			}
		}
		if spec.Histogram != nil {
			if m := s.findMissingStoredScriptInSpec(spec.Histogram.Script); m != "" {
				return m
			}
		}
		if spec.DateHistogram != nil {
			if m := s.findMissingStoredScriptInSpec(spec.DateHistogram.Script); m != "" {
				return m
			}
		}
		if r := spec.EffectiveRange(); r != nil {
			if m := s.findMissingStoredScriptInSpec(r.Script); m != "" {
				return m
			}
		}
		if m := s.validateStoredScriptsInQuery(spec.Filter); m != "" {
			return m
		}
		if spec.Filters != nil {
			for _, fq := range spec.Filters.Filters {
				q := fq
				if m := s.validateStoredScriptsInQuery(&q); m != "" {
					return m
				}
			}
			for i := range spec.Filters.AnonymousFilters {
				if m := s.validateStoredScriptsInQuery(&spec.Filters.AnonymousFilters[i]); m != "" {
					return m
				}
			}
		}
		for _, mSpec := range []*esast.MetricAggSpec{
			spec.Avg, spec.Sum, spec.Min, spec.Max,
			spec.Stats, spec.ExtendedStats, spec.ValueCount, spec.Cardinality, spec.Boxplot,
		} {
			if mSpec != nil {
				if m := s.findMissingStoredScriptInSpec(mSpec.Script); m != "" {
					return m
				}
			}
		}
		if spec.Percentiles != nil {
			if m := s.findMissingStoredScriptInSpec(spec.Percentiles.Script); m != "" {
				return m
			}
		}
		if spec.PercentileRanks != nil {
			if m := s.findMissingStoredScriptInSpec(spec.PercentileRanks.Script); m != "" {
				return m
			}
		}
		if spec.StringStats != nil {
			if m := s.findMissingStoredScriptInSpec(spec.StringStats.Script); m != "" {
				return m
			}
		}
		if spec.Rate != nil {
			if m := s.findMissingStoredScriptInSpec(spec.Rate.Script); m != "" {
				return m
			}
		}
		if spec.BucketScript != nil {
			if m := s.findMissingStoredScriptInSpec(spec.BucketScript.Script); m != "" {
				return m
			}
		}
		if spec.ScriptedMetric != nil {
			for _, sc := range []any{
				spec.ScriptedMetric.InitScript,
				spec.ScriptedMetric.MapScript,
				spec.ScriptedMetric.CombineScript,
				spec.ScriptedMetric.ReduceScript,
			} {
				if m := s.findMissingStoredScriptInSpec(sc); m != "" {
					return m
				}
			}
		}
		if m := s.validateStoredScriptsInAggs(spec.Aggs); m != "" {
			return m
		}
		if m := s.validateStoredScriptsInAggs(spec.Aggregations); m != "" {
			return m
		}
	}
	return ""
}

// ============================================================================
// F4: Mustache Search Templates (`/_search/template`, `/_render/template`, `/_msearch/template`)
// ============================================================================

func renderMustacheSearchTemplate(tplSource any, params map[string]any) (json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	var tplStr string
	switch v := tplSource.(type) {
	case string:
		tplStr = v
	case json.RawMessage:
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			tplStr = s
		} else {
			tplStr = string(v)
		}
	case nil:
		return nil, fmt.Errorf("template source is empty")
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		tplStr = string(b)
	}
	rendered := evalMustacheBlock(tplStr, params, nil)
	trimmed := strings.TrimSpace(rendered)
	if trimmed == "" {
		return json.RawMessage(`{}`), nil
	}
	// Validate JSON or normalize if needed
	var check any
	if err := json.Unmarshal([]byte(trimmed), &check); err != nil {
		return nil, fmt.Errorf("rendered mustache template is not valid JSON: %w (rendered: %s)", err, trimmed)
	}
	return json.RawMessage(trimmed), nil
}

func lookupMustacheVar(path string, ctx map[string]any, dotVal any) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "." {
		if dotVal != nil {
			return dotVal, true
		}
		if v, ok := ctx["."]; ok {
			return v, true
		}
		return ctx, len(ctx) > 0
	}
	if dotMap, ok := dotVal.(map[string]any); ok {
		if v, exists := lookupMustachePathInMap(path, dotMap); exists {
			return v, true
		}
	}
	return lookupMustachePathInMap(path, ctx)
}

func lookupMustachePathInMap(path string, m map[string]any) (any, bool) {
	if len(m) == 0 {
		return nil, false
	}
	if v, ok := m[path]; ok {
		return v, true
	}
	parts := strings.Split(path, ".")
	var cur any = m
	for _, p := range parts {
		cm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		val, exists := cm[p]
		if !exists {
			return nil, false
		}
		cur = val
	}
	return cur, true
}

func isMustacheTruthy(v any) bool {
	if v == nil {
		return false
	}
	switch tv := v.(type) {
	case bool:
		return tv
	case string:
		return tv != ""
	case []any:
		return len(tv) > 0
	case []string:
		return len(tv) > 0
	case map[string]any:
		return len(tv) > 0
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Map {
			return rv.Len() > 0
		}
		return true
	}
}

func formatMustacheScalar(v any) string {
	if v == nil {
		return ""
	}
	switch tv := v.(type) {
	case string:
		return tv
	case json.Number:
		return tv.String()
	case bool:
		if tv {
			return "true"
		}
		return "false"
	case float64:
		if tv == math.Trunc(tv) && !math.IsInf(tv, 0) && !math.IsNaN(tv) {
			return strconv.FormatInt(int64(tv), 10)
		}
		return strconv.FormatFloat(tv, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func evalMustacheBlock(tpl string, ctx map[string]any, dotVal any) string {
	var out strings.Builder
	i := 0
	n := len(tpl)
	for i < n {
		openIdx := strings.Index(tpl[i:], "{{")
		if openIdx < 0 {
			out.WriteString(tpl[i:])
			break
		}
		out.WriteString(tpl[i : i+openIdx])
		tagStart := i + openIdx
		if tagStart+3 <= n && tpl[tagStart:tagStart+3] == "{{{" {
			closeIdx := strings.Index(tpl[tagStart+3:], "}}}")
			if closeIdx < 0 {
				out.WriteString(tpl[tagStart:])
				break
			}
			varName := strings.TrimSpace(tpl[tagStart+3 : tagStart+3+closeIdx])
			if val, ok := lookupMustacheVar(varName, ctx, dotVal); ok {
				out.WriteString(formatMustacheScalar(val))
			}
			i = tagStart + 3 + closeIdx + 3
			continue
		}
		closeIdx := strings.Index(tpl[tagStart+2:], "}}")
		if closeIdx < 0 {
			out.WriteString(tpl[tagStart:])
			break
		}
		rawTag := strings.TrimSpace(tpl[tagStart+2 : tagStart+2+closeIdx])
		afterOpenTag := tagStart + 2 + closeIdx + 2
		if rawTag == "" {
			i = afterOpenTag
			continue
		}
		prefix := rawTag[0]
		switch prefix {
		case '!':
			// Comment tag {{! ... }}
			i = afterOpenTag
		case '#', '^':
			tagBody := strings.TrimSpace(rawTag[1:])
			// Check special Elastic Mustache lambdas: #toJson, #join, #url
			if prefix == '#' && (tagBody == "toJson" || strings.HasPrefix(tagBody, "toJson ")) {
				endMarker := "{{/toJson}}"
				endIdx := strings.Index(tpl[afterOpenTag:], endMarker)
				if endIdx >= 0 {
					innerVar := strings.TrimSpace(tpl[afterOpenTag : afterOpenTag+endIdx])
					if val, ok := lookupMustacheVar(innerVar, ctx, dotVal); ok {
						if b, err := json.Marshal(val); err == nil {
							// If the surrounding template already wrapped `{{#toJson}}...{{/toJson}}` in quotes `"{{#toJson}}...{{/toJson}}"`,
							// strip the outer quotes in `out` and after closing tag!
							strOut := out.String()
							nextPos := afterOpenTag + endIdx + len(endMarker)
							if strings.HasSuffix(strOut, `"`) && nextPos < n && tpl[nextPos] == '"' {
								trimmedOut := strOut[:len(strOut)-1]
								out.Reset()
								out.WriteString(trimmedOut)
								out.Write(b)
								i = nextPos + 1
								continue
							}
							out.Write(b)
						}
					} else {
						out.WriteString("null")
					}
					i = afterOpenTag + endIdx + len(endMarker)
					continue
				}
			}
			if prefix == '#' && (tagBody == "join" || strings.HasPrefix(tagBody, "join ")) {
				endMarker := "{{/join}}"
				endIdx := strings.Index(tpl[afterOpenTag:], endMarker)
				if endIdx >= 0 {
					delim := ","
					if strings.HasPrefix(tagBody, "join ") {
						rest := strings.TrimSpace(strings.TrimPrefix(tagBody, "join"))
						if strings.HasPrefix(rest, "delimiter=") {
							dVal := strings.TrimPrefix(rest, "delimiter=")
							dVal = strings.Trim(dVal, "'\"")
							delim = dVal
						}
					}
					innerVar := strings.TrimSpace(tpl[afterOpenTag : afterOpenTag+endIdx])
					if val, ok := lookupMustacheVar(innerVar, ctx, dotVal); ok {
						var items []string
						switch arr := val.(type) {
						case []any:
							for _, el := range arr {
								items = append(items, formatMustacheScalar(el))
							}
						case []string:
							items = append(items, arr...)
						default:
							items = []string{formatMustacheScalar(val)}
						}
						out.WriteString(strings.Join(items, delim))
					}
					i = afterOpenTag + endIdx + len(endMarker)
					continue
				}
			}
			if prefix == '#' && tagBody == "url" {
				endMarker := "{{/url}}"
				endIdx := strings.Index(tpl[afterOpenTag:], endMarker)
				if endIdx >= 0 {
					innerTpl := tpl[afterOpenTag : afterOpenTag+endIdx]
					innerRendered := evalMustacheBlock(innerTpl, ctx, dotVal)
					out.WriteString(strings.ReplaceAll(url.QueryEscape(innerRendered), "+", "%20"))
					i = afterOpenTag + endIdx + len(endMarker)
					continue
				}
			}
			// Normal section or inverted section
			secName := tagBody
			endMarker := "{{/" + secName + "}}"
			endIdx := findMatchingMustacheSectionEnd(tpl[afterOpenTag:], secName)
			if endIdx < 0 {
				i = afterOpenTag
				continue
			}
			innerTpl := tpl[afterOpenTag : afterOpenTag+endIdx]
			val, exists := lookupMustacheVar(secName, ctx, dotVal)
			truthy := exists && isMustacheTruthy(val)
			if prefix == '^' {
				if !truthy {
					out.WriteString(evalMustacheBlock(innerTpl, ctx, dotVal))
				}
			} else if truthy {
				switch tv := val.(type) {
				case []any:
					for _, elem := range tv {
						out.WriteString(evalMustacheBlock(innerTpl, ctx, elem))
					}
				case []string:
					for _, elem := range tv {
						out.WriteString(evalMustacheBlock(innerTpl, ctx, elem))
					}
				case map[string]any:
					mergedCtx := make(map[string]any, len(ctx)+len(tv))
					for k, v := range ctx {
						mergedCtx[k] = v
					}
					for k, v := range tv {
						mergedCtx[k] = v
					}
					out.WriteString(evalMustacheBlock(innerTpl, mergedCtx, tv))
				default:
					out.WriteString(evalMustacheBlock(innerTpl, ctx, dotVal))
				}
			}
			i = afterOpenTag + endIdx + len(endMarker)
		case '&':
			varName := strings.TrimSpace(rawTag[1:])
			if val, ok := lookupMustacheVar(varName, ctx, dotVal); ok {
				out.WriteString(formatMustacheScalar(val))
			}
			i = afterOpenTag
		default:
			if val, ok := lookupMustacheVar(rawTag, ctx, dotVal); ok {
				out.WriteString(formatMustacheScalar(val))
			}
			i = afterOpenTag
		}
	}
	return out.String()
}

func findMatchingMustacheSectionEnd(s, secName string) int {
	openTag1 := "{{#" + secName + "}}"
	openTag2 := "{{^" + secName + "}}"
	closeTag := "{{/" + secName + "}}"
	depth := 1
	pos := 0
	for pos < len(s) {
		nextClose := strings.Index(s[pos:], closeTag)
		if nextClose < 0 {
			return -1
		}
		absClose := pos + nextClose
		segment := s[pos:absClose]
		depth += strings.Count(segment, openTag1) + strings.Count(segment, openTag2)
		depth--
		if depth == 0 {
			return absClose
		}
		pos = absClose + len(closeTag)
	}
	return -1
}

func (s *Server) resolveTemplateSourceAndParams(r *http.Request, pathID string, body map[string]any) (any, map[string]any, int, string, string) {
	rawParams, _ := body["params"].(map[string]any)
	params := make(map[string]any, len(rawParams))
	for k, v := range rawParams {
		params[k] = v
	}
	if r != nil && r.URL != nil {
		for k, vals := range r.URL.Query() {
			switch k {
			case "pretty", "human", "error_trace", "source", "source_content_type", "filter_path", "typed_keys", "rest_total_hits_as_int":
				continue
			}
			if _, exists := params[k]; !exists && len(vals) > 0 {
				params[k] = vals[0]
			}
		}
	}
	tplSource := body["source"]
	if tplSource == nil {
		tplSource = body["inline"]
	}
	tplID, _ := body["id"].(string)
	if tplID == "" {
		tplID, _ = body["file"].(string)
	}
	if tplID == "" {
		tplID = pathID
	}
	if tplSource == nil && tplID != "" {
		stored, ok := s.lookupStoredScript(tplID)
		if !ok {
			return nil, nil, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("script [%s] is missing", tplID)
		}
		tplSource = stored["source"]
		if storedParams, okP := stored["params"].(map[string]any); okP && len(storedParams) > 0 {
			merged := make(map[string]any, len(storedParams)+len(params))
			for k, v := range storedParams {
				merged[k] = v
			}
			for k, v := range params {
				merged[k] = v
			}
			params = merged
		}
	}
	if tplSource == nil {
		return nil, nil, http.StatusBadRequest, "illegal_argument_exception", "search template must specify either [source] or [id]"
	}
	return tplSource, params, http.StatusOK, "", ""
}

func (s *Server) handleRenderSearchTemplate(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var body map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if body == nil {
		body = make(map[string]any)
	}
	tplSource, params, status, errType, errReason := s.resolveTemplateSourceAndParams(r, strings.TrimSpace(r.PathValue("id")), body)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	renderedJSON, err := renderMustacheSearchTemplate(tplSource, params)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	renderedJSON = coerceSearchTemplateNumericFields(renderedJSON)
	var parsed map[string]any
	dec := json.NewDecoder(bytes.NewReader(renderedJSON))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"template_output": parsed,
	})
}

func coerceSearchTemplateNumericInMap(m map[string]any) bool {
	if m == nil {
		return false
	}
	changed := false
	for _, intKey := range []string{"size", "from", "terminate_after", "shard_size", "min_doc_count", "k", "num_candidates"} {
		if sv, ok := m[intKey].(string); ok {
			if iv, err := strconv.Atoi(strings.TrimSpace(sv)); err == nil {
				m[intKey] = iv
				changed = true
			}
		}
	}
	for _, floatKey := range []string{"min_score", "boost"} {
		if sf, ok := m[floatKey].(string); ok {
			if fv, err := strconv.ParseFloat(strings.TrimSpace(sf), 64); err == nil {
				m[floatKey] = fv
				changed = true
			}
		}
	}
	for k, v := range m {
		switch sub := v.(type) {
		case map[string]any:
			if coerceSearchTemplateNumericInMap(sub) {
				changed = true
			}
		case []any:
			for i, el := range sub {
				if elMap, okM := el.(map[string]any); okM {
					if coerceSearchTemplateNumericInMap(elMap) {
						sub[i] = elMap
						changed = true
					}
				}
			}
			m[k] = sub
		}
	}
	return changed
}

func coerceSearchTemplateNumericFields(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		return raw
	}
	if !coerceSearchTemplateNumericInMap(m) {
		return raw
	}
	if b, err := json.Marshal(m); err == nil {
		return json.RawMessage(b)
	}
	return raw
}

func (s *Server) handleSearchTemplate(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var body map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if body == nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "search template request body is required")
		return
	}
	tplSource, params, status, errType, errReason := s.resolveTemplateSourceAndParams(r, "", body)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	renderedJSON, err := renderMustacheSearchTemplate(tplSource, params)
	if err != nil {
		writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
		return
	}
	renderedJSON = coerceSearchTemplateNumericFields(renderedJSON)
	clonedReq := r.Clone(r.Context())
	clonedReq.Body = io.NopCloser(bytes.NewReader(renderedJSON))
	clonedReq.ContentLength = int64(len(renderedJSON))
	s.handleSearch(w, clonedReq)
}

type bufferResponseWriter struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (b *bufferResponseWriter) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}

func (b *bufferResponseWriter) WriteHeader(statusCode int) {
	b.status = statusCode
}

func (b *bufferResponseWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.buf.Write(p)
}

func (s *Server) handleMSearchTemplate(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	rawLines := strings.Split(strings.TrimRight(string(bodyBytes), "\r\n"), "\n")
	var lines []string
	for _, rl := range rawLines {
		if strings.TrimSpace(rl) != "" {
			lines = append(lines, rl)
		}
	}
	if len(lines) < 2 || len(lines)%2 != 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: no requests added;")
		return
	}
	var rewrittenBuf bytes.Buffer
	perItemErrors := make(map[int]map[string]any)
	numItems := len(lines) / 2
	validItems := 0
	for idx := 0; idx < numItems; idx++ {
		hdrLine := strings.TrimSpace(lines[idx*2])
		tplLine := strings.TrimSpace(lines[idx*2+1])

		var body map[string]any
		dec := json.NewDecoder(strings.NewReader(tplLine))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
			perItemErrors[idx] = map[string]any{
				"status": http.StatusBadRequest,
				"error":  map[string]any{"type": "parsing_exception", "reason": err.Error()},
			}
			continue
		}
		tplSource, params, status, errType, errReason := s.resolveTemplateSourceAndParams(r, "", body)
		if errType != "" {
			perItemErrors[idx] = map[string]any{
				"status": status,
				"error":  map[string]any{"type": errType, "reason": errReason},
			}
			continue
		}
		renderedJSON, err := renderMustacheSearchTemplate(tplSource, params)
		if err != nil {
			perItemErrors[idx] = map[string]any{
				"status": http.StatusBadRequest,
				"error":  map[string]any{"type": "parsing_exception", "reason": err.Error()},
			}
			continue
		}
		renderedJSON = coerceSearchTemplateNumericFields(renderedJSON)
		rewrittenBuf.WriteString(hdrLine)
		rewrittenBuf.WriteByte('\n')
		var compact bytes.Buffer
		if errC := json.Compact(&compact, renderedJSON); errC == nil {
			rewrittenBuf.Write(compact.Bytes())
		} else {
			rewrittenBuf.Write(renderedJSON)
		}
		rewrittenBuf.WriteByte('\n')
		validItems++
	}
	if len(perItemErrors) == 0 {
		clonedReq := r.Clone(r.Context())
		clonedReq.Body = io.NopCloser(bytes.NewReader(rewrittenBuf.Bytes()))
		clonedReq.ContentLength = int64(rewrittenBuf.Len())
		s.handleMSearch(w, clonedReq)
		return
	}
	var validResponses []any
	if validItems > 0 {
		rec := &bufferResponseWriter{}
		clonedReq := r.Clone(r.Context())
		clonedReq.Body = io.NopCloser(bytes.NewReader(rewrittenBuf.Bytes()))
		clonedReq.ContentLength = int64(rewrittenBuf.Len())
		s.handleMSearch(rec, clonedReq)
		var msearchOut map[string]any
		dec := json.NewDecoder(bytes.NewReader(rec.buf.Bytes()))
		dec.UseNumber()
		if err := dec.Decode(&msearchOut); err == nil {
			validResponses, _ = msearchOut["responses"].([]any)
		}
	}
	finalResponses := make([]any, 0, numItems)
	validCursor := 0
	for idx := 0; idx < numItems; idx++ {
		if errObj, hasErr := perItemErrors[idx]; hasErr {
			finalResponses = append(finalResponses, errObj)
		} else if validCursor < len(validResponses) {
			finalResponses = append(finalResponses, validResponses[validCursor])
			validCursor++
		} else {
			finalResponses = append(finalResponses, map[string]any{})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"took":      4,
		"responses": finalResponses,
	})
}

// ============================================================================
// F5: Term Vectors (`/_termvectors`, `/_mtermvectors`), Rank Eval (`/_rank_eval`), and Vector Tile (`/_mvt`)
// ============================================================================

type termTokenOccurrence struct {
	term        string
	position    int
	startOffset int
	endOffset   int
}

func tokenizeTermVectorString(text string) []termTokenOccurrence {
	var out []termTokenOccurrence
	pos := 0
	inTok := false
	tokStartRune := 0
	runeIdx := 0
	var buf strings.Builder
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if !inTok {
				inTok = true
				tokStartRune = runeIdx
				buf.Reset()
			}
			buf.WriteRune(unicode.ToLower(r))
		} else if inTok {
			out = append(out, termTokenOccurrence{
				term:        buf.String(),
				position:    pos,
				startOffset: tokStartRune,
				endOffset:   runeIdx,
			})
			pos++
			inTok = false
		}
		runeIdx++
	}
	if inTok {
		out = append(out, termTokenOccurrence{
			term:        buf.String(),
			position:    pos,
			startOffset: tokStartRune,
			endOffset:   runeIdx,
		})
	}
	return out
}

func tokenizeTermVectorStringWithAnalyzer(text, analyzer string) []termTokenOccurrence {
	switch strings.ToLower(strings.TrimSpace(analyzer)) {
	case "keyword", "noop":
		if text == "" {
			return nil
		}
		return []termTokenOccurrence{{
			term:        text,
			position:    0,
			startOffset: 0,
			endOffset:   len([]rune(text)),
		}}
	case "whitespace":
		var out []termTokenOccurrence
		pos := 0
		inTok := false
		tokStartRune := 0
		runeIdx := 0
		var buf strings.Builder
		for _, r := range text {
			if !unicode.IsSpace(r) {
				if !inTok {
					inTok = true
					tokStartRune = runeIdx
					buf.Reset()
				}
				buf.WriteRune(r)
			} else if inTok {
				out = append(out, termTokenOccurrence{
					term:        buf.String(),
					position:    pos,
					startOffset: tokStartRune,
					endOffset:   runeIdx,
				})
				pos++
				inTok = false
			}
			runeIdx++
		}
		if inTok {
			out = append(out, termTokenOccurrence{
				term:        buf.String(),
				position:    pos,
				startOffset: tokStartRune,
				endOffset:   runeIdx,
			})
		}
		return out
	default:
		return tokenizeTermVectorString(text)
	}
}

func (s *Server) indexExistsInCatalog(ctx context.Context, rawIndex string) bool {
	rawIndex = strings.TrimSpace(rawIndex)
	if rawIndex == "" {
		return true
	}
	_ = s.syncCatalogFromBackend(ctx)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, isIdx := s.indices[rawIndex]; isIdx {
		return true
	}
	if _, isAlias := s.aliases[rawIndex]; isAlias {
		return true
	}
	if _, isDS := s.dataStreams[rawIndex]; isDS {
		return true
	}
	if strings.HasPrefix(rawIndex, ".ds-") && strings.HasSuffix(rawIndex, "-000001") {
		dsName := strings.TrimSuffix(strings.TrimPrefix(rawIndex, ".ds-"), "-000001")
		if _, okDS := s.dataStreams[dsName]; okDS {
			return true
		}
	}
	return false
}

func extractStringsFromFieldVal(v any) []string {
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case string:
		return []string{tv}
	case []any:
		var out []string
		for _, el := range tv {
			out = append(out, extractStringsFromFieldVal(el)...)
		}
		return out
	case []string:
		return tv
	default:
		return nil
	}
}

func collectAllStringFieldPathsFromDoc(prefix string, doc map[string]any, out *[]string) {
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		switch v := doc[k].(type) {
		case string:
			*out = append(*out, full)
		case []any:
			hasStr := false
			for _, el := range v {
				if _, ok := el.(string); ok {
					hasStr = true
					break
				}
			}
			if hasStr {
				*out = append(*out, full)
			}
		case map[string]any:
			collectAllStringFieldPathsFromDoc(full, v, out)
		}
	}
}

func (s *Server) computeSingleTermVectorResponse(
	ctx context.Context,
	rawIndex string,
	docID string,
	bodyMap map[string]any,
	queryFields string,
	queryTermStats bool,
	queryFieldStats *bool,
	queryPositions *bool,
	queryOffsets *bool,
) (map[string]any, int, string, string) {
	if rawIndex == "" {
		if bIdx, ok := bodyMap["_index"].(string); ok && bIdx != "" {
			rawIndex = bIdx
		}
	}
	if docID == "" {
		if bID, ok := bodyMap["_id"].(string); ok && bID != "" {
			docID = bID
		}
	}
	if rawIndex != "" && !s.indexExistsInCatalog(ctx, rawIndex) {
		return nil, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", rawIndex)
	}
	indexName := rawIndex
	if indexName != "" {
		resolved, _, err := s.resolveReadDocIndexWithFilter(rawIndex)
		if err == nil && resolved != "" {
			indexName = resolved
		}
	}

	var docMap map[string]any
	var ver int64
	found := false

	if artificialDoc, ok := bodyMap["doc"].(map[string]any); ok && artificialDoc != nil {
		docMap = artificialDoc
		found = true
		ver = 0
	} else if indexName != "" && docID != "" {
		roSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
		_ = s.coalescer.FlushTable(ctx, roSchema.DorisTable)
		if existing, okFound, err := s.backend.GetDocByID(ctx, roSchema.DorisDB, roSchema.DorisTable, docID); err == nil && okFound && existing != nil {
			found = true
			ver = existing.Version
			_ = json.Unmarshal(existing.Source, &docMap)
		}
	}

	var requestedFields []string
	if rawFields, ok := bodyMap["fields"].([]any); ok {
		for _, f := range rawFields {
			if fs, okS := f.(string); okS && strings.TrimSpace(fs) != "" {
				requestedFields = append(requestedFields, strings.TrimSpace(fs))
			}
		}
	} else if rawFieldsStr, ok := bodyMap["fields"].([]string); ok {
		requestedFields = append(requestedFields, rawFieldsStr...)
	}
	if len(requestedFields) == 0 && queryFields != "" {
		for _, f := range strings.Split(queryFields, ",") {
			if f = strings.TrimSpace(f); f != "" {
				requestedFields = append(requestedFields, f)
			}
		}
	}
	var allDocFields []string
	if docMap != nil {
		collectAllStringFieldPathsFromDoc("", docMap, &allDocFields)
	}
	var fields []string
	if len(requestedFields) == 0 {
		fields = allDocFields
	} else {
		seenField := make(map[string]bool)
		for _, rf := range requestedFields {
			if strings.ContainsAny(rf, "*?") {
				for _, df := range allDocFields {
					if matchWildcardPattern(rf, df) && !seenField[df] {
						seenField[df] = true
						fields = append(fields, df)
					}
				}
			} else if !seenField[rf] {
				seenField[rf] = true
				fields = append(fields, rf)
			}
		}
	}

	perFieldAnalyzer := make(map[string]string)
	if rawPFA, ok := bodyMap["per_field_analyzer"].(map[string]any); ok {
		for k, v := range rawPFA {
			if vs, okS := v.(string); okS {
				perFieldAnalyzer[k] = vs
			}
		}
	}

	var filterMap map[string]any
	if rawFlt, ok := bodyMap["filter"].(map[string]any); ok {
		filterMap = rawFlt
	}
	minWordLen, hasMinWordLen := toInt64(filterMap["min_word_length"])
	maxWordLen, hasMaxWordLen := toInt64(filterMap["max_word_length"])
	minTermFreq, hasMinTermFreq := toInt64(filterMap["min_term_freq"])
	maxTermFreq, hasMaxTermFreq := toInt64(filterMap["max_term_freq"])
	minDocFreq, hasMinDocFreq := toInt64(filterMap["min_doc_freq"])
	maxDocFreq, hasMaxDocFreq := toInt64(filterMap["max_doc_freq"])
	maxNumTerms, hasMaxNumTerms := toInt64(filterMap["max_num_terms"])

	termStats := queryTermStats
	if bTS, ok := parseOptionalBoolAny(bodyMap["term_statistics"]); ok {
		termStats = bTS
	}
	fieldStats := true
	if queryFieldStats != nil {
		fieldStats = *queryFieldStats
	}
	if bFS, ok := parseOptionalBoolAny(bodyMap["field_statistics"]); ok {
		fieldStats = bFS
	}
	includePositions := true
	if queryPositions != nil {
		includePositions = *queryPositions
	}
	if bPos, ok := parseOptionalBoolAny(bodyMap["positions"]); ok {
		includePositions = bPos
	}
	includeOffsets := true
	if queryOffsets != nil {
		includeOffsets = *queryOffsets
	}
	if bOff, ok := parseOptionalBoolAny(bodyMap["offsets"]); ok {
		includeOffsets = bOff
	}

	termVectors := make(map[string]any)
	if found && docMap != nil {
		for _, field := range fields {
			val, exists := getIngestPath(docMap, field)
			if !exists || val == nil {
				continue
			}
			strs := extractStringsFromFieldVal(val)
			if len(strs) == 0 {
				continue
			}
			joined := strings.Join(strs, " ")
			occs := tokenizeTermVectorStringWithAnalyzer(joined, perFieldAnalyzer[field])
			if len(occs) == 0 {
				continue
			}
			byTerm := make(map[string][]termTokenOccurrence)
			var uniqueTerms []string
			for _, occ := range occs {
				if _, seen := byTerm[occ.term]; !seen {
					uniqueTerms = append(uniqueTerms, occ.term)
				}
				byTerm[occ.term] = append(byTerm[occ.term], occ)
			}
			var filteredTerms []string
			for _, t := range uniqueTerms {
				runeLen := int64(len([]rune(t)))
				if hasMinWordLen && runeLen < minWordLen {
					continue
				}
				if hasMaxWordLen && runeLen > maxWordLen {
					continue
				}
				tf := int64(len(byTerm[t]))
				if hasMinTermFreq && tf < minTermFreq {
					continue
				}
				if hasMaxTermFreq && tf > maxTermFreq {
					continue
				}
				df := int64(1)
				if hasMinDocFreq && df < minDocFreq {
					continue
				}
				if hasMaxDocFreq && df > maxDocFreq {
					continue
				}
				filteredTerms = append(filteredTerms, t)
			}
			if hasMaxNumTerms && maxNumTerms > 0 && int64(len(filteredTerms)) > maxNumTerms {
				sort.Slice(filteredTerms, func(i, j int) bool {
					tfi := len(byTerm[filteredTerms[i]])
					tfj := len(byTerm[filteredTerms[j]])
					if tfi != tfj {
						return tfi > tfj
					}
					return filteredTerms[i] < filteredTerms[j]
				})
				filteredTerms = filteredTerms[:maxNumTerms]
			}
			sort.Strings(filteredTerms)
			termsMap := make(map[string]any, len(filteredTerms))
			for _, t := range filteredTerms {
				tOccs := byTerm[t]
				tf := len(tOccs)
				tEntry := map[string]any{
					"term_freq": tf,
				}
				if termStats {
					tEntry["doc_freq"] = 1
					tEntry["ttf"] = tf
				}
				if includePositions || includeOffsets {
					tokensArr := make([]map[string]any, 0, len(tOccs))
					for _, o := range tOccs {
						tokObj := make(map[string]any, 3)
						if includePositions {
							tokObj["position"] = o.position
						}
						if includeOffsets {
							tokObj["start_offset"] = o.startOffset
							tokObj["end_offset"] = o.endOffset
						}
						tokensArr = append(tokensArr, tokObj)
					}
					tEntry["tokens"] = tokensArr
				}
				termsMap[t] = tEntry
			}
			fieldVec := map[string]any{
				"terms": termsMap,
			}
			if fieldStats {
				fieldVec["field_statistics"] = map[string]any{
					"doc_count":    1,
					"sum_doc_freq": len(uniqueTerms),
					"sum_ttf":      len(occs),
				}
			}
			termVectors[field] = fieldVec
		}
	}

	resp := map[string]any{
		"_index":       indexName,
		"_type":        "_doc",
		"_id":          docID,
		"_version":     ver,
		"found":        found,
		"took":         1,
		"term_vectors": termVectors,
	}
	return resp, http.StatusOK, "", ""
}

func (s *Server) handleTermVectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var bodyMap map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if bodyMap == nil {
		bodyMap = make(map[string]any)
	}
	q := r.URL.Query()
	var qFieldStats, qPositions, qOffsets *bool
	if q.Has("field_statistics") {
		v := isTruthyBoolQueryParam(r, "field_statistics")
		qFieldStats = &v
	}
	if q.Has("positions") {
		v := isTruthyBoolQueryParam(r, "positions")
		qPositions = &v
	}
	if q.Has("offsets") {
		v := isTruthyBoolQueryParam(r, "offsets")
		qOffsets = &v
	}
	resp, status, errType, errReason := s.computeSingleTermVectorResponse(
		r.Context(),
		strings.TrimSpace(r.PathValue("index")),
		strings.TrimSpace(r.PathValue("id")),
		bodyMap,
		q.Get("fields"),
		isTruthyBoolQueryParam(r, "term_statistics"),
		qFieldStats,
		qPositions,
		qOffsets,
	)
	if errType != "" {
		writeESError(w, status, errType, errReason)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMTermVectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var bodyMap map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if bodyMap == nil {
		bodyMap = make(map[string]any)
	}
	defaultIndex := strings.TrimSpace(r.PathValue("index"))
	q := r.URL.Query()
	var qFieldStats, qPositions, qOffsets *bool
	if q.Has("field_statistics") {
		v := isTruthyBoolQueryParam(r, "field_statistics")
		qFieldStats = &v
	}
	if q.Has("positions") {
		v := isTruthyBoolQueryParam(r, "positions")
		qPositions = &v
	}
	if q.Has("offsets") {
		v := isTruthyBoolQueryParam(r, "offsets")
		qOffsets = &v
	}

	defaultKeys := []string{"fields", "offsets", "positions", "payloads", "term_statistics", "field_statistics", "filter", "per_field_analyzer"}
	var docSpecs []map[string]any
	if rawDocs, okD := bodyMap["docs"].([]any); okD {
		for _, item := range rawDocs {
			if m, okM := item.(map[string]any); okM {
				mergedSpec := make(map[string]any, len(m)+len(defaultKeys))
				for _, dk := range defaultKeys {
					if dv, hasDV := bodyMap[dk]; hasDV {
						mergedSpec[dk] = dv
					}
				}
				for k, v := range m {
					mergedSpec[k] = v
				}
				docSpecs = append(docSpecs, mergedSpec)
			}
		}
	}
	if len(docSpecs) == 0 {
		var ids []string
		if rawIDs, okI := bodyMap["ids"].([]any); okI {
			for _, item := range rawIDs {
				ids = append(ids, fmt.Sprintf("%v", item))
			}
		} else if qIDs := q.Get("ids"); qIDs != "" {
			for _, id := range strings.Split(qIDs, ",") {
				if id = strings.TrimSpace(id); id != "" {
					ids = append(ids, id)
				}
			}
		}
		for _, id := range ids {
			spec := make(map[string]any, len(bodyMap)+2)
			for k, v := range bodyMap {
				if k != "ids" && k != "docs" {
					spec[k] = v
				}
			}
			if existingIdx, ok := spec["_index"].(string); !ok || existingIdx == "" {
				if altIdx, okA := spec["index"].(string); okA && altIdx != "" {
					spec["_index"] = altIdx
				} else {
					spec["_index"] = defaultIndex
				}
			}
			spec["_id"] = id
			docSpecs = append(docSpecs, spec)
		}
	}

	docsOut := make([]map[string]any, 0, len(docSpecs))
	for _, spec := range docSpecs {
		idx, _ := spec["_index"].(string)
		if idx == "" {
			if altIdx, okA := spec["index"].(string); okA && altIdx != "" {
				idx = altIdx
			} else {
				idx = defaultIndex
			}
		}
		id, _ := spec["_id"].(string)
		resp, status, errType, errReason := s.computeSingleTermVectorResponse(
			r.Context(),
			idx,
			id,
			spec,
			q.Get("fields"),
			isTruthyBoolQueryParam(r, "term_statistics"),
			qFieldStats,
			qPositions,
			qOffsets,
		)
		if errType != "" {
			docsOut = append(docsOut, map[string]any{
				"_index": idx,
				"_id":    id,
				"error": map[string]any{
					"type":   errType,
					"reason": errReason,
				},
				"status": status,
			})
			continue
		}
		docsOut = append(docsOut, resp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": docsOut})
}

type rankEvalHitRef struct {
	index string
	id    string
}

func extractRankEvalHitRefs(resp map[string]any, fallbackIndex string) []rankEvalHitRef {
	var out []rankEvalHitRef
	if resp == nil {
		return out
	}
	hitsMap, _ := resp["hits"].(map[string]any)
	if hitsMap == nil {
		return out
	}
	extractOne := func(hm map[string]any) {
		if hm == nil {
			return
		}
		id, _ := hm["_id"].(string)
		if id == "" {
			return
		}
		idx, _ := hm["_index"].(string)
		if idx == "" {
			idx = fallbackIndex
		}
		out = append(out, rankEvalHitRef{index: idx, id: id})
	}
	switch hl := hitsMap["hits"].(type) {
	case []map[string]any:
		for _, hm := range hl {
			extractOne(hm)
		}
	case []any:
		for _, item := range hl {
			if hm, ok := item.(map[string]any); ok {
				extractOne(hm)
			}
		}
	}
	return out
}

func (s *Server) handleRankEval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	targetIndex := strings.TrimSpace(r.PathValue("index"))
	if targetIndex != "" {
		if _, _, ok := s.resolveValidatedReadTargets(w, r, targetIndex); !ok {
			return
		}
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var payload struct {
		Requests []struct {
			ID         string         `json:"id"`
			Request    map[string]any `json:"request,omitempty"`
			TemplateID string         `json:"template_id,omitempty"`
			Params     map[string]any `json:"params,omitempty"`
			Ratings    []struct {
				Index  string  `json:"_index"`
				ID     string  `json:"_id"`
				Rating float64 `json:"rating"`
			} `json:"ratings"`
		} `json:"requests"`
		Metric    map[string]map[string]any `json:"metric"`
		Templates []struct {
			ID       string `json:"id"`
			Template any    `json:"template"`
		} `json:"templates,omitempty"`
	}
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", err.Error())
			return
		}
	}
	if len(payload.Requests) == 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: requests are required for _rank_eval;")
		return
	}

	inlineTemplates := make(map[string]any, len(payload.Templates))
	for _, t := range payload.Templates {
		if m, okM := t.Template.(map[string]any); okM {
			if src, hasSrc := m["source"]; hasSrc {
				inlineTemplates[t.ID] = src
				continue
			}
			if inl, hasInl := m["inline"]; hasInl {
				inlineTemplates[t.ID] = inl
				continue
			}
		}
		inlineTemplates[t.ID] = t.Template
	}

	metricName := "precision"
	var metricSpec map[string]any
	for k, v := range payload.Metric {
		metricName = strings.ToLower(strings.TrimSpace(k))
		metricSpec = v
		break
	}
	kVal := 10
	relevantThreshold := 1.0
	discountFactor := 1.0
	if metricSpec != nil {
		if kv, okK := toInt64(metricSpec["k"]); okK && kv > 0 {
			kVal = int(kv)
		}
		if rt, okRT := toFloat64(metricSpec["relevant_rating_threshold"]); okRT {
			relevantThreshold = rt
		}
		if df, okDF := toFloat64(metricSpec["discount_factor"]); okDF && df > 0 {
			discountFactor = df
		}
	}

	details := make(map[string]any, len(payload.Requests))
	failures := make(map[string]any)
	var sumScore float64
	validCount := 0

	for _, item := range payload.Requests {
		var searchBodyJSON []byte
		if item.TemplateID != "" {
			var tplSrc any
			if inl, okI := inlineTemplates[item.TemplateID]; okI {
				tplSrc = inl
			} else if stored, okS := s.lookupStoredScript(item.TemplateID); okS {
				tplSrc = stored["source"]
			}
			if tplSrc == nil {
				failures[item.ID] = map[string]any{"error": fmt.Sprintf("template [%s] not found", item.TemplateID)}
				continue
			}
			rendered, err := renderMustacheSearchTemplate(tplSrc, item.Params)
			if err != nil {
				failures[item.ID] = map[string]any{"error": err.Error()}
				continue
			}
			searchBodyJSON = rendered
		} else if item.Request != nil {
			b, err := json.Marshal(item.Request)
			if err != nil {
				failures[item.ID] = map[string]any{"error": err.Error()}
				continue
			}
			searchBodyJSON = b
		} else {
			searchBodyJSON = []byte(`{}`)
		}

		var sReq esast.SearchRequest
		searchBodyJSON = coerceSearchTemplateNumericFields(searchBodyJSON)
		if err := json.Unmarshal(searchBodyJSON, &sReq); err != nil {
			failures[item.ID] = map[string]any{"error": err.Error()}
			continue
		}
		if sReq.Size == nil || *sReq.Size < kVal {
			sz := kVal
			sReq.Size = &sz
		}
		resp, _, errType, errReason := s.executeSearchRequest(r.Context(), targetIndex, &sReq)
		if errType != "" {
			failures[item.ID] = map[string]any{"error": errReason}
			continue
		}
		hitRefs := extractRankEvalHitRefs(resp, targetIndex)
		if len(hitRefs) > kVal {
			hitRefs = hitRefs[:kVal]
		}

		ratingByID := make(map[string]float64, len(item.Ratings)*2)
		totalRelevantInRatings := 0
		for _, rt := range item.Ratings {
			ratingByID[rt.Index+"\x00"+rt.ID] = rt.Rating
			if _, exists := ratingByID["\x00"+rt.ID]; !exists || rt.Index == "" {
				ratingByID["\x00"+rt.ID] = rt.Rating
			}
			if rt.Rating >= relevantThreshold {
				totalRelevantInRatings++
			}
		}

		hitsReport := make([]map[string]any, 0, len(hitRefs))
		unratedDocs := make([]map[string]any, 0)
		relevantRetrieved := 0
		mrr := 0.0
		dcg := 0.0
		errMetric := 0.0
		pStop := 1.0
		maxRating := 3.0
		if metricSpec != nil {
			if mr, okMR := toFloat64(metricSpec["maximum_relevance"]); okMR && mr > 0 {
				maxRating = mr
			}
		}

		for rankIdx, hRef := range hitRefs {
			rating, rated := ratingByID[hRef.index+"\x00"+hRef.id]
			if !rated {
				rating, rated = ratingByID["\x00"+hRef.id]
			}
			var ratingOut any
			if rated {
				ratingOut = rating
			} else {
				unratedDocs = append(unratedDocs, map[string]any{
					"_index": hRef.index,
					"_id":    hRef.id,
				})
			}
			hitsReport = append(hitsReport, map[string]any{
				"hit": map[string]any{
					"_index": hRef.index,
					"_id":    hRef.id,
				},
				"rating": ratingOut,
			})
			isRel := rated && rating >= relevantThreshold
			if isRel {
				relevantRetrieved++
				if mrr == 0 {
					mrr = 1.0 / float64(rankIdx+1)
				}
			}
			if rated && rating > 0 {
				dcg += (math.Pow(2.0, rating) - 1.0) / (math.Log2(float64(rankIdx+2)) * discountFactor)
				rProb := (math.Pow(2.0, rating) - 1.0) / math.Pow(2.0, maxRating)
				errMetric += pStop * rProb / float64(rankIdx+1)
				pStop *= (1.0 - rProb)
			}
		}

		var qScore float64
		switch metricName {
		case "precision":
			denom := len(hitRefs)
			if denom == 0 {
				denom = kVal
			}
			if denom > 0 {
				qScore = float64(relevantRetrieved) / float64(denom)
			}
		case "recall":
			if totalRelevantInRatings > 0 {
				qScore = float64(relevantRetrieved) / float64(totalRelevantInRatings)
			}
		case "mean_reciprocal_rank", "mrr":
			qScore = mrr
		case "dcg":
			qScore = dcg
			if metricSpec != nil {
				if norm, okN := parseOptionalBoolAny(metricSpec["normalize"]); okN && norm {
					var idealRatings []float64
					for _, rt := range item.Ratings {
						if rt.Rating > 0 {
							idealRatings = append(idealRatings, rt.Rating)
						}
					}
					sort.Sort(sort.Reverse(sort.Float64Slice(idealRatings)))
					if len(idealRatings) > kVal {
						idealRatings = idealRatings[:kVal]
					}
					idcg := 0.0
					for idx, rVal := range idealRatings {
						idcg += (math.Pow(2.0, rVal) - 1.0) / (math.Log2(float64(idx+2)) * discountFactor)
					}
					if idcg > 0 {
						qScore = dcg / idcg
					} else {
						qScore = 0
					}
				}
			}
		case "expected_reciprocal_rank", "err":
			qScore = errMetric
		default:
			if len(hitRefs) > 0 {
				qScore = float64(relevantRetrieved) / float64(len(hitRefs))
			}
		}

		sumScore += qScore
		validCount++
		details[item.ID] = map[string]any{
			"metric_score": qScore,
			"unrated_docs": unratedDocs,
			"hits":         hitsReport,
			"metric_details": map[string]any{
				metricName: map[string]any{
					"relevant_docs_retrieved": relevantRetrieved,
					"docs_retrieved":          len(hitRefs),
					"unrated_docs":            len(unratedDocs),
				},
			},
		}
	}

	avgScore := 0.0
	if validCount > 0 {
		avgScore = sumScore / float64(validCount)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"metric_score": avgScore,
		"details":      details,
		"failures":     failures,
	})
}

func (s *Server) handleMVT(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	field := strings.TrimSpace(r.PathValue("field"))
	zoomStr := strings.TrimSpace(r.PathValue("zoom"))
	xStr := strings.TrimSpace(r.PathValue("x"))
	yStr := strings.TrimSpace(r.PathValue("y"))

	zoom, errZ := strconv.Atoi(zoomStr)
	x, errX := strconv.Atoi(xStr)
	y, errY := strconv.Atoi(yStr)
	if errZ != nil || errX != nil || errY != nil || zoom < 0 || zoom > 29 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("invalid vector tile coordinates [%s/%s/%s]", zoomStr, xStr, yStr))
		return
	}
	maxCoord := 1 << zoom
	if x < 0 || x >= maxCoord || y < 0 || y >= maxCoord {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("tile coordinates [%d/%d/%d] out of range [0..%d]", zoom, x, y, maxCoord-1))
		return
	}
	if field == "" {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", "field is required for _mvt")
		return
	}
	if _, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/vnd.mapbox-vector-tile")
	w.WriteHeader(http.StatusOK)
}

// ============================================================================
// F6: Remaining `_cat/*`, `_tasks`, `_cluster/*`, `_nodes/*`, and Index Operations
// ============================================================================

func (s *Server) handleCatAllocation(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	s.mu.RLock()
	numShards := len(s.indices)
	s.mu.RUnlock()
	list := []map[string]any{
		{
			"shards":       fmt.Sprintf("%d", numShards),
			"disk.indices": "0b",
			"disk.used":    "1gb",
			"disk.avail":   "99gb",
			"disk.total":   "100gb",
			"disk.percent": "1",
			"host":         "127.0.0.1",
			"ip":           "127.0.0.1",
			"node":         "doris-fe-1",
		},
	}
	writeCatResponse(w, r, []string{"shards", "disk.indices", "disk.used", "disk.avail", "disk.total", "disk.percent", "host", "ip", "node"}, list)
}

func (s *Server) handleCatFielddata(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{}
	writeCatResponse(w, r, []string{"id", "host", "ip", "node", "field", "size"}, list)
}

func (s *Server) handleCatMaster(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{
		{
			"id":   "doris-node-1",
			"host": "127.0.0.1",
			"ip":   "127.0.0.1",
			"node": "doris-fe-1",
		},
	}
	writeCatResponse(w, r, []string{"id", "host", "ip", "node"}, list)
}

func (s *Server) handleCatNodeattrs(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{
		{
			"node":  "doris-fe-1",
			"host":  "127.0.0.1",
			"ip":    "127.0.0.1",
			"attr":  "ml.machine_memory",
			"value": "8589934592",
		},
	}
	writeCatResponse(w, r, []string{"node", "host", "ip", "attr", "value"}, list)
}

func (s *Server) handleCatPendingTasks(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{}
	writeCatResponse(w, r, []string{"insertOrder", "timeInQueue", "priority", "source"}, list)
}

func (s *Server) handleCatPlugins(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{}
	writeCatResponse(w, r, []string{"name", "component", "version", "description"}, list)
}

func (s *Server) handleCatRecovery(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	list := make([]map[string]any, 0, len(targets))
	for _, idx := range targets {
		list = append(list, map[string]any{
			"index":                  idx,
			"shard":                  "0",
			"time":                   "1ms",
			"type":                   "existing_store",
			"stage":                  "done",
			"source_host":            "n/a",
			"source_node":            "n/a",
			"target_host":            "127.0.0.1",
			"target_node":            "doris-fe-1",
			"repository":             "n/a",
			"snapshot":               "n/a",
			"files":                  "0",
			"files_recovered":        "0",
			"files_percent":          "100.0%",
			"files_total":            "0",
			"bytes":                  "0",
			"bytes_recovered":        "0",
			"bytes_percent":          "100.0%",
			"bytes_total":            "0",
			"translog_ops":           "0",
			"translog_ops_recovered": "0",
			"translog_ops_percent":   "100.0%",
		})
	}
	writeCatResponse(w, r, []string{"index", "shard", "time", "type", "stage", "source_host", "source_node", "target_host", "target_node", "repository", "snapshot", "files", "files_recovered", "files_percent", "files_total", "bytes", "bytes_recovered", "bytes_percent", "bytes_total", "translog_ops", "translog_ops_recovered", "translog_ops_percent"}, list)
}

func (s *Server) handleCatRepositories(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	repoNames := make([]string, 0, len(s.snapshotRepos))
	for k := range s.snapshotRepos {
		repoNames = append(repoNames, k)
	}
	sort.Strings(repoNames)
	list := make([]map[string]any, 0, len(repoNames))
	for _, name := range repoNames {
		repoObj := s.snapshotRepos[name]
		repoType, _ := repoObj["type"].(string)
		if repoType == "" {
			repoType = "fs"
		}
		list = append(list, map[string]any{
			"id":   name,
			"type": repoType,
		})
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"id", "type"}, list)
}

func (s *Server) handleCatSegments(w http.ResponseWriter, r *http.Request) {
	targets := s.resolveTargetIndices(r.PathValue("index"))
	list := make([]map[string]any, 0, len(targets))
	for _, idx := range targets {
		list = append(list, map[string]any{
			"index":        idx,
			"shard":        "0",
			"prirep":       "p",
			"ip":           "127.0.0.1",
			"segment":      "_0",
			"generation":   "0",
			"docs.count":   "0",
			"docs.deleted": "0",
			"size":         "1kb",
			"size.memory":  "0",
			"committed":    "true",
			"searchable":   "true",
			"version":      "9.9.0",
			"compound":     "true",
		})
	}
	writeCatResponse(w, r, []string{"index", "shard", "prirep", "ip", "segment", "generation", "docs.count", "docs.deleted", "size", "size.memory", "committed", "searchable", "version", "compound"}, list)
}

func (s *Server) handleCatTasks(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{
		{
			"action":         "cluster:monitor/tasks/lists",
			"task_id":        "doris-node-1:1",
			"parent_task_id": "-",
			"type":           "transport",
			"start_time":     "1700000000000",
			"timestamp":      "00:00:00",
			"running_time":   "1ms",
			"ip":             "127.0.0.1",
			"node":           "doris-fe-1",
		},
	}
	writeCatResponse(w, r, []string{"action", "task_id", "parent_task_id", "type", "start_time", "timestamp", "running_time", "ip", "node"}, list)
}

func (s *Server) handleCatThreadPool(w http.ResponseWriter, r *http.Request) {
	names := []string{"search", "write", "get", "management"}
	if pat := strings.TrimSpace(r.PathValue("name")); pat != "" {
		var filtered []string
		for _, n := range names {
			if matchMultiWildcardWithExclusions(pat, n) {
				filtered = append(filtered, n)
			}
		}
		names = filtered
	}
	list := make([]map[string]any, 0, len(names))
	for _, n := range names {
		list = append(list, map[string]any{
			"node_name": "doris-fe-1",
			"name":      n,
			"active":    "0",
			"queue":     "0",
			"rejected":  "0",
			"completed": "1",
		})
	}
	writeCatResponse(w, r, []string{"node_name", "name", "active", "queue", "rejected", "completed"}, list)
}

func (s *Server) handleCatTemplates(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	pat := strings.TrimSpace(r.PathValue("name"))
	s.mu.RLock()
	names := make([]string, 0, len(s.templates))
	for k := range s.templates {
		if pat == "" || matchMultiWildcardWithExclusions(pat, k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	list := make([]map[string]any, 0, len(names))
	for _, k := range names {
		tpl := s.templates[k]
		patterns := "[" + strings.Join(tpl.EffectivePatterns(), ", ") + "]"
		list = append(list, map[string]any{
			"name":           k,
			"index_patterns": patterns,
			"order":          fmt.Sprintf("%d", tpl.EffectivePriority()),
			"version":        "",
			"composed_of":    "[" + strings.Join(tpl.ComposedOf, ", ") + "]",
		})
	}
	s.mu.RUnlock()
	writeCatResponse(w, r, []string{"name", "index_patterns", "order", "version", "composed_of"}, list)
}

func (s *Server) handleTasksList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": map[string]any{
			"doris-node-1": map[string]any{
				"name":              "doris-fe-1",
				"transport_address": "127.0.0.1:9030",
				"host":              "127.0.0.1",
				"ip":                "127.0.0.1:9030",
				"roles":             []string{"master", "data", "ingest"},
				"tasks": map[string]any{
					"doris-node-1:1": map[string]any{
						"node":                  "doris-node-1",
						"id":                    1,
						"type":                  "transport",
						"action":                "cluster:monitor/tasks/lists",
						"start_time_in_millis":  1700000000000,
						"running_time_in_nanos": 1000,
						"cancellable":           false,
					},
				},
			},
		},
	})
}

func (s *Server) handleTasksGet(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimSpace(r.PathValue("task_id"))
	nodeID := "doris-node-1"
	var numID int64 = 1
	if idx := strings.IndexByte(taskID, ':'); idx > 0 {
		nodeID = taskID[:idx]
		if parsed, err := strconv.ParseInt(taskID[idx+1:], 10, 64); err == nil {
			numID = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"completed": true,
		"task": map[string]any{
			"node":                  nodeID,
			"id":                    numID,
			"type":                  "transport",
			"action":                "indices:data/write/reindex",
			"start_time_in_millis":  1700000000000,
			"running_time_in_nanos": 1000,
			"cancellable":           true,
		},
		"response": map[string]any{
			"took":      1,
			"timed_out": false,
			"total":     0,
			"updated":   0,
			"created":   0,
			"deleted":   0,
		},
	})
}

func (s *Server) handleTasksCancel(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": map[string]any{},
	})
}

func (s *Server) handleClusterAllocationExplain(w http.ResponseWriter, r *http.Request) {
	_ = s.syncCatalogFromBackend(r.Context())
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var body map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		_ = json.Unmarshal(bodyBytes, &body)
	}
	idxName, _ := body["index"].(string)
	if idxName == "" {
		s.mu.RLock()
		for k := range s.indices {
			idxName = k
			break
		}
		s.mu.RUnlock()
		if idxName == "" {
			idxName = "default"
		}
	}
	shard := 0
	if sv, okS := toInt64(body["shard"]); okS {
		shard = int(sv)
	}
	primary := true
	if pv, okP := parseOptionalBoolAny(body["primary"]); okP {
		primary = pv
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"index":         idxName,
		"shard":         shard,
		"primary":       primary,
		"current_state": "started",
		"current_node": map[string]any{
			"id":                "doris-node-1",
			"name":              "doris-fe-1",
			"transport_address": "127.0.0.1:9030",
			"attributes":        map[string]any{},
		},
	})
}

func (s *Server) handleClusterPendingTasks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tasks": []any{},
	})
}

func (s *Server) handleClusterReroute(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged": true,
		"state":        map[string]any{},
	})
}

func (s *Server) handleNodesHotThreads(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("::: {doris-fe-1}{doris-node-1}{127.0.0.1}{127.0.0.1:9030}\n   Hot threads at 2026-01-01T00:00:00Z:\n"))
}

func (s *Server) handleNodesUsage(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
		"cluster_name": "doris-es-cluster",
		"nodes": map[string]any{
			"doris-node-1": map[string]any{
				"timestamp":    1700000000000,
				"since":        1700000000000,
				"rest_actions": map[string]any{},
				"aggregations": map[string]any{},
			},
		},
	})
}

func (s *Server) handleIndexRecovery(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	var targets []string
	if rawIndex == "" {
		targets = s.resolveTargetIndices("")
	} else {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	}
	resp := make(map[string]any, len(targets))
	for _, idx := range targets {
		resp[idx] = map[string]any{
			"shards": []map[string]any{
				{
					"id":                   0,
					"type":                 "EXISTING_STORE",
					"stage":                "DONE",
					"primary":              true,
					"start_time_in_millis": 1700000000000,
					"stop_time_in_millis":  1700000000001,
					"total_time_in_millis": 1,
					"source":               map[string]any{},
					"target": map[string]any{
						"id":   "doris-node-1",
						"host": "127.0.0.1",
						"ip":   "127.0.0.1",
						"name": "doris-fe-1",
					},
					"index": map[string]any{
						"size":  map[string]any{"total_in_bytes": 0, "reused_in_bytes": 0, "recovered_in_bytes": 0, "percent": "100.0%"},
						"files": map[string]any{"total": 0, "reused": 0, "recovered": 0, "percent": "100.0%"},
					},
					"translog": map[string]any{
						"recovered":            0,
						"total":                0,
						"percent":              "100.0%",
						"total_on_start":       0,
						"total_time_in_millis": 0,
					},
				},
			},
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleIndexSegments(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	var targets []string
	if rawIndex == "" {
		targets = s.resolveTargetIndices("")
	} else {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	}
	indicesMap := make(map[string]any, len(targets))
	for _, idx := range targets {
		indicesMap[idx] = map[string]any{
			"shards": map[string]any{
				"0": []map[string]any{
					{
						"routing": map[string]any{
							"state":   "STARTED",
							"primary": true,
							"node":    "doris-node-1",
						},
						"num_committed_segments": 1,
						"num_search_segments":    1,
						"segments": map[string]any{
							"_0": map[string]any{
								"generation":      0,
								"num_docs":        0,
								"deleted_docs":    0,
								"size_in_bytes":   1024,
								"memory_in_bytes": 0,
								"committed":       true,
								"search":          true,
								"version":         "9.9.0",
								"compound":        true,
								"attributes":      map[string]any{},
							},
						},
					},
				},
			},
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{"total": len(targets), "successful": len(targets), "failed": 0},
		"indices": indicesMap,
	})
}

func (s *Server) handleIndexShardStores(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex != "" {
		if _, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex); !ok {
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"indices": map[string]any{},
	})
}

func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	if rawIndex != "" {
		if _, _, ok := s.resolveValidatedReadTargets(w, r, rawIndex); !ok {
			return
		}
	}
	s.queryCache.InvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{
		"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
	})
}

func (s *Server) handleIndexOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	var targets []string
	if rawIndex != "" {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	}
	s.mu.Lock()
	for _, idx := range targets {
		delete(s.closedIndices, idx)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
	})
}

func (s *Server) handleIndexClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method")
		return
	}
	rawIndex := strings.TrimSpace(r.PathValue("index"))
	var targets []string
	if rawIndex != "" {
		var ok bool
		targets, _, ok = s.resolveValidatedReadTargets(w, r, rawIndex)
		if !ok {
			return
		}
	}
	s.mu.Lock()
	if s.closedIndices == nil {
		s.closedIndices = make(map[string]bool)
	}
	for _, idx := range targets {
		s.closedIndices[idx] = true
	}
	s.mu.Unlock()
	indicesOut := make(map[string]any, len(targets))
	for _, idx := range targets {
		indicesOut[idx] = map[string]any{"closed": true}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":        true,
		"shards_acknowledged": true,
		"indices":             indicesOut,
	})
}

// ============================================================================
// F7: `matched_queries` in Search Hits
// ============================================================================

func querySliceHasNamedClauses(qs []esast.Query) bool {
	for i := range qs {
		if queryHasNamedClauses(&qs[i]) {
			return true
		}
	}
	return false
}

func knnSliceHasNamedClauses(knns []esast.KNNQuery) bool {
	for i := range knns {
		if knns[i].Name != "" {
			return true
		}
		if querySliceHasNamedClauses(knns[i].Filter) {
			return true
		}
	}
	return false
}

func queryHasNamedClauses(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if extractDirectQueryClauseName(q) != "" {
		return true
	}
	if q.ConstantScore != nil && queryHasNamedClauses(&q.ConstantScore.Filter) {
		return true
	}
	if q.Bool != nil {
		if querySliceHasNamedClauses(q.Bool.Must) ||
			querySliceHasNamedClauses(q.Bool.Should) ||
			querySliceHasNamedClauses(q.Bool.Filter) ||
			querySliceHasNamedClauses(q.Bool.MustNot) {
			return true
		}
	}
	if q.Boosting != nil && (queryHasNamedClauses(&q.Boosting.Positive) || queryHasNamedClauses(&q.Boosting.Negative)) {
		return true
	}
	if q.DisMax != nil && querySliceHasNamedClauses(q.DisMax.Queries) {
		return true
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil && queryHasNamedClauses(q.FunctionScore.Query) {
			return true
		}
		for i := range q.FunctionScore.Functions {
			if q.FunctionScore.Functions[i].Filter != nil && queryHasNamedClauses(q.FunctionScore.Functions[i].Filter) {
				return true
			}
		}
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil && queryHasNamedClauses(q.ScriptScore.Query) {
		return true
	}
	if q.Nested != nil && queryHasNamedClauses(&q.Nested.Query) {
		return true
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && queryHasNamedClauses(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && q.Pinned.Organic != nil && queryHasNamedClauses(q.Pinned.Organic) {
		return true
	}
	if q.KNN != nil && querySliceHasNamedClauses(q.KNN.Filter) {
		return true
	}
	if q.SpanNear != nil && querySliceHasNamedClauses(q.SpanNear.Clauses) {
		return true
	}
	if q.SpanOr != nil && querySliceHasNamedClauses(q.SpanOr.Clauses) {
		return true
	}
	if q.SpanNot != nil && (queryHasNamedClauses(q.SpanNot.Include) || queryHasNamedClauses(q.SpanNot.Exclude)) {
		return true
	}
	if q.SpanFirst != nil && queryHasNamedClauses(q.SpanFirst.Match) {
		return true
	}
	if q.SpanMulti != nil && queryHasNamedClauses(q.SpanMulti.Match) {
		return true
	}
	if q.SpanContaining != nil && (queryHasNamedClauses(q.SpanContaining.Little) || queryHasNamedClauses(q.SpanContaining.Big)) {
		return true
	}
	if q.SpanWithin != nil && (queryHasNamedClauses(q.SpanWithin.Little) || queryHasNamedClauses(q.SpanWithin.Big)) {
		return true
	}
	if q.FieldMaskingSpan != nil && queryHasNamedClauses(q.FieldMaskingSpan.Query) {
		return true
	}
	return false
}

func extractDirectQueryClauseName(q *esast.Query) string {
	if q == nil {
		return ""
	}
	if q.Name != "" {
		return q.Name
	}
	if q.ConstantScore != nil && q.ConstantScore.Name != "" {
		return q.ConstantScore.Name
	}
	if q.DisMax != nil && q.DisMax.Name != "" {
		return q.DisMax.Name
	}
	if q.HasChild != nil && q.HasChild.Name != "" {
		return q.HasChild.Name
	}
	if q.HasParent != nil && q.HasParent.Name != "" {
		return q.HasParent.Name
	}
	if q.ParentID != nil && q.ParentID.Name != "" {
		return q.ParentID.Name
	}
	if q.Percolate != nil && q.Percolate.Name != "" {
		return q.Percolate.Name
	}
	if q.MoreLikeThis != nil && q.MoreLikeThis.Name != "" {
		return q.MoreLikeThis.Name
	}
	if q.KNN != nil && q.KNN.Name != "" {
		return q.KNN.Name
	}
	if q.Wrapper != nil && q.Wrapper.Name != "" {
		return q.Wrapper.Name
	}
	return ""
}

func collectMatchedQueryNamesForSearch(idxSchema *schema.IndexSchema, docMap map[string]any, q, postFilter *esast.Query, knns []esast.KNNQuery) []string {
	seen := make(map[string]bool)
	var out []string
	addNames := func(names []string) {
		for _, n := range names {
			if n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	if q != nil {
		addNames(collectMatchedQueryNames(idxSchema, docMap, q))
	}
	if postFilter != nil {
		addNames(collectMatchedQueryNames(idxSchema, docMap, postFilter))
	}
	for i := range knns {
		kq := esast.Query{KNN: &knns[i]}
		if evalBranchMatchesDoc(idxSchema, docMap, &kq) {
			if knns[i].Name != "" {
				addNames([]string{knns[i].Name})
			}
			for j := range knns[i].Filter {
				addNames(collectMatchedQueryNames(idxSchema, docMap, &knns[i].Filter[j]))
			}
		}
	}
	sort.Strings(out)
	return out
}

func collectMatchedQueryNames(idxSchema *schema.IndexSchema, docMap map[string]any, q *esast.Query) []string {
	seen := make(map[string]bool)
	var out []string
	var walk func(curSchema *schema.IndexSchema, curDoc map[string]any, cur *esast.Query)
	walk = func(curSchema *schema.IndexSchema, curDoc map[string]any, cur *esast.Query) {
		if cur == nil {
			return
		}
		if !evalBranchMatchesDoc(curSchema, curDoc, cur) {
			return
		}
		if name := extractDirectQueryClauseName(cur); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		if cur.Bool != nil {
			for i := range cur.Bool.Must {
				walk(curSchema, curDoc, &cur.Bool.Must[i])
			}
			for i := range cur.Bool.Should {
				walk(curSchema, curDoc, &cur.Bool.Should[i])
			}
			for i := range cur.Bool.Filter {
				walk(curSchema, curDoc, &cur.Bool.Filter[i])
			}
		}
		if cur.ConstantScore != nil {
			walk(curSchema, curDoc, &cur.ConstantScore.Filter)
		}
		if cur.Boosting != nil {
			walk(curSchema, curDoc, &cur.Boosting.Positive)
		}
		if cur.DisMax != nil {
			for i := range cur.DisMax.Queries {
				walk(curSchema, curDoc, &cur.DisMax.Queries[i])
			}
		}
		if cur.FunctionScore != nil {
			if cur.FunctionScore.Query != nil {
				walk(curSchema, curDoc, cur.FunctionScore.Query)
			}
			for i := range cur.FunctionScore.Functions {
				if cur.FunctionScore.Functions[i].Filter != nil {
					walk(curSchema, curDoc, cur.FunctionScore.Functions[i].Filter)
				}
			}
		}
		if cur.ScriptScore != nil && cur.ScriptScore.Query != nil {
			walk(curSchema, curDoc, cur.ScriptScore.Query)
		}
		if cur.Nested != nil {
			pathSegs := strings.Split(cur.Nested.Path, ".")
			nestedSchema := deriveNestedEvalSchema(curSchema, cur.Nested.Path)
			for _, cand := range extractNestedElementsAtPath(curDoc, pathSegs) {
				elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
				walk(nestedSchema, elemDoc, &cur.Nested.Query)
			}
		}
		if cur.Wrapper != nil && cur.Wrapper.Decoded != nil {
			walk(curSchema, curDoc, cur.Wrapper.Decoded)
		}
		if cur.Pinned != nil && cur.Pinned.Organic != nil {
			walk(curSchema, curDoc, cur.Pinned.Organic)
		}
		if cur.KNN != nil {
			for i := range cur.KNN.Filter {
				walk(curSchema, curDoc, &cur.KNN.Filter[i])
			}
		}
		if cur.SpanNear != nil {
			for i := range cur.SpanNear.Clauses {
				walk(curSchema, curDoc, &cur.SpanNear.Clauses[i])
			}
		}
		if cur.SpanOr != nil {
			for i := range cur.SpanOr.Clauses {
				walk(curSchema, curDoc, &cur.SpanOr.Clauses[i])
			}
		}
		if cur.SpanNot != nil {
			walk(curSchema, curDoc, cur.SpanNot.Include)
		}
		if cur.SpanFirst != nil {
			walk(curSchema, curDoc, cur.SpanFirst.Match)
		}
		if cur.SpanMulti != nil {
			walk(curSchema, curDoc, cur.SpanMulti.Match)
		}
		if cur.SpanContaining != nil {
			walk(curSchema, curDoc, cur.SpanContaining.Little)
			walk(curSchema, curDoc, cur.SpanContaining.Big)
		}
		if cur.SpanWithin != nil {
			walk(curSchema, curDoc, cur.SpanWithin.Little)
			walk(curSchema, curDoc, cur.SpanWithin.Big)
		}
		if cur.FieldMaskingSpan != nil {
			walk(curSchema, curDoc, cur.FieldMaskingSpan.Query)
		}
	}
	walk(idxSchema, docMap, q)
	sort.Strings(out)
	return out
}

func collectIdsQueriesWithInnerHits(q *esast.Query, out *[]*esast.IdsQuery) {
	if q == nil || out == nil {
		return
	}
	if q.Ids != nil && len(q.Ids.ResolvedInnerHits) > 0 {
		*out = append(*out, q.Ids)
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectIdsQueriesWithInnerHits(&q.Bool.Must[i], out)
		}
		for i := range q.Bool.Should {
			collectIdsQueriesWithInnerHits(&q.Bool.Should[i], out)
		}
		for i := range q.Bool.Filter {
			collectIdsQueriesWithInnerHits(&q.Bool.Filter[i], out)
		}
	}
	if q.ConstantScore != nil {
		collectIdsQueriesWithInnerHits(&q.ConstantScore.Filter, out)
	}
	if q.Boosting != nil {
		collectIdsQueriesWithInnerHits(&q.Boosting.Positive, out)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectIdsQueriesWithInnerHits(&q.DisMax.Queries[i], out)
		}
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectIdsQueriesWithInnerHits(q.FunctionScore.Query, out)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectIdsQueriesWithInnerHits(q.ScriptScore.Query, out)
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		collectIdsQueriesWithInnerHits(q.Wrapper.Decoded, out)
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		collectIdsQueriesWithInnerHits(q.Pinned.Organic, out)
	}
}

// ============================================================================
// F8-F11: Query Pre-Resolution & Runtime Evaluation (`MoreLikeThis`, `HasChild`, `HasParent`, `ParentID`, `Percolate`)
// ============================================================================

var (
	activeStoredScriptsServerMu sync.RWMutex
	activeStoredScriptsServer   *Server
)

func hasSpecialLookupInSearchRequest(req *esast.SearchRequest) bool {
	if req == nil {
		return false
	}
	if hasSpecialLookupInQuery(req.Query) || hasSpecialLookupInQuery(req.PostFilter) {
		return true
	}
	return false
}

func hasSpecialLookupInQuery(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.HasChild != nil || q.HasParent != nil || q.ParentID != nil || q.Percolate != nil || q.MoreLikeThis != nil {
		return true
	}
	if q.Nested != nil && hasSpecialLookupInQuery(&q.Nested.Query) {
		return true
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && hasSpecialLookupInQuery(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && q.Pinned.Organic != nil && hasSpecialLookupInQuery(q.Pinned.Organic) {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if hasSpecialLookupInQuery(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if hasSpecialLookupInQuery(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if hasSpecialLookupInQuery(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if hasSpecialLookupInQuery(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && hasSpecialLookupInQuery(&q.ConstantScore.Filter) {
		return true
	}
	if q.Boosting != nil && (hasSpecialLookupInQuery(&q.Boosting.Positive) || hasSpecialLookupInQuery(&q.Boosting.Negative)) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if hasSpecialLookupInQuery(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil && hasSpecialLookupInQuery(q.FunctionScore.Query) {
		return true
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil && hasSpecialLookupInQuery(q.ScriptScore.Query) {
		return true
	}
	return false
}

func (s *Server) preResolveSpecialQueriesInSearchRequest(ctx context.Context, targets []string, req *esast.SearchRequest) error {
	if s != nil {
		activeStoredScriptsServerMu.Lock()
		activeStoredScriptsServer = s
		activeStoredScriptsServerMu.Unlock()
	}
	if s == nil || req == nil || !hasSpecialLookupInSearchRequest(req) {
		return nil
	}
	if req.Query != nil {
		resolved, err := s.preResolveSpecialQueriesInQuery(ctx, targets, req.Query)
		if err != nil {
			return err
		}
		req.Query = resolved
	}
	if req.PostFilter != nil {
		resolved, err := s.preResolveSpecialQueriesInQuery(ctx, targets, req.PostFilter)
		if err != nil {
			return err
		}
		req.PostFilter = resolved
	}
	return nil
}

func (s *Server) validateJoinFieldForTargets(ctx context.Context, targets []string, relType string, isParentRel bool) (joinField string, hasJoin bool, hasRel bool, hasMappedFields bool) {
	relType = strings.TrimSpace(relType)
	for _, t := range targets {
		sch := s.getOrCompileReadOnlySchema(ctx, t)
		if sch == nil || len(sch.Fields) == 0 {
			continue
		}
		hasMappedFields = true
		for fname, fb := range sch.Fields {
			if fb.ESType != "join" {
				continue
			}
			hasJoin = true
			if joinField == "" {
				joinField = fname
			}
			if relType == "" || len(fb.Relations) == 0 {
				hasRel = true
				continue
			}
			if isParentRel {
				if _, ok := fb.Relations[relType]; ok {
					hasRel = true
				}
			} else {
				for _, childSpec := range fb.Relations {
					switch cs := childSpec.(type) {
					case string:
						if cs == relType {
							hasRel = true
						}
					case []any:
						for _, item := range cs {
							if fmt.Sprintf("%v", item) == relType {
								hasRel = true
							}
						}
					case []string:
						for _, item := range cs {
							if item == relType {
								hasRel = true
							}
						}
					}
				}
			}
		}
	}
	return joinField, hasJoin, hasRel, hasMappedFields
}

func buildJoinInnerHitsEnvelope(hits []HitRow, spec *esast.InnerHitsSpec, idxSchema *schema.IndexSchema) map[string]any {
	from := 0
	size := 3
	if spec != nil {
		if spec.From >= 0 {
			from = spec.From
		}
		if spec.Size != nil && *spec.Size >= 0 {
			size = *spec.Size
		}
	}
	total := len(hits)
	var paged []HitRow
	if from < total {
		end := from + size
		if end > total {
			end = total
		}
		paged = hits[from:end]
	}
	var maxScoreVal any
	hitObjs := make([]map[string]any, 0, len(paged))
	for _, h := range paged {
		rawSrc := h.Source
		if spec != nil && spec.Source != nil {
			rawSrc = filterSourceJSON(h.Source, spec.Source)
		}
		var filteredSrc any
		if len(rawSrc) > 0 && string(rawSrc) != "null" {
			var srcMap map[string]any
			_ = json.Unmarshal(rawSrc, &srcMap)
			filteredSrc = srcMap
		}
		scoreVal := h.Score
		if maxScoreVal == nil || scoreVal > maxScoreVal.(float64) {
			maxScoreVal = scoreVal
		}
		idxName := ""
		if idxSchema != nil {
			idxName = idxSchema.IndexName
		}
		hitObj := map[string]any{
			"_index":  idxName,
			"_id":     h.ID,
			"_score":  scoreVal,
			"_source": filteredSrc,
		}
		if spec != nil && (len(spec.Fields) > 0 || len(spec.DocvalueFields) > 0) {
			if fMap := extractHitFieldsMap(h, idxName, &esast.SearchRequest{Fields: spec.EffectiveFieldSpecs()}, idxSchema); len(fMap) > 0 {
				hitObj["fields"] = fMap
			}
		}
		hitObjs = append(hitObjs, hitObj)
	}
	return map[string]any{
		"hits": map[string]any{
			"total": map[string]any{
				"value":    total,
				"relation": "eq",
			},
			"max_score": maxScoreVal,
			"hits":      hitObjs,
		},
	}
}

func hitMapToHitRow(hm map[string]any) HitRow {
	idStr, _ := hm["_id"].(string)
	srcMap := extractSourceMapFromHitMap(hm)
	rawBytes, _ := json.Marshal(srcMap)
	scVal := 1.0
	if sc, ok := toFloat(hm["_score"]); ok {
		scVal = sc
	}
	return HitRow{
		ID:     idStr,
		Score:  scVal,
		Source: rawBytes,
	}
}

func (s *Server) preResolveSpecialQueriesInQuery(ctx context.Context, targets []string, q *esast.Query) (*esast.Query, error) {
	if q == nil {
		return nil, nil
	}
	cp := *q
	defaultIdx := ""
	if len(targets) > 0 {
		defaultIdx = targets[0]
	}

	if cp.Wrapper != nil && cp.Wrapper.Decoded != nil {
		dec, err := s.preResolveSpecialQueriesInQuery(ctx, targets, cp.Wrapper.Decoded)
		if err != nil {
			return nil, err
		}
		wCopy := *cp.Wrapper
		wCopy.Decoded = dec
		cp.Wrapper = &wCopy
	}
	if cp.Pinned != nil && cp.Pinned.Organic != nil {
		org, err := s.preResolveSpecialQueriesInQuery(ctx, targets, cp.Pinned.Organic)
		if err != nil {
			return nil, err
		}
		pCopy := *cp.Pinned
		pCopy.Organic = org
		cp.Pinned = &pCopy
	}

	// F9: MoreLikeThis document lookup by _id
	if cp.MoreLikeThis != nil {
		mlt := *cp.MoreLikeThis
		resolveItems := func(raw any) any {
			items := normalizeMLTItems(raw)
			if len(items) == 0 {
				return raw
			}
			out := make([]any, 0, len(items))
			for _, item := range items {
				m, ok := item.(map[string]any)
				if !ok {
					out = append(out, item)
					continue
				}
				if _, hasDoc := m["doc"]; hasDoc {
					out = append(out, m)
					continue
				}
				if _, hasSrc := m["_source"]; hasSrc {
					out = append(out, m)
					continue
				}
				id, _ := m["_id"].(string)
				if id == "" {
					out = append(out, m)
					continue
				}
				idx, _ := m["_index"].(string)
				if idx == "" {
					idx = defaultIdx
				}
				cloned := make(map[string]any, len(m)+1)
				for k, v := range m {
					cloned[k] = v
				}
				if idx != "" && s.backend != nil {
					resolvedIdx, _, _ := s.resolveReadDocIndexWithFilter(idx)
					if resolvedIdx == "" {
						resolvedIdx = idx
					}
					roSchema := s.getOrCompileReadOnlySchema(ctx, resolvedIdx)
					_ = s.coalescer.FlushTable(ctx, roSchema.DorisTable)
					if existing, found, err := s.backend.GetDocByID(ctx, roSchema.DorisDB, roSchema.DorisTable, id); err == nil && found && existing != nil {
						var docMap map[string]any
						if json.Unmarshal(existing.Source, &docMap) == nil && docMap != nil {
							cloned["doc"] = docMap
						}
					}
				}
				if _, hasResolvedDoc := cloned["doc"]; !hasResolvedDoc {
					cloned["doc"] = map[string]any{}
				}
				out = append(out, cloned)
			}
			return out
		}
		mlt.Like = resolveItems(mlt.Like)
		mlt.Unlike = resolveItems(mlt.Unlike)
		cp.MoreLikeThis = &mlt
	}

	// F7 / F11: Percolate validation + lookup by document `_id` (`index` + `id`)
	if cp.Percolate != nil {
		perc := *cp.Percolate
		field := strings.TrimSpace(perc.Field)
		if field == "" {
			field = "query"
		}
		hasMappedFields := false
		foundPercolator := false
		hasDynamicSubfields := false
		var wrongType string
		for _, t := range targets {
			sch := s.getOrCompileReadOnlySchema(ctx, t)
			if sch == nil || len(sch.Fields) == 0 {
				continue
			}
			hasMappedFields = true
			fb := sch.ResolveEffectiveField(field, false)
			if fb.ESType == "percolator" {
				foundPercolator = true
			} else if fb.ESType != "" {
				wrongType = fb.ESType
			}
			prefix := field + "."
			for fname := range sch.Fields {
				if strings.HasPrefix(fname, prefix) {
					hasDynamicSubfields = true
					break
				}
			}
		}
		if hasMappedFields && !foundPercolator {
			if wrongType != "" {
				return nil, fmt.Errorf("field [%s] is not of type [percolator]", field)
			}
			if !hasDynamicSubfields {
				if perc.IgnoreUnmapped {
					cp.Percolate = nil
					cp.Ids = &esast.IdsQuery{
						Values: []string{"__no_match_unmapped__"},
						Name:   perc.Name,
					}
					return &cp, nil
				}
				return nil, fmt.Errorf("field [%s] does not exist or is not of type [percolator]", field)
			}
		}
		if perc.ID != "" && perc.Document == nil && len(perc.Documents) == 0 {
			idx := perc.Index
			if idx == "" {
				idx = defaultIdx
			}
			if idx != "" && s.backend != nil {
				resolvedIdx, _, _ := s.resolveReadDocIndexWithFilter(idx)
				if resolvedIdx == "" {
					resolvedIdx = idx
				}
				roSchema := s.getOrCompileReadOnlySchema(ctx, resolvedIdx)
				_ = s.coalescer.FlushTable(ctx, roSchema.DorisTable)
				if existing, found, err := s.backend.GetDocByID(ctx, roSchema.DorisDB, roSchema.DorisTable, perc.ID); err == nil && found && existing != nil {
					var docMap map[string]any
					dec := json.NewDecoder(bytes.NewReader(existing.Source))
					dec.UseNumber()
					if dec.Decode(&docMap) == nil && docMap != nil {
						perc.Document = docMap
					}
				}
			}
			if perc.Document == nil {
				perc.Document = map[string]any{}
			}
		}
		cp.Percolate = &perc
	}

	// F5: ParentID validation for unmapped join field/relation
	if cp.ParentID != nil {
		pid := cp.ParentID
		_, hasJoin, hasRel, hasMappedFields := s.validateJoinFieldForTargets(ctx, targets, pid.Type, false)
		if hasMappedFields && (!hasJoin || !hasRel) {
			if pid.IgnoreUnmapped {
				cp.ParentID = nil
				cp.Ids = &esast.IdsQuery{
					Values: []string{"__no_match_unmapped__"},
					Name:   pid.Name,
				}
				return &cp, nil
			}
			return nil, fmt.Errorf("[parent_id] no join field has been configured or unknown child relation [%s]", pid.Type)
		}
	}

	// F5 / F10: HasChild pre-resolution -> rewrite into `_id` IdsQuery of matching parent IDs
	if cp.HasChild != nil {
		hc := cp.HasChild
		childType := strings.TrimSpace(hc.Type)
		joinField, hasJoin, hasRel, hasMappedFields := s.validateJoinFieldForTargets(ctx, targets, childType, false)
		if hasMappedFields && (!hasJoin || !hasRel) {
			if hc.IgnoreUnmapped {
				cp.HasChild = nil
				cp.Ids = &esast.IdsQuery{
					Values: []string{"__no_match_unmapped__"},
					Name:   hc.Name,
				}
				return &cp, nil
			}
			return nil, fmt.Errorf("[has_child] no join field has been configured or unknown child relation [%s]", childType)
		}

		minChildren := 1
		if hc.MinChildren != nil && *hc.MinChildren > 0 {
			minChildren = *hc.MinChildren
		}
		maxChildren := 0
		if hc.MaxChildren != nil && *hc.MaxChildren > 0 {
			maxChildren = *hc.MaxChildren
		}
		if maxChildren > 0 && minChildren > maxChildren {
			cp.HasChild = nil
			cp.Ids = &esast.IdsQuery{
				Values: []string{"__no_match_unmapped__"},
				Name:   hc.Name,
			}
			return &cp, nil
		}

		scoreMode := strings.ToLower(strings.TrimSpace(hc.ScoreMode))
		if scoreMode == "" {
			scoreMode = "none"
		}
		sz := 10000
		resolvedInner, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &hc.Query)
		if err != nil {
			return nil, err
		}
		innerQ := resolvedInner
		parentCounts := make(map[string]int)
		parentChildScores := make(map[string][]float64)
		parentChildHits := make(map[string][]HitRow)
		var firstTargetSchema *schema.IndexSchema

		for _, t := range targets {
			sch := s.getOrCompileReadOnlySchema(ctx, t)
			if sch == nil || s.backend == nil {
				continue
			}
			if firstTargetSchema == nil {
				firstTargetSchema = sch
			}
			_ = s.coalescer.FlushTable(ctx, sch.DorisTable)
			trackScoresTrue := true
			resp, _, errType, _ := s.executeSearchRequest(ctx, t, &esast.SearchRequest{
				Size:        &sz,
				Query:       innerQ,
				TrackScores: &trackScoresTrue,
			})
			if errType != "" {
				continue
			}
			hitsWrapper, _ := resp["hits"].(map[string]any)
			if hitsWrapper == nil {
				continue
			}
			var hitMaps []map[string]any
			switch hl := hitsWrapper["hits"].(type) {
			case []map[string]any:
				hitMaps = hl
			case []any:
				for _, item := range hl {
					if m, okM := item.(map[string]any); okM {
						hitMaps = append(hitMaps, m)
					}
				}
			}
			for _, hm := range hitMaps {
				srcMap := extractSourceMapFromHitMap(hm)
				if srcMap == nil {
					continue
				}
				relName, parentID := extractJoinRelationAndParent(srcMap, joinField)
				if parentID != "" && (childType == "" || relName == childType) {
					parentCounts[parentID]++
					childScore := 1.0
					if sc, okSc := toFloat(hm["_score"]); okSc {
						childScore = sc
					}
					parentChildScores[parentID] = append(parentChildScores[parentID], childScore)
					if hc.InnerHits != nil {
						parentChildHits[parentID] = append(parentChildHits[parentID], hitMapToHitRow(hm))
					}
				}
			}
		}

		boost := 1.0
		if hc.Boost != nil {
			boost = *hc.Boost
		}
		var matchedParentIDs []string
		var resolvedScores map[string]float64
		var resolvedInnerHits map[string]any
		for pid, cnt := range parentCounts {
			if cnt < minChildren {
				continue
			}
			if maxChildren > 0 && cnt > maxChildren {
				continue
			}
			matchedParentIDs = append(matchedParentIDs, pid)
			if scoreMode != "none" {
				scores := parentChildScores[pid]
				if len(scores) > 0 {
					var agg float64
					switch scoreMode {
					case "max":
						agg = scores[0]
						for _, sVal := range scores[1:] {
							if sVal > agg {
								agg = sVal
							}
						}
					case "min":
						agg = scores[0]
						for _, sVal := range scores[1:] {
							if sVal < agg {
								agg = sVal
							}
						}
					case "sum":
						for _, sVal := range scores {
							agg += sVal
						}
					case "avg":
						for _, sVal := range scores {
							agg += sVal
						}
						agg /= float64(len(scores))
					default:
						agg = 1.0
					}
					if resolvedScores == nil {
						resolvedScores = make(map[string]float64)
					}
					resolvedScores[pid] = agg * boost
				}
			}
			if hc.InnerHits != nil {
				if resolvedInnerHits == nil {
					resolvedInnerHits = make(map[string]any)
				}
				resolvedInnerHits[pid] = buildJoinInnerHitsEnvelope(parentChildHits[pid], hc.InnerHits, firstTargetSchema)
			}
		}
		sort.Strings(matchedParentIDs)
		cp.HasChild = nil
		cp.Ids = &esast.IdsQuery{
			Values:            matchedParentIDs,
			Boost:             hc.Boost,
			Name:              hc.Name,
			ResolvedScores:    resolvedScores,
			ResolvedInnerHits: resolvedInnerHits,
			InnerHitsSpec:     hc.InnerHits,
			JoinQueryType:     "has_child",
			JoinRelType:       childType,
			JoinScoreMode:     scoreMode,
		}
		return &cp, nil
	}

	// F5 / F10: HasParent pre-resolution -> find matching parent `_id`s, then match child docs whose join parent is in that set
	if cp.HasParent != nil {
		hp := cp.HasParent
		parentType := strings.TrimSpace(hp.ParentType)
		joinField, hasJoin, hasRel, hasMappedFields := s.validateJoinFieldForTargets(ctx, targets, parentType, true)
		if hasMappedFields && (!hasJoin || !hasRel) {
			if hp.IgnoreUnmapped {
				cp.HasParent = nil
				cp.Ids = &esast.IdsQuery{
					Values: []string{"__no_match_unmapped__"},
					Name:   hp.Name,
				}
				return &cp, nil
			}
			return nil, fmt.Errorf("[has_parent] no join field has been configured or unknown parent relation [%s]", parentType)
		}

		sz := 10000
		resolvedInner, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &hp.Query)
		if err != nil {
			return nil, err
		}
		innerQ := resolvedInner
		matchedParentSet := make(map[string]bool)
		parentScores := make(map[string]float64)
		parentHitRows := make(map[string]HitRow)
		var firstTargetSchema *schema.IndexSchema

		for _, t := range targets {
			sch := s.getOrCompileReadOnlySchema(ctx, t)
			if sch == nil || s.backend == nil {
				continue
			}
			if firstTargetSchema == nil {
				firstTargetSchema = sch
			}
			_ = s.coalescer.FlushTable(ctx, sch.DorisTable)
			trackScoresTrue := true
			resp, _, errType, _ := s.executeSearchRequest(ctx, t, &esast.SearchRequest{
				Size:        &sz,
				Query:       innerQ,
				TrackScores: &trackScoresTrue,
			})
			if errType != "" {
				continue
			}
			hitsWrapper, _ := resp["hits"].(map[string]any)
			if hitsWrapper == nil {
				continue
			}
			var hitMaps []map[string]any
			switch hl := hitsWrapper["hits"].(type) {
			case []map[string]any:
				hitMaps = hl
			case []any:
				for _, item := range hl {
					if m, okM := item.(map[string]any); okM {
						hitMaps = append(hitMaps, m)
					}
				}
			}
			for _, hm := range hitMaps {
				idStr, _ := hm["_id"].(string)
				srcMap := extractSourceMapFromHitMap(hm)
				if idStr == "" || srcMap == nil {
					continue
				}
				relName, _ := extractJoinRelationAndParent(srcMap, joinField)
				if parentType == "" || relName == parentType || relName == "" {
					matchedParentSet[idStr] = true
					pScore := 1.0
					if sc, okSc := toFloat(hm["_score"]); okSc {
						pScore = sc
					}
					parentScores[idStr] = pScore
					if hp.InnerHits != nil {
						parentHitRows[idStr] = hitMapToHitRow(hm)
					}
				}
			}
		}

		boost := 1.0
		if hp.Boost != nil {
			boost = *hp.Boost
		}
		scoreEnabled := hp.Score != nil && *hp.Score
		var matchedChildIDs []string
		var resolvedScores map[string]float64
		var resolvedInnerHits map[string]any

		if len(matchedParentSet) > 0 {
			for _, t := range targets {
				sch := s.getOrCompileReadOnlySchema(ctx, t)
				if sch == nil || s.backend == nil {
					continue
				}
				resp, _, errType, _ := s.executeSearchRequest(ctx, t, &esast.SearchRequest{
					Size: &sz,
				})
				if errType != "" {
					continue
				}
				hitsWrapper, _ := resp["hits"].(map[string]any)
				if hitsWrapper == nil {
					continue
				}
				var hitMaps []map[string]any
				switch hl := hitsWrapper["hits"].(type) {
				case []map[string]any:
					hitMaps = hl
				case []any:
					for _, item := range hl {
						if m, okM := item.(map[string]any); okM {
							hitMaps = append(hitMaps, m)
						}
					}
				}
				for _, hm := range hitMaps {
					idStr, _ := hm["_id"].(string)
					srcMap := extractSourceMapFromHitMap(hm)
					if idStr == "" || srcMap == nil {
						continue
					}
					_, parentID := extractJoinRelationAndParent(srcMap, joinField)
					if parentID != "" && matchedParentSet[parentID] {
						matchedChildIDs = append(matchedChildIDs, idStr)
						if scoreEnabled {
							if resolvedScores == nil {
								resolvedScores = make(map[string]float64)
							}
							resolvedScores[idStr] = parentScores[parentID] * boost
						}
						if hp.InnerHits != nil {
							if resolvedInnerHits == nil {
								resolvedInnerHits = make(map[string]any)
							}
							resolvedInnerHits[idStr] = buildJoinInnerHitsEnvelope([]HitRow{parentHitRows[parentID]}, hp.InnerHits, firstTargetSchema)
						}
					}
				}
			}
		}
		sort.Strings(matchedChildIDs)
		cp.HasParent = nil
		cp.Ids = &esast.IdsQuery{
			Values:            matchedChildIDs,
			Boost:             hp.Boost,
			Name:              hp.Name,
			ResolvedScores:    resolvedScores,
			ResolvedInnerHits: resolvedInnerHits,
			InnerHitsSpec:     hp.InnerHits,
			JoinQueryType:     "has_parent",
			JoinRelType:       parentType,
		}
		return &cp, nil
	}

	if cp.Nested != nil {
		nCopy := *cp.Nested
		r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &nCopy.Query)
		if err != nil {
			return nil, err
		}
		nCopy.Query = *r
		cp.Nested = &nCopy
	}
	if cp.Bool != nil {
		bCopy := *cp.Bool
		if len(bCopy.Must) > 0 {
			bCopy.Must = append([]esast.Query(nil), bCopy.Must...)
			for i := range bCopy.Must {
				r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &bCopy.Must[i])
				if err != nil {
					return nil, err
				}
				bCopy.Must[i] = *r
			}
		}
		if len(bCopy.Should) > 0 {
			bCopy.Should = append([]esast.Query(nil), bCopy.Should...)
			for i := range bCopy.Should {
				r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &bCopy.Should[i])
				if err != nil {
					return nil, err
				}
				bCopy.Should[i] = *r
			}
		}
		if len(bCopy.Filter) > 0 {
			bCopy.Filter = append([]esast.Query(nil), bCopy.Filter...)
			for i := range bCopy.Filter {
				r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &bCopy.Filter[i])
				if err != nil {
					return nil, err
				}
				bCopy.Filter[i] = *r
			}
		}
		if len(bCopy.MustNot) > 0 {
			bCopy.MustNot = append([]esast.Query(nil), bCopy.MustNot...)
			for i := range bCopy.MustNot {
				r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &bCopy.MustNot[i])
				if err != nil {
					return nil, err
				}
				bCopy.MustNot[i] = *r
			}
		}
		cp.Bool = &bCopy
	}
	if cp.ConstantScore != nil {
		csCopy := *cp.ConstantScore
		r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &csCopy.Filter)
		if err != nil {
			return nil, err
		}
		csCopy.Filter = *r
		cp.ConstantScore = &csCopy
	}
	if cp.Boosting != nil {
		bstCopy := *cp.Boosting
		pos, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &bstCopy.Positive)
		if err != nil {
			return nil, err
		}
		neg, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &bstCopy.Negative)
		if err != nil {
			return nil, err
		}
		bstCopy.Positive = *pos
		bstCopy.Negative = *neg
		cp.Boosting = &bstCopy
	}
	if cp.DisMax != nil {
		dmCopy := *cp.DisMax
		dmCopy.Queries = append([]esast.Query(nil), dmCopy.Queries...)
		for i := range dmCopy.Queries {
			r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, &dmCopy.Queries[i])
			if err != nil {
				return nil, err
			}
			dmCopy.Queries[i] = *r
		}
		cp.DisMax = &dmCopy
	}
	if cp.FunctionScore != nil && cp.FunctionScore.Query != nil {
		fsCopy := *cp.FunctionScore
		r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, fsCopy.Query)
		if err != nil {
			return nil, err
		}
		fsCopy.Query = r
		cp.FunctionScore = &fsCopy
	}
	if cp.ScriptScore != nil && cp.ScriptScore.Query != nil {
		ssCopy := *cp.ScriptScore
		r, err := s.preResolveSpecialQueriesInQuery(ctx, targets, ssCopy.Query)
		if err != nil {
			return nil, err
		}
		ssCopy.Query = r
		cp.ScriptScore = &ssCopy
	}
	return &cp, nil
}

func extractJoinRelationAndParent(docMap map[string]any, joinField string) (relName string, parentID string) {
	if docMap == nil {
		return "", ""
	}
	checkVal := func(v any) (string, string, bool) {
		switch tv := v.(type) {
		case string:
			return tv, "", true
		case map[string]any:
			n, _ := tv["name"].(string)
			p := ""
			if pv, okP := tv["parent"]; okP && pv != nil {
				p = fmt.Sprintf("%v", pv)
			}
			if n != "" || p != "" {
				return n, p, true
			}
		}
		return "", "", false
	}
	if joinField != "" {
		if val, ok := getIngestPath(docMap, joinField); ok {
			if n, p, okC := checkVal(val); okC {
				return n, p
			}
		}
	}
	// Fallback: inspect top-level fields for a join object {"name": ..., "parent": ...}
	for _, v := range docMap {
		if m, ok := v.(map[string]any); ok {
			if _, hasName := m["name"]; hasName {
				if n, p, okC := checkVal(m); okC {
					return n, p
				}
			}
		}
	}
	return "", ""
}

func extractSourceMapFromHitMap(hm map[string]any) map[string]any {
	if hm == nil {
		return nil
	}
	switch src := hm["_source"].(type) {
	case map[string]any:
		return src
	case json.RawMessage:
		var m map[string]any
		if json.Unmarshal(src, &m) == nil {
			return m
		}
	case []byte:
		var m map[string]any
		if json.Unmarshal(src, &m) == nil {
			return m
		}
	}
	return nil
}

func findJoinFieldInSchema(sch *schema.IndexSchema) string {
	if sch == nil {
		return ""
	}
	for fname, fb := range sch.Fields {
		if fb.ESType == "join" {
			return fname
		}
	}
	return ""
}

func evalParentIDOnDoc(idxSchema *schema.IndexSchema, docMap map[string]any, pid *esast.ParentIDQuery) bool {
	if pid == nil || docMap == nil {
		return false
	}
	targetParent := strings.TrimSpace(fmt.Sprintf("%v", pid.ID))
	childType := strings.TrimSpace(pid.Type)
	joinField := findJoinFieldInSchema(idxSchema)
	if idxSchema != nil && len(idxSchema.Fields) > 0 && joinField == "" {
		return false
	}
	relName, parentID := extractJoinRelationAndParent(docMap, joinField)
	if parentID == "" || parentID != targetParent {
		return false
	}
	if childType != "" && relName != "" && relName != childType {
		return false
	}
	return true
}

func normalizeMLTItems(raw any) []any {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		return v
	case string:
		return []any{v}
	case map[string]any:
		return []any{v}
	default:
		return []any{v}
	}
}

func evalMoreLikeThisOnDoc(_ *schema.IndexSchema, docMap map[string]any, mlt *esast.MoreLikeThisQuery) (bool, float64) {
	if mlt == nil || docMap == nil {
		return false, 0
	}
	fields := mlt.Fields
	if len(fields) == 0 {
		collectAllStringFieldPathsFromDoc("", docMap, &fields)
	}
	stopSet := make(map[string]bool, len(mlt.StopWords))
	for _, sw := range mlt.StopWords {
		stopSet[strings.ToLower(strings.TrimSpace(sw))] = true
	}
	minWordLen := mlt.MinWordLength
	maxWordLen := mlt.MaxWordLength
	minTermFreq := mlt.MinTermFreq
	if minTermFreq <= 0 {
		minTermFreq = 1
	}

	var excludedIDs map[string]bool
	extractTokens := func(items []any) []string {
		freq := make(map[string]int)
		var order []string
		for _, item := range items {
			switch v := item.(type) {
			case string:
				for _, occ := range tokenizeTermVectorString(v) {
					t := occ.term
					if stopSet[t] || (minWordLen > 0 && len(t) < minWordLen) || (maxWordLen > 0 && len(t) > maxWordLen) {
						continue
					}
					if freq[t] == 0 {
						order = append(order, t)
					}
					freq[t]++
				}
			case map[string]any:
				if idStr, okID := v["_id"].(string); okID && idStr != "" {
					if _, hasDoc := v["doc"]; !hasDoc {
						if excludedIDs == nil {
							excludedIDs = make(map[string]bool)
						}
						excludedIDs[idStr] = true
					} else if len(v) <= 3 {
						if excludedIDs == nil {
							excludedIDs = make(map[string]bool)
						}
						excludedIDs[idStr] = true
					}
				}
				srcObj, okD := v["doc"].(map[string]any)
				if !okD {
					srcObj, _ = v["_source"].(map[string]any)
				}
				if srcObj != nil {
					for _, f := range fields {
						if fv, okF := getIngestPath(srcObj, f); okF {
							for _, s := range extractStringsFromFieldVal(fv) {
								for _, occ := range tokenizeTermVectorString(s) {
									t := occ.term
									if stopSet[t] || (minWordLen > 0 && len(t) < minWordLen) || (maxWordLen > 0 && len(t) > maxWordLen) {
										continue
									}
									if freq[t] == 0 {
										order = append(order, t)
									}
									freq[t]++
								}
							}
						}
					}
				}
			}
		}
		var out []string
		for _, t := range order {
			if freq[t] >= minTermFreq {
				out = append(out, t)
			}
		}
		return out
	}

	likeTokens := extractTokens(normalizeMLTItems(mlt.Like))
	if len(likeTokens) == 0 {
		return false, 0
	}
	unlikeSet := make(map[string]bool)
	for _, ut := range extractTokens(normalizeMLTItems(mlt.Unlike)) {
		unlikeSet[ut] = true
	}
	var filteredLike []string
	for _, lt := range likeTokens {
		if !unlikeSet[lt] {
			filteredLike = append(filteredLike, lt)
		}
	}
	if len(filteredLike) == 0 {
		return false, 0
	}
	if excludedIDs != nil {
		if docID, ok := docMap["__meta_id"].(string); ok && excludedIDs[docID] {
			return false, 0
		}
		if docID, ok := docMap["_id"].(string); ok && excludedIDs[docID] {
			return false, 0
		}
	}

	docTerms := make(map[string]bool)
	for _, f := range fields {
		if fv, okF := getIngestPath(docMap, f); okF {
			for _, s := range extractStringsFromFieldVal(fv) {
				for _, occ := range tokenizeTermVectorString(s) {
					docTerms[occ.term] = true
				}
			}
		}
	}
	matchedCount := 0
	for _, lt := range filteredLike {
		if docTerms[lt] {
			matchedCount++
		}
	}
	reqMatches := 1
	if mlt.MinimumShouldMatch != nil {
		msm := strings.TrimSpace(fmt.Sprintf("%v", mlt.MinimumShouldMatch))
		if strings.HasSuffix(msm, "%") {
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(msm, "%"), 64); err == nil {
				reqMatches = int(math.Ceil(float64(len(filteredLike)) * pct / 100.0))
			}
		} else if n, err := strconv.Atoi(msm); err == nil && n > 0 {
			reqMatches = n
		}
	}
	if reqMatches < 1 {
		reqMatches = 1
	}
	if matchedCount < reqMatches {
		return false, 0
	}
	boost := 1.0
	if mlt.Boost != nil {
		boost = *mlt.Boost
	}
	return true, float64(matchedCount) * boost
}

func evalPercolateQueryOnDoc(idxSchema *schema.IndexSchema, docMap map[string]any, perc *esast.PercolateQuery) (bool, float64, []int) {
	if perc == nil || docMap == nil {
		return false, 0, nil
	}
	field := strings.TrimSpace(perc.Field)
	if field == "" {
		field = "query"
	}
	rawQueryObj, exists := getIngestPath(docMap, field)
	if !exists || rawQueryObj == nil {
		return false, 0, nil
	}
	var storedQuery esast.Query
	switch v := rawQueryObj.(type) {
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return false, 0, nil
		}
		if err := json.Unmarshal(b, &storedQuery); err != nil {
			return false, 0, nil
		}
	case string:
		if err := json.Unmarshal([]byte(v), &storedQuery); err != nil {
			return false, 0, nil
		}
	default:
		return false, 0, nil
	}

	activeStoredScriptsServerMu.RLock()
	srv := activeStoredScriptsServer
	activeStoredScriptsServerMu.RUnlock()
	if srv != nil {
		srv.resolveStoredScriptsInQuery(&storedQuery)
	}

	var docsToTest []map[string]any
	if len(perc.Documents) > 0 {
		docsToTest = perc.Documents
	} else if perc.Document != nil {
		docsToTest = []map[string]any{perc.Document}
	}
	if len(docsToTest) == 0 {
		return false, 0, nil
	}

	var matchedSlots []int
	var maxScore float64
	for slotIdx, candidateDoc := range docsToTest {
		if evalBranchMatchesDoc(idxSchema, candidateDoc, &storedQuery) {
			matchedSlots = append(matchedSlots, slotIdx)
			sc := scoreNonScriptClauseOnDoc(idxSchema, candidateDoc, &storedQuery)
			if queryHasRuntimeScript(&storedQuery) || queryHasNestedScoring(&storedQuery) || storedQuery.FunctionScore != nil {
				sc = evalQueryScriptScoreOnDocWithSchema(idxSchema, candidateDoc, &storedQuery, sc)
			}
			if sc > maxScore {
				maxScore = sc
			}
		}
	}
	if len(matchedSlots) == 0 {
		return false, 0, nil
	}
	boost := 1.0
	if perc.Boost != nil {
		boost = *perc.Boost
	}
	if maxScore == 0 {
		maxScore = 1.0
	}
	return true, maxScore * boost, matchedSlots
}

func queryHasPercolateMultiDocs(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Percolate != nil && len(q.Percolate.Documents) > 0 {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryHasPercolateMultiDocs(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryHasPercolateMultiDocs(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryHasPercolateMultiDocs(&q.Bool.Filter[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryHasPercolateMultiDocs(&q.ConstantScore.Filter) {
		return true
	}
	if q.Boosting != nil && queryHasPercolateMultiDocs(&q.Boosting.Positive) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryHasPercolateMultiDocs(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil && queryHasPercolateMultiDocs(q.FunctionScore.Query) {
		return true
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil && queryHasPercolateMultiDocs(q.ScriptScore.Query) {
		return true
	}
	if q.Pinned != nil && q.Pinned.Organic != nil && queryHasPercolateMultiDocs(q.Pinned.Organic) {
		return true
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && queryHasPercolateMultiDocs(q.Wrapper.Decoded) {
		return true
	}
	return false
}

func collectPercolateMatchedSlots(idxSchema *schema.IndexSchema, docMap map[string]any, q *esast.Query) []int {
	seen := make(map[int]bool)
	var out []int
	var walk func(cur *esast.Query)
	walk = func(cur *esast.Query) {
		if cur == nil {
			return
		}
		if cur.Percolate != nil && len(cur.Percolate.Documents) > 0 {
			ok, _, slots := evalPercolateQueryOnDoc(idxSchema, docMap, cur.Percolate)
			if ok {
				for _, sl := range slots {
					if !seen[sl] {
						seen[sl] = true
						out = append(out, sl)
					}
				}
			}
		}
		if cur.Bool != nil {
			for i := range cur.Bool.Must {
				walk(&cur.Bool.Must[i])
			}
			for i := range cur.Bool.Should {
				walk(&cur.Bool.Should[i])
			}
			for i := range cur.Bool.Filter {
				walk(&cur.Bool.Filter[i])
			}
		}
		if cur.ConstantScore != nil {
			walk(&cur.ConstantScore.Filter)
		}
		if cur.Boosting != nil {
			walk(&cur.Boosting.Positive)
		}
		if cur.DisMax != nil {
			for i := range cur.DisMax.Queries {
				walk(&cur.DisMax.Queries[i])
			}
		}
		if cur.FunctionScore != nil && cur.FunctionScore.Query != nil {
			walk(cur.FunctionScore.Query)
		}
		if cur.ScriptScore != nil && cur.ScriptScore.Query != nil {
			walk(cur.ScriptScore.Query)
		}
		if cur.Pinned != nil && cur.Pinned.Organic != nil {
			walk(cur.Pinned.Organic)
		}
		if cur.Wrapper != nil && cur.Wrapper.Decoded != nil {
			walk(cur.Wrapper.Decoded)
		}
	}
	walk(q)
	sort.Ints(out)
	return out
}
