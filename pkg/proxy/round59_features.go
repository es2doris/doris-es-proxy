package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// Round 59 F2: Single-Document CRUD Missing-Index 404, op_type/OCC & _update fields
// ============================================================================

func (s *Server) indexExistsInCatalogLocked(indexName string) bool {
	if indexName == "" {
		return false
	}
	if _, ok := s.indices[indexName]; ok {
		return true
	}
	if _, ok := s.dataStreams[indexName]; ok {
		return true
	}
	if strings.HasPrefix(indexName, ".ds-") {
		for _, ds := range s.dataStreams {
			for _, bi := range extractDataStreamBackingIndexNames(ds) {
				if bi == indexName {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) indexExistsRound59(ctx context.Context, indexName string) bool {
	if indexName == "" {
		return false
	}
	s.mu.RLock()
	exists := s.indexExistsInCatalogLocked(indexName)
	s.mu.RUnlock()
	if exists {
		return true
	}
	_ = s.syncCatalogFromBackend(ctx)
	s.mu.RLock()
	exists = s.indexExistsInCatalogLocked(indexName)
	s.mu.RUnlock()
	return exists
}

// ensureConcreteIndexExists verifies that resolvedIndex exists in the proxy catalog
// (syncing from _es_catalog on cache miss) before touching Doris SELECT or Stream Load.
func (s *Server) ensureConcreteIndexExists(w http.ResponseWriter, r *http.Request, rawIndex, resolvedIndex string) bool {
	if s.indexExistsRound59(r.Context(), resolvedIndex) {
		return true
	}
	disp := strings.TrimSpace(rawIndex)
	if disp == "" {
		disp = resolvedIndex
	}
	if r != nil && r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusNotFound)
		return false
	}
	writeESError(w, http.StatusNotFound, "index_not_found_exception", "no such index ["+disp+"]")
	return false
}

// validatePutDocRound59 validates op_type and auto-ID OCC/version constraints on handlePutDoc.
func validatePutDocRound59(w http.ResponseWriter, r *http.Request, docID string) (isCreate bool, isExplicitIndexOp bool, ok bool) {
	isCreateEndpoint := r != nil && strings.Contains(r.URL.Path, "/_create/")
	var rawOpType string
	if r != nil && r.URL != nil && r.URL.Query().Has("op_type") {
		rawOpType = strings.TrimSpace(r.URL.Query().Get("op_type"))
		switch strings.ToLower(rawOpType) {
		case "", "index":
			if isCreateEndpoint && strings.EqualFold(rawOpType, "index") {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					"op_type [index] is not supported on the [_create] endpoint")
				return false, false, false
			}
		case "create":
			// valid
		default:
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("op_type must be 'create' or 'index', found: [%s]", rawOpType))
			return false, false, false
		}
	}
	if docID == "" && r != nil && r.URL != nil {
		q := r.URL.Query()
		if strings.TrimSpace(q.Get("if_seq_no")) != "" || strings.TrimSpace(q.Get("if_primary_term")) != "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: cannot specify if_seq_no or if_primary_term for auto-generated document ID;")
			return false, false, false
		}
		if strings.TrimSpace(q.Get("version")) != "" {
			writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: version is not supported for auto-generated document ID;")
			return false, false, false
		}
	}
	isExplicitIndexOp = strings.EqualFold(rawOpType, "index")
	isCreate = isCreateEndpoint || strings.EqualFold(rawOpType, "create")
	return isCreate, isExplicitIndexOp, true
}

func parseStrictESBoolValueRound59(raw any) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func parseStrictQueryBoolParamRound59(r *http.Request, key string) (val bool, present bool, err error) {
	if r == nil || r.URL == nil || !r.URL.Query().Has(key) {
		return false, false, nil
	}
	raw := r.URL.Query().Get(key)
	switch raw {
	case "", "true":
		return true, true, nil
	case "false":
		return false, true, nil
	default:
		return false, true, fmt.Errorf("failed to parse value [%s] as only [true] or [false] are allowed", raw)
	}
}

// validateAndParseUpdateDocRound59 validates boolean body/query flags on _update and parses requested fields.
func validateAndParseUpdateDocRound59(w http.ResponseWriter, r *http.Request, bodyBytes []byte, updReq *painless.UpdateRequest) ([]esast.FieldRequestSpec, bool) {
	var rawBodyMap map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&rawBodyMap); err != nil {
			writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
			return nil, false
		}
		for _, bKey := range []string{"doc_as_upsert", "detect_noop", "scripted_upsert"} {
			if rawVal, exists := rawBodyMap[bKey]; exists && rawVal != nil {
				bVal, ok := parseStrictESBoolValueRound59(rawVal)
				if !ok {
					writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("Failed to parse value [%v] for [%s] as only [true] or [false] are allowed.", rawVal, bKey))
					return nil, false
				}
				// Normalize string booleans into JSON booleans before struct unmarshal if needed.
				rawBodyMap[bKey] = bVal
			}
		}
		normBytes, mErr := json.Marshal(rawBodyMap)
		if mErr == nil {
			bodyBytes = normBytes
		}
	}
	if err := json.Unmarshal(bodyBytes, updReq); err != nil {
		writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
		return nil, false
	}

	if b, present, err := parseStrictQueryBoolParamRound59(r, "doc_as_upsert"); present {
		if err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return nil, false
		}
		updReq.DocAsUpsert = b
	}
	if b, present, err := parseStrictQueryBoolParamRound59(r, "detect_noop"); present {
		if err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return nil, false
		}
		updReq.DetectNoop = &b
	}
	if b, present, err := parseStrictQueryBoolParamRound59(r, "scripted_upsert"); present {
		if err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return nil, false
		}
		updReq.ScriptedUpsert = b
	}

	var fieldSpecs []esast.FieldRequestSpec
	if rawBodyMap != nil {
		if rawFields, hasF := rawBodyMap["fields"]; hasF && rawFields != nil {
			switch fv := rawFields.(type) {
			case string:
				for _, p := range strings.Split(fv, ",") {
					if p = strings.TrimSpace(p); p != "" {
						fieldSpecs = append(fieldSpecs, esast.FieldRequestSpec{Field: p})
					}
				}
			case []any:
				rawArr, err := json.Marshal(fv)
				if err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return nil, false
				}
				var parsed []esast.FieldRequestSpec
				if err := json.Unmarshal(rawArr, &parsed); err != nil {
					writeESError(w, http.StatusBadRequest, "parse_exception", err.Error())
					return nil, false
				}
				fieldSpecs = append(fieldSpecs, parsed...)
			default:
				writeESError(w, http.StatusBadRequest, "parse_exception", "[fields] must be an array of field names or objects")
				return nil, false
			}
		}
	}
	if r != nil && r.URL != nil && len(r.URL.Query()["fields"]) > 0 {
		for _, qf := range esast.StoredFieldsSlice(strings.Join(r.URL.Query()["fields"], ",")) {
			if strings.TrimSpace(qf) != "" {
				fieldSpecs = append(fieldSpecs, esast.FieldRequestSpec{Field: strings.TrimSpace(qf)})
			}
		}
	}
	return fieldSpecs, true
}

func (s *Server) buildUpdateGetResultRound59(
	ctx context.Context,
	indexName, docID, effRouting string,
	ver int64,
	src json.RawMessage,
	foundDoc bool,
	sf *esast.SourceFilter,
	fieldSpecs []esast.FieldRequestSpec,
) map[string]any {
	wantSource := sf != nil && !sf.Disabled
	wantFields := len(fieldSpecs) > 0
	if !wantSource && !wantFields {
		return nil
	}
	if !foundDoc || len(src) == 0 {
		return map[string]any{"found": false}
	}
	getObj := map[string]any{
		"found": true,
	}
	idxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
	if wantSource {
		if filtered, ok := filterDocumentSourceRound59(src, idxSchema, sf); ok {
			getObj["_source"] = filtered
		}
	}
	if wantFields {
		hit := HitRow{
			ID:      docID,
			Version: ver,
			Routing: effRouting,
			Source:  src,
		}
		if fm := extractHitFieldsMap(hit, indexName, &esast.SearchRequest{Fields: fieldSpecs}, idxSchema); len(fm) > 0 {
			getObj["fields"] = fm
		}
	}
	return getObj
}

// ============================================================================
// Round 59 F3: Multi-Percolate API (GET/POST /_mpercolate & /{index}/_mpercolate)
// ============================================================================

func buildInlineESErrorItemRound59(status int, errType, reason string) map[string]any {
	return map[string]any{
		"error": map[string]any{
			"root_cause": []map[string]any{
				{
					"type":   errType,
					"reason": reason,
				},
			},
			"type":   errType,
			"reason": reason,
		},
		"status": status,
	}
}

// handleMPercolate implements GET/POST /_mpercolate and GET/POST /{index}/_mpercolate.
func (s *Server) handleMPercolate(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	start := time.Now()
	rawBody, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	rawLines := strings.Split(string(rawBody), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, ln := range rawLines {
		trimmed := strings.TrimSpace(ln)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) == 0 {
		writeESError(w, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: no requests added;")
		return
	}
	if len(lines)%2 != 0 {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			"Validation Failed: mpercolate requires an even number of non-empty NDJSON header/body lines")
		return
	}

	defaultIndex := strings.TrimSpace(r.PathValue("index"))
	responses := make([]any, 0, len(lines)/2)

	for i := 0; i < len(lines); i += 2 {
		hdrLine := lines[i]
		bodyLine := lines[i+1]

		var hdrOuter map[string]json.RawMessage
		if err := json.Unmarshal([]byte(hdrLine), &hdrOuter); err != nil {
			writeESError(w, http.StatusBadRequest, "parsing_exception", "failed to parse mpercolate header: "+err.Error())
			return
		}
		if len(hdrOuter) != 1 {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				"mpercolate header must contain a single [percolate] or [count] key")
			return
		}
		var actionType string
		var hdrRaw json.RawMessage
		for k, v := range hdrOuter {
			if k != "percolate" && k != "count" {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("unknown mpercolate header action [%s], expected [percolate] or [count]", k))
				return
			}
			actionType = k
			hdrRaw = v
		}
		var hdrMap map[string]any
		if len(bytes.TrimSpace(hdrRaw)) > 0 && string(bytes.TrimSpace(hdrRaw)) != "{}" {
			dec := json.NewDecoder(bytes.NewReader(hdrRaw))
			dec.UseNumber()
			if err := dec.Decode(&hdrMap); err != nil {
				writeESError(w, http.StatusBadRequest, "parsing_exception", "failed to parse mpercolate header object: "+err.Error())
				return
			}
		}

		var bodyMap map[string]any
		if len(strings.TrimSpace(bodyLine)) > 0 {
			dec := json.NewDecoder(strings.NewReader(bodyLine))
			dec.UseNumber()
			if err := dec.Decode(&bodyMap); err != nil {
				responses = append(responses, buildInlineESErrorItemRound59(http.StatusBadRequest, "parsing_exception", err.Error()))
				continue
			}
		}

		targetIndex := defaultIndex
		if v, ok := hdrMap["index"].(string); ok && strings.TrimSpace(v) != "" {
			targetIndex = strings.TrimSpace(v)
		} else if indicesArr, ok := hdrMap["indices"].([]any); ok && len(indicesArr) > 0 {
			parts := make([]string, 0, len(indicesArr))
			for _, el := range indicesArr {
				if ps, ok := el.(string); ok && strings.TrimSpace(ps) != "" {
					parts = append(parts, strings.TrimSpace(ps))
				}
			}
			if len(parts) > 0 {
				targetIndex = strings.Join(parts, ",")
			}
		}
		if targetIndex == "" {
			responses = append(responses, buildInlineESErrorItemRound59(
				http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: index is missing;"))
			continue
		}

		field := "query"
		if f, ok := hdrMap["field"].(string); ok && strings.TrimSpace(f) != "" {
			field = strings.TrimSpace(f)
		}
		docID, _ := hdrMap["id"].(string)
		docID = strings.TrimSpace(docID)
		percIdx, _ := hdrMap["percolate_index"].(string)
		percIdx = strings.TrimSpace(percIdx)
		if percIdx == "" {
			percIdx = targetIndex
		}

		var singleDoc map[string]any
		if dm, ok := bodyMap["doc"].(map[string]any); ok {
			singleDoc = dm
		} else if dm, ok := bodyMap["document"].(map[string]any); ok {
			singleDoc = dm
		}
		var multiDocs []any
		if docsArr, ok := bodyMap["documents"].([]any); ok {
			multiDocs = docsArr
		} else if docsArr, ok := bodyMap["docs"].([]any); ok {
			multiDocs = docsArr
		}

		if singleDoc == nil && len(multiDocs) == 0 {
			if docID == "" {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusBadRequest, "illegal_argument_exception",
					"[percolate] Must specify either [doc], [documents], or [id]"))
				continue
			}
			resolvedLookupIdx, aliasFilter, rErr := s.resolveReadDocIndexWithFilter(percIdx)
			if rErr != nil {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusBadRequest, "illegal_argument_exception", rErr.Error()))
				continue
			}
			if !s.indexExistsRound59(r.Context(), resolvedLookupIdx) {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusNotFound, "index_not_found_exception", "no such index ["+percIdx+"]"))
				continue
			}
			if s.isIndexClosed(resolvedLookupIdx) {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusBadRequest, "index_closed_exception", "closed ["+resolvedLookupIdx+"]"))
				continue
			}
			roSchema := s.getOrCompileReadOnlySchema(r.Context(), resolvedLookupIdx)
			_ = s.coalescer.FlushTable(r.Context(), roSchema.DorisTable)
			existing, found, gErr := s.backend.GetDocByID(r.Context(), roSchema.DorisDB, roSchema.DorisTable, docID)
			if gErr != nil {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusInternalServerError, "doris_query_exception", gErr.Error()))
				continue
			}
			if found && existing != nil && aliasFilter != nil && !s.docMatchesAliasFilter(r.Context(), resolvedLookupIdx, docID, existing.Source, aliasFilter) {
				found = false
			}
			if !found || existing == nil {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusBadRequest, "illegal_argument_exception", "Nothing to percolate"))
				continue
			}
			dec := json.NewDecoder(bytes.NewReader(existing.Source))
			dec.UseNumber()
			if err := dec.Decode(&singleDoc); err != nil || singleDoc == nil {
				responses = append(responses, buildInlineESErrorItemRound59(
					http.StatusBadRequest, "illegal_argument_exception", "Nothing to percolate"))
				continue
			}
		}

		percSpec := map[string]any{
			"field": field,
		}
		if len(multiDocs) > 0 {
			percSpec["documents"] = multiDocs
		} else {
			percSpec["document"] = singleDoc
		}
		if rt, ok := hdrMap["percolate_routing"].(string); ok && strings.TrimSpace(rt) != "" {
			percSpec["routing"] = strings.TrimSpace(rt)
		} else if rt, ok := hdrMap["routing"].(string); ok && strings.TrimSpace(rt) != "" {
			percSpec["routing"] = strings.TrimSpace(rt)
		}

		percQueryObj := map[string]any{"percolate": percSpec}
		var finalQuery any = percQueryObj
		if filterQ, hasQ := bodyMap["query"]; hasQ && filterQ != nil {
			finalQuery = map[string]any{
				"bool": map[string]any{
					"must":   []any{percQueryObj},
					"filter": []any{filterQ},
				},
			}
		}

		searchPayload := map[string]any{
			"query": finalQuery,
		}
		for _, copyKey := range []string{"size", "from", "sort", "aggs", "aggregations", "highlight", "_source", "track_total_hits", "min_score", "fields", "script_fields"} {
			if v, exists := bodyMap[copyKey]; exists {
				searchPayload[copyKey] = v
			}
		}
		if actionType == "count" {
			searchPayload["size"] = 0
			if _, hasTTH := searchPayload["track_total_hits"]; !hasTTH {
				searchPayload["track_total_hits"] = true
			}
		}

		subBodyBytes, err := json.Marshal(searchPayload)
		if err != nil {
			responses = append(responses, buildInlineESErrorItemRound59(http.StatusBadRequest, "parsing_exception", err.Error()))
			continue
		}

		qVals := url.Values{}
		if r != nil && r.URL != nil {
			for _, inhKey := range []string{"allow_no_indices", "ignore_unavailable", "expand_wildcards"} {
				if r.URL.Query().Has(inhKey) {
					qVals.Set(inhKey, r.URL.Query().Get(inhKey))
				}
			}
		}
		for _, hKey := range []string{"routing", "preference", "allow_no_indices", "ignore_unavailable", "expand_wildcards"} {
			if rawHV, exists := hdrMap[hKey]; exists && rawHV != nil {
				qVals.Set(hKey, fmt.Sprintf("%v", rawHV))
			}
		}

		subURL := "/" + url.PathEscape(targetIndex) + "/_search"
		if enc := qVals.Encode(); enc != "" {
			subURL += "?" + enc
		}
		subReq := httptest.NewRequest(http.MethodPost, subURL, bytes.NewReader(subBodyBytes))
		subReq = subReq.WithContext(r.Context())
		subReq.SetPathValue("index", targetIndex)
		subReq.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		if _, _, okT := s.resolveValidatedReadTargets(rec, subReq, targetIndex); okT {
			s.handleSearch(rec, subReq)
		}

		var itemResp map[string]any
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		if err := dec.Decode(&itemResp); err != nil || itemResp == nil {
			itemResp = buildInlineESErrorItemRound59(rec.Code, "internal_exception", strings.TrimSpace(rec.Body.String()))
		} else {
			itemResp["status"] = rec.Code
		}
		responses = append(responses, itemResp)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"took":      time.Since(start).Milliseconds(),
		"responses": responses,
	})
}

// ============================================================================
// Round 59 F4: _open / _close Lifecycle, _es_catalog Persistence & Guards
// ============================================================================

func withDefaultExpandWildcardsRound59(r *http.Request, defaultVal string) *http.Request {
	if r == nil || r.URL == nil || strings.TrimSpace(r.URL.Query().Get("expand_wildcards")) != "" {
		return r
	}
	cloned := r.Clone(r.Context())
	uCopy := *r.URL
	q := uCopy.Query()
	q.Set("expand_wildcards", defaultVal)
	uCopy.RawQuery = q.Encode()
	cloned.URL = &uCopy
	return cloned
}

// checkCloseDataStreamTargetRound59 rejects direct data-stream names on POST /{index}/_close.
func (s *Server) checkCloseDataStreamTargetRound59(w http.ResponseWriter, rawIndex string) bool {
	if strings.TrimSpace(rawIndex) == "" {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, part := range strings.Split(rawIndex, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "-") || strings.ContainsAny(part, "*?") || part == "_all" {
			continue
		}
		if _, isDS := s.dataStreams[part]; isDS {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Data stream [%s] cannot be closed", part))
			return false
		}
	}
	return true
}

// ensureNoExplicitClosedTargetRound59 enforces 400 index_closed_exception when concrete closed
// indices are targeted on _stats, _refresh, or _flush (unless ignore_unavailable=true).
func (s *Server) ensureNoExplicitClosedTargetRound59(w http.ResponseWriter, r *http.Request, rawIndex string) bool {
	rawIndex = strings.TrimSpace(rawIndex)
	if rawIndex == "" || isTruthyBoolQueryParam(r, "ignore_unavailable") {
		return true
	}
	if closedIdx := s.findClosedTargetIndex(r, rawIndex); closedIdx != "" {
		if r != nil && r.Method == http.MethodHead {
			ensureESCompatHeaders(w, r)
			w.WriteHeader(http.StatusBadRequest)
			return false
		}
		writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", closedIdx))
		return false
	}
	return true
}

func (s *Server) persistIndexBatchRound59(ctx context.Context, indexNames []string) {
	for _, idxName := range indexNames {
		s.mu.RLock()
		sch := s.indices[idxName]
		s.mu.RUnlock()
		if sch != nil {
			s.persistIndex(ctx, idxName, sch)
		}
	}
}

// ============================================================================
// Round 59 F5: _rollover Condition Engine, creation_date & Settings
// ============================================================================

func (s *Server) ensureIndexCreationDateLocked(indexName string) {
	if indexName == "" {
		return
	}
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	if s.indexCustomSettings[indexName] == nil {
		s.indexCustomSettings[indexName] = make(map[string]any)
	}
	if existing, ok := s.indexCustomSettings[indexName]["creation_date"]; !ok || strings.TrimSpace(fmt.Sprintf("%v", existing)) == "" {
		s.indexCustomSettings[indexName]["creation_date"] = strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
}

func (s *Server) setFreshIndexCreationDateLocked(indexName string) {
	if indexName == "" {
		return
	}
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	if s.indexCustomSettings[indexName] == nil {
		s.indexCustomSettings[indexName] = make(map[string]any)
	}
	s.indexCustomSettings[indexName]["creation_date"] = strconv.FormatInt(time.Now().UnixMilli(), 10)
}

var reESDurationRound59 = regexp.MustCompile(`^\s*([+-]?(?:\d+(?:\.\d+)?|\.\d+))\s*([a-zA-Z]+)\s*$`)

// parseESDurationMillisRound59 parses an ES TimeValue string (e.g. "7d", "500ms", "1.5h", "0s") into milliseconds.
func parseESDurationMillisRound59(raw string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("duration cannot be empty")
	}
	m := reESDurationRound59.FindStringSubmatch(trimmed)
	if m == nil {
		return 0, fmt.Errorf("failed to parse setting with value [%s] as a time value: unit is missing or unrecognized", raw)
	}
	val, err := strconv.ParseFloat(m[1], 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val < 0 {
		return 0, fmt.Errorf("failed to parse duration [%s]: value must be non-negative", raw)
	}
	var multMs float64
	switch m[2] {
	case "nanos", "ns":
		multMs = 1e-6
	case "micros", "us":
		multMs = 1e-3
	case "ms", "millis":
		multMs = 1
	case "s", "sec", "secs", "second", "seconds":
		multMs = 1000
	case "m", "min", "mins", "minute", "minutes":
		multMs = 60 * 1000
	case "h", "hr", "hrs", "hour", "hours":
		multMs = 3600 * 1000
	case "d", "day", "days":
		multMs = 86400 * 1000
	case "w", "week", "weeks":
		multMs = 7 * 86400 * 1000
	default:
		return 0, fmt.Errorf("failed to parse setting with value [%s] as a time value: unit [%s] is not supported", raw, m[2])
	}
	ms := val * multMs
	if ms >= math.Ldexp(1, 63) {
		return 0, fmt.Errorf("duration [%s] overflows int64 milliseconds", raw)
	}
	return int64(math.Round(ms)), nil
}

func parseStrictNonNegIntConditionRound59(key string, raw any) (int64, error) {
	switch v := raw.(type) {
	case int:
		if v < 0 {
			return 0, fmt.Errorf("[%s] must be a non-negative integer, got [%d]", key, v)
		}
		return int64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("[%s] must be a non-negative integer, got [%d]", key, v)
		}
		return v, nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || math.Trunc(v) != v || v >= math.Ldexp(1, 63) {
			return 0, fmt.Errorf("[%s] must be a non-negative integer, got [%v]", key, raw)
		}
		return int64(v), nil
	case json.Number:
		iv, err := v.Int64()
		if err != nil || iv < 0 {
			return 0, fmt.Errorf("[%s] must be a non-negative integer, got [%s]", key, v.String())
		}
		return iv, nil
	default:
		return 0, fmt.Errorf("[%s] must be a non-negative integer, got [%v]", key, raw)
	}
}

func (s *Server) getIndexShardCountLocked(indexName string) int64 {
	if cs := s.indexCustomSettings[indexName]; cs != nil {
		if raw, ok := cs["number_of_shards"]; ok && raw != nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", raw)), 10, 64); err == nil && n >= 1 {
				return n
			}
		}
	}
	return 1
}

func (s *Server) getIndexCreationDateMsLocked(indexName string, fallbackMs int64) int64 {
	if cs := s.indexCustomSettings[indexName]; cs != nil {
		if raw, ok := cs["creation_date"]; ok && raw != nil {
			if ms, err := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", raw)), 10, 64); err == nil && ms > 0 {
				return ms
			}
		}
	}
	return fallbackMs
}

func (s *Server) computeLiveIndexDocCountAndStoreBytesRound59(ctx context.Context, indexName string, needBytes bool) (int64, int64) {
	var docCount int64
	zero := 0
	if resp, _, errType, _ := s.executeSearchRequest(ctx, indexName, &esast.SearchRequest{Size: &zero, TrackTotalHits: true}); errType == "" {
		docCount, _ = extractTotalAndHitIDs(resp)
	}
	if !needBytes {
		return docCount, 0
	}
	idxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
	if idxSchema == nil || s.backend == nil {
		return docCount, 0
	}
	if s.coalescer != nil {
		_ = s.coalescer.FlushTable(ctx, idxSchema.DorisTable)
	}
	opts := s.transpileOpts
	opts.MaxResultWindow = 0
	tr := transpiler.NewTranspiler(idxSchema, opts)
	batchSize := 1000
	var searchAfter []any
	var totalBytes int64
	for {
		plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
			Size:           &batchSize,
			TrackTotalHits: false,
			Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
			SearchAfter:    searchAfter,
		})
		if err != nil {
			break
		}
		hits, err := s.backend.QueryHits(ctx, plan.HitsSQL)
		if err != nil || len(hits) == 0 {
			break
		}
		for _, h := range hits {
			src := h.EffectiveSource()
			if len(src) == 0 {
				src = h.Source
			}
			totalBytes += int64(len(src))
		}
		searchAfter = []any{hits[len(hits)-1].ID}
		if len(hits) < batchSize {
			break
		}
	}
	return docCount, totalBytes
}

// evaluateRolloverConditionsRound59 validates and evaluates all max_* / min_* rollover conditions.
func (s *Server) evaluateRolloverConditionsRound59(ctx context.Context, oldIdx string, conditions map[string]any) (map[string]bool, bool, error) {
	condResults := make(map[string]bool)
	if len(conditions) == 0 {
		return condResults, true, nil
	}

	type parsedCond struct {
		key       string
		label     string
		isMax     bool
		kind      string // "docs", "primary_docs", "age", "size", "primary_size"
		threshold int64
	}

	keys := make([]string, 0, len(conditions))
	for k := range conditions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	needBytes := false
	parsed := make([]parsedCond, 0, len(keys))
	for _, k := range keys {
		rawVal := conditions[k]
		switch k {
		case "max_docs", "min_docs", "max_primary_shard_docs", "min_primary_shard_docs":
			limit, err := parseStrictNonNegIntConditionRound59(k, rawVal)
			if err != nil {
				return nil, false, err
			}
			kind := "docs"
			if strings.Contains(k, "primary_shard") {
				kind = "primary_docs"
			}
			parsed = append(parsed, parsedCond{
				key:       k,
				label:     fmt.Sprintf("[%s: %d]", k, limit),
				isMax:     strings.HasPrefix(k, "max_"),
				kind:      kind,
				threshold: limit,
			})
		case "max_age", "min_age":
			sVal, ok := rawVal.(string)
			if !ok {
				return nil, false, fmt.Errorf("[%s] must be a duration string, got [%v]", k, rawVal)
			}
			limitMs, err := parseESDurationMillisRound59(sVal)
			if err != nil {
				return nil, false, err
			}
			parsed = append(parsed, parsedCond{
				key:       k,
				label:     fmt.Sprintf("[%s: %s]", k, strings.TrimSpace(sVal)),
				isMax:     strings.HasPrefix(k, "max_"),
				kind:      "age",
				threshold: limitMs,
			})
		case "max_size", "min_size", "max_primary_shard_size", "min_primary_shard_size":
			sVal, ok := rawVal.(string)
			if !ok {
				return nil, false, fmt.Errorf("[%s] must be a byte size string, got [%v]", k, rawVal)
			}
			limitBytes, err := parseIngestByteSize(sVal)
			if err != nil {
				return nil, false, err
			}
			needBytes = true
			kind := "size"
			if strings.Contains(k, "primary_shard") {
				kind = "primary_size"
			}
			parsed = append(parsed, parsedCond{
				key:       k,
				label:     fmt.Sprintf("[%s: %s]", k, strings.TrimSpace(sVal)),
				isMax:     strings.HasPrefix(k, "max_"),
				kind:      kind,
				threshold: limitBytes,
			})
		default:
			return nil, false, fmt.Errorf("unknown rollover condition [%s]", k)
		}
	}

	nowMs := time.Now().UnixMilli()
	s.mu.RLock()
	numShards := s.getIndexShardCountLocked(oldIdx)
	createdMs := s.getIndexCreationDateMsLocked(oldIdx, nowMs)
	s.mu.RUnlock()

	docCount, storeSizeBytes := s.computeLiveIndexDocCountAndStoreBytesRound59(ctx, oldIdx, needBytes)
	primaryShardDocs := docCount / numShards
	primaryShardSizeBytes := storeSizeBytes / numShards
	indexAgeMs := nowMs - createdMs
	if indexAgeMs < 0 {
		indexAgeMs = 0
	}

	numMax := 0
	numMin := 0
	anyMaxMet := false
	allMinMet := true

	for _, pc := range parsed {
		var actual int64
		switch pc.kind {
		case "docs":
			actual = docCount
		case "primary_docs":
			actual = primaryShardDocs
		case "age":
			actual = indexAgeMs
		case "size":
			actual = storeSizeBytes
		case "primary_size":
			actual = primaryShardSizeBytes
		}
		var met bool
		if pc.key == "max_docs" || pc.key == "max_primary_shard_docs" {
			// Note: max_docs: 0 rolls over immediately (>= 0); max_docs: N rolls over at >= N.
			met = actual >= pc.threshold
		} else {
			met = actual >= pc.threshold
		}
		condResults[pc.label] = met
		if pc.isMax {
			numMax++
			if met {
				anyMaxMet = true
			}
		} else {
			numMin++
			if !met {
				allMinMet = false
			}
		}
	}

	shouldRollover := (numMax == 0 && numMin == 0) || (numMax > 0 && anyMaxMet && allMinMet)
	return condResults, shouldRollover, nil
}

// validateIndexCreateOrResizeSettingsRound59 validates number_of_shards, number_of_replicas, and pipeline existence.
func (s *Server) validateIndexCreateOrResizeSettingsRound59(settings map[string]any) (targetShards int64, hasShards bool, err error) {
	if len(settings) == 0 {
		return 0, false, nil
	}
	if p, found := extractDefaultPipelineFromSettings(settings); found && p != "" && p != "_none" && p != "none" {
		s.mu.RLock()
		_, pipeExists := s.pipelines[p]
		s.mu.RUnlock()
		if !pipeExists {
			return 0, false, fmt.Errorf("pipeline with id [%s] does not exist", p)
		}
	}
	if fp, found := extractFinalPipelineFromSettings(settings); found && fp != "" && fp != "_none" && fp != "none" {
		s.mu.RLock()
		_, pipeExists := s.pipelines[fp]
		s.mu.RUnlock()
		if !pipeExists {
			return 0, false, fmt.Errorf("pipeline with id [%s] does not exist", fp)
		}
	}
	customFlat := extractCustomIndexSettings(settings)
	if rawShards, exists := customFlat["number_of_shards"]; exists && rawShards != nil {
		n, pErr := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", rawShards)), 10, 64)
		if pErr != nil || n < 1 {
			return 0, false, fmt.Errorf("index.number_of_shards must be >= 1, got [%v]", rawShards)
		}
		targetShards = n
		hasShards = true
	}
	if rawReplicas, exists := customFlat["number_of_replicas"]; exists && rawReplicas != nil {
		n, pErr := strconv.ParseInt(strings.TrimSpace(fmt.Sprintf("%v", rawReplicas)), 10, 64)
		if pErr != nil || n < 0 {
			return 0, false, fmt.Errorf("index.number_of_replicas must be >= 0, got [%v]", rawReplicas)
		}
	}
	return targetShards, hasShards, nil
}

// ============================================================================
// Round 59 F6: _shrink, _split & _clone Guards, Shard Factors & Settings Copy
// ============================================================================

func validateResizeShardFactorRound59(urlPath string, srcShards, targetShards int64, hasTargetShards bool) error {
	if !hasTargetShards {
		return nil
	}
	if strings.Contains(urlPath, "/_split/") {
		if targetShards <= srcShards || targetShards%srcShards != 0 {
			return fmt.Errorf("the number of target shards [%d] must be a factor greater than the number of source shards [%d]", targetShards, srcShards)
		}
	} else if strings.Contains(urlPath, "/_shrink/") {
		if targetShards < 1 || targetShards > srcShards || srcShards%targetShards != 0 {
			return fmt.Errorf("the number of source shards [%d] must be a multiple of the target shards [%d]", srcShards, targetShards)
		}
	}
	return nil
}

func (s *Server) copyAndOverlayResizeIndexSettingsLocked(srcIndex, targetIndex string, reqSettings map[string]any) {
	if s.indexCustomSettings == nil {
		s.indexCustomSettings = make(map[string]map[string]any)
	}
	dst := make(map[string]any)
	if srcMap := s.indexCustomSettings[srcIndex]; len(srcMap) > 0 {
		for k, v := range srcMap {
			cleanK := strings.TrimPrefix(k, "index.")
			if cleanK == "uuid" || cleanK == "creation_date" || cleanK == "provided_name" ||
				cleanK == "default_pipeline" || cleanK == "final_pipeline" ||
				strings.HasPrefix(cleanK, "blocks.") {
				continue
			}
			dst[cleanK] = deepCloneIngestValue(v)
		}
	}
	for k, v := range extractCustomIndexSettings(reqSettings) {
		if k == "default_pipeline" || k == "final_pipeline" || v == nil {
			continue
		}
		dst[k] = normalizeCustomSettingValue(v)
	}
	dst["creation_date"] = strconv.FormatInt(time.Now().UnixMilli(), 10)
	s.indexCustomSettings[targetIndex] = dst
}

// ============================================================================
// Round 59 F7: Enrich Snapshot Isolation, Spatial geo_match & REST Endpoints
// ============================================================================

type enrichGeoShapeRound59 struct {
	isPoint bool
	lon     float64
	lat     float64
	// rings[0] is exterior ring; rings[1:] are interior holes (if any).
	polygons [][][2]float64
	minLon   float64
	maxLon   float64
	minLat   float64
	maxLat   float64
}

func computeRingBoundsRound59(polys [][][2]float64) (minLon, maxLon, minLat, maxLat float64) {
	first := true
	for _, ring := range polys {
		for _, pt := range ring {
			if first {
				minLon, maxLon = pt[0], pt[0]
				minLat, maxLat = pt[1], pt[1]
				first = false
			} else {
				if pt[0] < minLon {
					minLon = pt[0]
				}
				if pt[0] > maxLon {
					maxLon = pt[0]
				}
				if pt[1] < minLat {
					minLat = pt[1]
				}
				if pt[1] > maxLat {
					maxLat = pt[1]
				}
			}
		}
	}
	return minLon, maxLon, minLat, maxLat
}

func makeBoxPolygonRound59(minLon, minLat, maxLon, maxLat float64) enrichGeoShapeRound59 {
	if minLon > maxLon {
		minLon, maxLon = maxLon, minLon
	}
	if minLat > maxLat {
		minLat, maxLat = maxLat, minLat
	}
	ring := [][2]float64{
		{minLon, minLat},
		{maxLon, minLat},
		{maxLon, maxLat},
		{minLon, maxLat},
		{minLon, minLat},
	}
	return enrichGeoShapeRound59{
		polygons: [][][2]float64{ring},
		minLon:   minLon,
		maxLon:   maxLon,
		minLat:   minLat,
		maxLat:   maxLat,
	}
}

func parseCoordPairSliceRound59(raw any) ([2]float64, bool) {
	arr, ok := raw.([]any)
	if !ok || len(arr) < 2 {
		return [2]float64{}, false
	}
	lon, okLon := toFloat64(arr[0])
	lat, okLat := toFloat64(arr[1])
	if !okLon || !okLat || math.IsNaN(lon) || math.IsNaN(lat) {
		return [2]float64{}, false
	}
	return [2]float64{lon, lat}, true
}

func parseRingCoordsRound59(raw any) ([][2]float64, bool) {
	arr, ok := raw.([]any)
	if !ok || len(arr) < 3 {
		return nil, false
	}
	ring := make([][2]float64, 0, len(arr))
	for _, el := range arr {
		pt, okPt := parseCoordPairSliceRound59(el)
		if !okPt {
			return nil, false
		}
		ring = append(ring, pt)
	}
	return ring, true
}

func parseWKTCoordSeqRound59(seq string) ([][2]float64, bool) {
	parts := strings.Split(seq, ",")
	pts := make([][2]float64, 0, len(parts))
	for _, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) < 2 {
			return nil, false
		}
		lon, err1 := strconv.ParseFloat(fields[0], 64)
		lat, err2 := strconv.ParseFloat(fields[1], 64)
		if err1 != nil || err2 != nil || math.IsNaN(lon) || math.IsNaN(lat) {
			return nil, false
		}
		pts = append(pts, [2]float64{lon, lat})
	}
	return pts, len(pts) > 0
}

func parseEnrichGeoShapeRound59(raw any) (enrichGeoShapeRound59, bool) {
	if raw == nil {
		return enrichGeoShapeRound59{}, false
	}
	switch v := raw.(type) {
	case []any:
		if pt, ok := parseCoordPairSliceRound59(v); ok {
			return enrichGeoShapeRound59{
				isPoint: true, lon: pt[0], lat: pt[1],
				minLon: pt[0], maxLon: pt[0], minLat: pt[1], maxLat: pt[1],
			}, true
		}
	case map[string]any:
		if rawType, hasType := v["type"].(string); hasType {
			switch strings.ToLower(strings.TrimSpace(rawType)) {
			case "point":
				if pt, ok := parseCoordPairSliceRound59(v["coordinates"]); ok {
					return enrichGeoShapeRound59{
						isPoint: true, lon: pt[0], lat: pt[1],
						minLon: pt[0], maxLon: pt[0], minLat: pt[1], maxLat: pt[1],
					}, true
				}
			case "envelope":
				coords, ok := v["coordinates"].([]any)
				if !ok || len(coords) != 2 {
					return enrichGeoShapeRound59{}, false
				}
				tl, ok1 := parseCoordPairSliceRound59(coords[0])
				br, ok2 := parseCoordPairSliceRound59(coords[1])
				if !ok1 || !ok2 {
					return enrichGeoShapeRound59{}, false
				}
				return makeBoxPolygonRound59(tl[0], br[1], br[0], tl[1]), true
			case "polygon":
				ringsAny, ok := v["coordinates"].([]any)
				if !ok || len(ringsAny) == 0 {
					return enrichGeoShapeRound59{}, false
				}
				extRing, ok := parseRingCoordsRound59(ringsAny[0])
				if !ok {
					return enrichGeoShapeRound59{}, false
				}
				polys := [][][2]float64{extRing}
				minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
				return enrichGeoShapeRound59{
					polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
				}, true
			case "multipoint":
				ptsAny, ok := v["coordinates"].([]any)
				if !ok || len(ptsAny) == 0 {
					return enrichGeoShapeRound59{}, false
				}
				var polys [][][2]float64
				for _, ptAny := range ptsAny {
					pt, okP := parseCoordPairSliceRound59(ptAny)
					if !okP {
						return enrichGeoShapeRound59{}, false
					}
					polys = append(polys, [][2]float64{pt, pt, pt})
				}
				minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
				return enrichGeoShapeRound59{
					polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
				}, true
			case "linestring":
				ptsAny, ok := v["coordinates"].([]any)
				if !ok || len(ptsAny) < 2 {
					return enrichGeoShapeRound59{}, false
				}
				line := make([][2]float64, 0, len(ptsAny))
				for _, el := range ptsAny {
					pt, okP := parseCoordPairSliceRound59(el)
					if !okP {
						return enrichGeoShapeRound59{}, false
					}
					line = append(line, pt)
				}
				// Represent open polyline as forward+reverse closed degenerate ring so segment intersection & within checks work uniformly.
				for i := len(line) - 2; i >= 0; i-- {
					line = append(line, line[i])
				}
				polys := [][][2]float64{line}
				minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
				return enrichGeoShapeRound59{
					polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
				}, true
			case "multilinestring":
				mlAny, ok := v["coordinates"].([]any)
				if !ok || len(mlAny) == 0 {
					return enrichGeoShapeRound59{}, false
				}
				var polys [][][2]float64
				for _, lAny := range mlAny {
					sub, okL := parseEnrichGeoShapeRound59(map[string]any{"type": "LineString", "coordinates": lAny})
					if !okL {
						return enrichGeoShapeRound59{}, false
					}
					polys = append(polys, sub.polygons...)
				}
				minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
				return enrichGeoShapeRound59{
					polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
				}, true
			case "geometrycollection":
				geomsAny, ok := v["geometries"].([]any)
				if !ok || len(geomsAny) == 0 {
					return enrichGeoShapeRound59{}, false
				}
				var polys [][][2]float64
				for _, gAny := range geomsAny {
					sub, okG := parseEnrichGeoShapeRound59(gAny)
					if !okG {
						return enrichGeoShapeRound59{}, false
					}
					if sub.isPoint {
						pt := [2]float64{sub.lon, sub.lat}
						polys = append(polys, [][2]float64{pt, pt, pt})
					} else {
						polys = append(polys, sub.polygons...)
					}
				}
				minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
				return enrichGeoShapeRound59{
					polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
				}, true
			case "multipolygon":
				mpAny, ok := v["coordinates"].([]any)
				if !ok || len(mpAny) == 0 {
					return enrichGeoShapeRound59{}, false
				}
				var polys [][][2]float64
				for _, polyAny := range mpAny {
					ringsAny, okR := polyAny.([]any)
					if !okR || len(ringsAny) == 0 {
						return enrichGeoShapeRound59{}, false
					}
					extRing, okE := parseRingCoordsRound59(ringsAny[0])
					if !okE {
						return enrichGeoShapeRound59{}, false
					}
					polys = append(polys, extRing)
				}
				minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
				return enrichGeoShapeRound59{
					polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
				}, true
			}
		}
		// {lat, lon} geo_point object
		latVal, okLat := toFloat64(v["lat"])
		lonVal, okLon := toFloat64(v["lon"])
		if okLat && okLon && !math.IsNaN(latVal) && !math.IsNaN(lonVal) {
			return enrichGeoShapeRound59{
				isPoint: true, lon: lonVal, lat: latVal,
				minLon: lonVal, maxLon: lonVal, minLat: latVal, maxLat: latVal,
			}, true
		}
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return enrichGeoShapeRound59{}, false
		}
		if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
			var decoded any
			if json.Unmarshal([]byte(s), &decoded) == nil {
				return parseEnrichGeoShapeRound59(decoded)
			}
		}
		upper := strings.ToUpper(s)
		switch {
		case strings.HasPrefix(upper, "POINT"):
			openIdx := strings.IndexByte(s, '(')
			closeIdx := strings.LastIndexByte(s, ')')
			if openIdx > 0 && closeIdx > openIdx {
				pts, ok := parseWKTCoordSeqRound59(s[openIdx+1 : closeIdx])
				if ok && len(pts) == 1 {
					return enrichGeoShapeRound59{
						isPoint: true, lon: pts[0][0], lat: pts[0][1],
						minLon: pts[0][0], maxLon: pts[0][0], minLat: pts[0][1], maxLat: pts[0][1],
					}, true
				}
			}
		case strings.HasPrefix(upper, "BBOX"):
			openIdx := strings.IndexByte(s, '(')
			closeIdx := strings.LastIndexByte(s, ')')
			if openIdx > 0 && closeIdx > openIdx {
				parts := strings.Split(s[openIdx+1:closeIdx], ",")
				if len(parts) == 4 {
					// WKT BBOX (minLon, maxLon, maxLat, minLat)
					minLon, e1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
					maxLon, e2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
					maxLat, e3 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
					minLat, e4 := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
					if e1 == nil && e2 == nil && e3 == nil && e4 == nil {
						return makeBoxPolygonRound59(minLon, minLat, maxLon, maxLat), true
					}
				}
			}
		case strings.HasPrefix(upper, "LINESTRING"):
			openIdx := strings.IndexByte(s, '(')
			closeIdx := strings.LastIndexByte(s, ')')
			if openIdx > 0 && closeIdx > openIdx {
				pts, ok := parseWKTCoordSeqRound59(s[openIdx+1 : closeIdx])
				if ok && len(pts) >= 2 {
					for i := len(pts) - 2; i >= 0; i-- {
						pts = append(pts, pts[i])
					}
					polys := [][][2]float64{pts}
					minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
					return enrichGeoShapeRound59{
						polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
					}, true
				}
			}
		case strings.HasPrefix(upper, "POLYGON"):
			openIdx := strings.IndexByte(s, '(')
			closeIdx := strings.LastIndexByte(s, ')')
			if openIdx > 0 && closeIdx > openIdx {
				inner := strings.TrimSpace(s[openIdx+1 : closeIdx])
				// Strip outer ring parens
				if strings.HasPrefix(inner, "(") && strings.HasSuffix(inner, ")") {
					ringEnd := strings.IndexByte(inner, ')')
					if ringEnd > 1 {
						pts, ok := parseWKTCoordSeqRound59(inner[1:ringEnd])
						if ok && len(pts) >= 3 {
							polys := [][][2]float64{pts}
							minLon, maxLon, minLat, maxLat := computeRingBoundsRound59(polys)
							return enrichGeoShapeRound59{
								polygons: polys, minLon: minLon, maxLon: maxLon, minLat: minLat, maxLat: maxLat,
							}, true
						}
					}
				}
			}
		default:
			// "lat,lon" string format
			parts := strings.Split(s, ",")
			if len(parts) == 2 {
				lat, e1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
				lon, e2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
				if e1 == nil && e2 == nil && !math.IsNaN(lat) && !math.IsNaN(lon) {
					return enrichGeoShapeRound59{
						isPoint: true, lon: lon, lat: lat,
						minLon: lon, maxLon: lon, minLat: lat, maxLat: lat,
					}, true
				}
			}
		}
	}
	return enrichGeoShapeRound59{}, false
}

func pointOnSegmentRound59(px, py, ax, ay, bx, by float64) bool {
	const eps = 1e-9
	cross := (px-ax)*(by-ay) - (py-ay)*(bx-ax)
	if math.Abs(cross) > eps {
		return false
	}
	minX, maxX := math.Min(ax, bx)-eps, math.Max(ax, bx)+eps
	minY, maxY := math.Min(ay, by)-eps, math.Max(ay, by)+eps
	return px >= minX && px <= maxX && py >= minY && py <= maxY
}

func pointInRingRound59(px, py float64, ring [][2]float64) bool {
	n := len(ring)
	if n < 3 {
		return false
	}
	inside := false
	j := n - 1
	for i := 0; i < n; i++ {
		xi, yi := ring[i][0], ring[i][1]
		xj, yj := ring[j][0], ring[j][1]
		if pointOnSegmentRound59(px, py, xi, yi, xj, yj) {
			return true
		}
		if ((yi > py) != (yj > py)) && (px < (xj-xi)*(py-yi)/(yj-yi)+xi) {
			inside = !inside
		}
		j = i
	}
	return inside
}

func pointInShapeRound59(px, py float64, sh enrichGeoShapeRound59) bool {
	if sh.isPoint {
		return math.Abs(px-sh.lon) <= 1e-9 && math.Abs(py-sh.lat) <= 1e-9
	}
	if px < sh.minLon-1e-9 || px > sh.maxLon+1e-9 || py < sh.minLat-1e-9 || py > sh.maxLat+1e-9 {
		return false
	}
	for _, ring := range sh.polygons {
		if pointInRingRound59(px, py, ring) {
			return true
		}
	}
	return false
}

func orient2DRound59(ax, ay, bx, by, cx, cy float64) float64 {
	return (bx-ax)*(cy-ay) - (by-ay)*(cx-ax)
}

func segmentsIntersectRound59(ax, ay, bx, by, cx, cy, dx, dy float64) bool {
	o1 := orient2DRound59(ax, ay, bx, by, cx, cy)
	o2 := orient2DRound59(ax, ay, bx, by, dx, dy)
	o3 := orient2DRound59(cx, cy, dx, dy, ax, ay)
	o4 := orient2DRound59(cx, cy, dx, dy, bx, by)
	if ((o1 > 0 && o2 < 0) || (o1 < 0 && o2 > 0)) && ((o3 > 0 && o4 < 0) || (o3 < 0 && o4 > 0)) {
		return true
	}
	if pointOnSegmentRound59(cx, cy, ax, ay, bx, by) ||
		pointOnSegmentRound59(dx, dy, ax, ay, bx, by) ||
		pointOnSegmentRound59(ax, ay, cx, cy, dx, dy) ||
		pointOnSegmentRound59(bx, by, cx, cy, dx, dy) {
		return true
	}
	return false
}

func geoShapesIntersectRound59(a, b enrichGeoShapeRound59) bool {
	if a.maxLon < b.minLon-1e-9 || b.maxLon < a.minLon-1e-9 ||
		a.maxLat < b.minLat-1e-9 || b.maxLat < a.minLat-1e-9 {
		return false
	}
	if a.isPoint {
		return pointInShapeRound59(a.lon, a.lat, b)
	}
	if b.isPoint {
		return pointInShapeRound59(b.lon, b.lat, a)
	}
	for _, rA := range a.polygons {
		for _, pt := range rA {
			if pointInShapeRound59(pt[0], pt[1], b) {
				return true
			}
		}
	}
	for _, rB := range b.polygons {
		for _, pt := range rB {
			if pointInShapeRound59(pt[0], pt[1], a) {
				return true
			}
		}
	}
	for _, rA := range a.polygons {
		for i := 0; i < len(rA); i++ {
			ni := (i + 1) % len(rA)
			for _, rB := range b.polygons {
				for j := 0; j < len(rB); j++ {
					nj := (j + 1) % len(rB)
					if segmentsIntersectRound59(
						rA[i][0], rA[i][1], rA[ni][0], rA[ni][1],
						rB[j][0], rB[j][1], rB[nj][0], rB[nj][1],
					) {
						return true
					}
				}
			}
		}
	}
	return false
}

// geoShapeWithinRound59 returns true if every point of shape a lies inside or on the boundary of shape b.
func geoShapeWithinRound59(a, b enrichGeoShapeRound59) bool {
	if a.isPoint {
		return pointInShapeRound59(a.lon, a.lat, b)
	}
	if b.isPoint {
		for _, ring := range a.polygons {
			for _, pt := range ring {
				if math.Abs(pt[0]-b.lon) > 1e-9 || math.Abs(pt[1]-b.lat) > 1e-9 {
					return false
				}
			}
		}
		return len(a.polygons) > 0
	}
	for _, rA := range a.polygons {
		for i := 0; i < len(rA); i++ {
			if !pointInShapeRound59(rA[i][0], rA[i][1], b) {
				return false
			}
			ni := (i + 1) % len(rA)
			midX := 0.5 * (rA[i][0] + rA[ni][0])
			midY := 0.5 * (rA[i][1] + rA[ni][1])
			if !pointInShapeRound59(midX, midY, b) {
				return false
			}
		}
	}
	return len(a.polygons) > 0
}

func validateEnrichShapeRelationRound59(rel string) error {
	switch strings.ToLower(strings.TrimSpace(rel)) {
	case "", "intersects", "within", "contains", "disjoint":
		return nil
	default:
		return fmt.Errorf("illegal_argument_exception: invalid shape_relation [%s], must be one of [intersects, within, contains, disjoint]", rel)
	}
}

// enrichDocMatchesGeoValueRound59 evaluates ES geo_match spatial relation between indexed doc shape and lookup shape.
func enrichDocMatchesGeoValueRound59(srcMap map[string]any, matchField string, lookupVal any, shapeRelation string) bool {
	docVal, ok := getIngestPath(srcMap, matchField)
	if !ok || docVal == nil || lookupVal == nil {
		return false
	}
	rel := strings.ToLower(strings.TrimSpace(shapeRelation))
	if rel == "" {
		rel = "intersects"
	}
	docShape, okDoc := parseEnrichGeoShapeRound59(docVal)
	lookupShape, okLookup := parseEnrichGeoShapeRound59(lookupVal)
	if !okDoc || !okLookup {
		return false
	}
	switch rel {
	case "intersects":
		return geoShapesIntersectRound59(docShape, lookupShape)
	case "disjoint":
		return !geoShapesIntersectRound59(docShape, lookupShape)
	case "within":
		// Indexed enrich shape is within the incoming lookup shape.
		return geoShapeWithinRound59(docShape, lookupShape)
	case "contains":
		// Indexed enrich shape contains the incoming lookup shape.
		return geoShapeWithinRound59(lookupShape, docShape)
	default:
		return false
	}
}

func extractEnrichSnapshotDocsRound59(pol map[string]any) ([]map[string]any, bool) {
	if pol == nil {
		return nil, false
	}
	executed, _ := pol["__executed"].(bool)
	switch raw := pol["__snapshot_docs"].(type) {
	case []map[string]any:
		return raw, executed
	case []any:
		out := make([]map[string]any, 0, len(raw))
		for _, el := range raw {
			if m, ok := el.(map[string]any); ok && m != nil {
				out = append(out, m)
			}
		}
		return out, executed
	default:
		return nil, executed
	}
}

func resolveEnrichShapeRelationRound59(specMap, pol map[string]any) string {
	if sr, ok := specMap["shape_relation"].(string); ok && strings.TrimSpace(sr) != "" {
		return strings.TrimSpace(sr)
	}
	if pol != nil {
		if gm, ok := pol["geo_match"].(map[string]any); ok {
			if sr, okS := gm["shape_relation"].(string); okS && strings.TrimSpace(sr) != "" {
				return strings.TrimSpace(sr)
			}
		}
	}
	return "intersects"
}

// ============================================================================
// Round 59 F8: Snapshot & Restore Conflict, Closed-Index Drop/Reopen & Global State
// ============================================================================

type snapshotRestoreTargetPairRound59 struct {
	srcIdx    string
	targetIdx string
}

// preValidateAndResolveRestoreTargetsRound59 checks all target indices atomically before mutating state.
func (s *Server) preValidateAndResolveRestoreTargetsRound59(
	ctx context.Context,
	repo, snap string,
	sourceIndices []string,
	renameRe *regexp.Regexp,
	renameReplacement string,
) ([]snapshotRestoreTargetPairRound59, int, string, string) {
	_ = s.syncCatalogFromBackend(ctx)
	pairs := make([]snapshotRestoreTargetPairRound59, 0, len(sourceIndices))
	seenTargets := make(map[string]bool, len(sourceIndices))

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, srcIdx := range sourceIndices {
		targetIdx := srcIdx
		if renameRe != nil {
			targetIdx = applyJavaRegexSimpleReplacement(renameRe, srcIdx, renameReplacement)
		}
		if reason, ok := validateESIndexName(targetIdx); !ok {
			return nil, http.StatusBadRequest, "invalid_index_name_exception", reason
		}
		if seenTargets[targetIdx] {
			return nil, http.StatusBadRequest, "snapshot_restore_exception",
				fmt.Sprintf("[%s:%s] cannot restore multiple indices into the same target index [%s]", repo, snap, targetIdx)
		}
		seenTargets[targetIdx] = true
		if s.indices[targetIdx] != nil && !s.closedIndices[targetIdx] {
			return nil, http.StatusBadRequest, "snapshot_restore_exception",
				fmt.Sprintf("[%s:%s] cannot restore index [%s] because an open index with same name already exists in the cluster", repo, snap, targetIdx)
		}
		pairs = append(pairs, snapshotRestoreTargetPairRound59{srcIdx: srcIdx, targetIdx: targetIdx})
	}
	return pairs, 0, "", ""
}

// dropAndResetClosedTargetIndexForRestoreRound59 drops an existing closed index table and resets its in-memory state.
func (s *Server) dropAndResetClosedTargetIndexForRestoreRound59(ctx context.Context, targetIdx string) {
	s.mu.RLock()
	oldSchema := s.indices[targetIdx]
	isClosed := s.closedIndices[targetIdx]
	s.mu.RUnlock()
	if oldSchema == nil || !isClosed {
		return
	}
	if s.coalescer != nil {
		_ = s.coalescer.FlushTable(ctx, oldSchema.DorisTable)
	}
	if s.backend != nil {
		dropSQL := fmt.Sprintf("DROP TABLE IF EXISTS `%s`.`%s`", s.dorisDB, oldSchema.DorisTable)
		_ = s.backend.ExecDDL(ctx, dropSQL)
	}
	aliasesToPersist := make(map[string][]string)
	s.mu.Lock()
	delete(s.indices, targetIdx)
	delete(s.closedIndices, targetIdx)
	delete(s.docVersions, targetIdx)
	delete(s.docRouting, targetIdx)
	delete(s.indexCustomSettings, targetIdx)
	delete(s.indexDefaultPipelines, targetIdx)
	delete(s.indexFinalPipelines, targetIdx)
	for aliasName, targets := range s.aliases {
		filtered := targets[:0]
		changed := false
		for _, t := range targets {
			if t == targetIdx {
				changed = true
				continue
			}
			filtered = append(filtered, t)
		}
		if changed {
			if len(filtered) == 0 {
				delete(s.aliases, aliasName)
				delete(s.aliasMeta, aliasName)
				aliasesToPersist[aliasName] = nil
			} else {
				cp := append([]string(nil), filtered...)
				s.aliases[aliasName] = cp
				if s.aliasMeta[aliasName] != nil {
					delete(s.aliasMeta[aliasName], targetIdx)
				}
				aliasesToPersist[aliasName] = cp
			}
		}
	}
	s.mu.Unlock()
	for aliasName, targets := range aliasesToPersist {
		s.persistAlias(ctx, aliasName, targets)
	}
}

func (s *Server) captureSnapshotExtraGlobalAndIndexStateLocked(snapObj map[string]any, indices []string, includeGlobalState bool) {
	defPipes := make(map[string]string)
	finPipes := make(map[string]string)
	for _, idxName := range indices {
		if dp := s.indexDefaultPipelines[idxName]; dp != "" {
			defPipes[idxName] = dp
		}
		if fp := s.indexFinalPipelines[idxName]; fp != "" {
			finPipes[idxName] = fp
		}
	}
	if len(defPipes) > 0 {
		snapObj["__default_pipelines"] = defPipes
	}
	if len(finPipes) > 0 {
		snapObj["__final_pipelines"] = finPipes
	}
	if !includeGlobalState {
		return
	}
	if len(s.templates) > 0 {
		savedTpls := make(map[string]esast.IndexTemplateRequest, len(s.templates))
		for tk, tv := range s.templates {
			if raw, err := json.Marshal(tv); err == nil {
				var cp esast.IndexTemplateRequest
				if json.Unmarshal(raw, &cp) == nil {
					savedTpls[tk] = cp
				}
			}
		}
		snapObj["__composable_templates"] = savedTpls
	}
	if len(s.legacyTemplates) > 0 {
		savedLeg := make(map[string]esast.IndexTemplateRequest, len(s.legacyTemplates))
		for tk, tv := range s.legacyTemplates {
			if raw, err := json.Marshal(tv); err == nil {
				var cp esast.IndexTemplateRequest
				if json.Unmarshal(raw, &cp) == nil {
					cp.Legacy = true
					savedLeg[tk] = cp
				}
			}
		}
		snapObj["__legacy_templates"] = savedLeg
	}
	if len(s.clusterPersistentSettings) > 0 {
		snapObj["__cluster_persistent_settings"] = deepCloneDocMap(s.clusterPersistentSettings)
	}
}

func (s *Server) restoreSnapshotExtraGlobalStateRound59(ctx context.Context, rawSnapRef map[string]any) {
	if rawSnapRef == nil {
		return
	}
	var restoredComposable map[string]esast.IndexTemplateRequest
	var restoredLegacy map[string]esast.IndexTemplateRequest

	s.mu.Lock()
	switch savedComp := rawSnapRef["__composable_templates"].(type) {
	case map[string]esast.IndexTemplateRequest:
		if s.templates == nil {
			s.templates = make(map[string]esast.IndexTemplateRequest)
		}
		restoredComposable = make(map[string]esast.IndexTemplateRequest, len(savedComp))
		for tk, tv := range savedComp {
			if raw, err := json.Marshal(tv); err == nil {
				var cp esast.IndexTemplateRequest
				if json.Unmarshal(raw, &cp) == nil {
					s.templates[tk] = cp
					restoredComposable[tk] = cp
				}
			}
		}
	case map[string]any:
		if s.templates == nil {
			s.templates = make(map[string]esast.IndexTemplateRequest)
		}
		restoredComposable = make(map[string]esast.IndexTemplateRequest, len(savedComp))
		for tk, tv := range savedComp {
			if raw, err := json.Marshal(tv); err == nil {
				var cp esast.IndexTemplateRequest
				if json.Unmarshal(raw, &cp) == nil {
					s.templates[tk] = cp
					restoredComposable[tk] = cp
				}
			}
		}
	}

	switch savedLeg := rawSnapRef["__legacy_templates"].(type) {
	case map[string]esast.IndexTemplateRequest:
		if s.legacyTemplates == nil {
			s.legacyTemplates = make(map[string]esast.IndexTemplateRequest)
		}
		restoredLegacy = make(map[string]esast.IndexTemplateRequest, len(savedLeg))
		for tk, tv := range savedLeg {
			if raw, err := json.Marshal(tv); err == nil {
				var cp esast.IndexTemplateRequest
				if json.Unmarshal(raw, &cp) == nil {
					cp.Legacy = true
					s.legacyTemplates[tk] = cp
					restoredLegacy[tk] = cp
				}
			}
		}
	case map[string]any:
		if s.legacyTemplates == nil {
			s.legacyTemplates = make(map[string]esast.IndexTemplateRequest)
		}
		restoredLegacy = make(map[string]esast.IndexTemplateRequest, len(savedLeg))
		for tk, tv := range savedLeg {
			if raw, err := json.Marshal(tv); err == nil {
				var cp esast.IndexTemplateRequest
				if json.Unmarshal(raw, &cp) == nil {
					cp.Legacy = true
					s.legacyTemplates[tk] = cp
					restoredLegacy[tk] = cp
				}
			}
		}
	}

	if savedCluster, okC := rawSnapRef["__cluster_persistent_settings"].(map[string]any); okC {
		if s.clusterPersistentSettings == nil {
			s.clusterPersistentSettings = make(map[string]any)
		}
		for ck, cv := range savedCluster {
			s.clusterPersistentSettings[ck] = deepCloneIngestValue(cv)
		}
	}
	s.mu.Unlock()

	for tk, tv := range restoredComposable {
		s.persistTemplate(ctx, tk, tv)
	}
	if cb, ok := s.backend.(CatalogBackend); ok {
		for tk, tv := range restoredLegacy {
			if raw, err := marshalTemplatePreservingEmptyMaps(tv); err == nil {
				_ = cb.UpsertCatalogEntry(ctx, s.dorisDB, CatalogEntry{
					EntityType:     "legacy_template",
					EntityKey:      tk,
					PayloadJSON:    string(raw),
					UpdatedEpochMs: s.allocVersion(0),
				})
			}
		}
	}
}

// ============================================================================
// Round 59 F9: Wire Protocol Strictness, _validate/query & _terms_enum
// ============================================================================

func validateGlobalWireQueryParamsRound59(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return true
	}
	for _, key := range []string{"pretty", "error_trace", "human"} {
		if _, present, err := parseStrictQueryBoolParamRound59(r, key); present && err != nil {
			if r.Method == http.MethodHead {
				ensureESCompatHeaders(w, r)
				w.WriteHeader(http.StatusBadRequest)
				return false
			}
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return false
		}
	}
	return true
}

func isSupportedESContentTypeRound59(rawCT string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(rawCT))
	if semi := strings.IndexByte(mediaType, ';'); semi >= 0 {
		mediaType = strings.TrimSpace(mediaType[:semi])
	}
	switch mediaType {
	case "",
		"application/json",
		"application/x-ndjson",
		"application/ndjson",
		"application/vnd.elasticsearch+json",
		"application/vnd.elasticsearch+ndjson",
		"application/vnd.elasticsearch+x-ndjson",
		"application/yaml",
		"text/yaml",
		"application/cbor",
		"application/smile":
		return true
	default:
		return false
	}
}

func isRawUploadEndpointRound59(urlPath string) bool {
	p := strings.Trim(urlPath, "/")
	return strings.HasSuffix(p, "_ml/find_file_structure")
}

type prependedBodyReadCloserRound59 struct {
	io.Reader
	closer io.Closer
}

func (p *prependedBodyReadCloserRound59) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}

// validateRequestContentTypeRound59 enforces 406 Not Acceptable when a non-empty request sends
// an explicit unsupported Content-Type header.
func validateRequestContentTypeRound59(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return true
	}
	rawCT := strings.TrimSpace(r.Header.Get("Content-Type"))
	if rawCT == "" || isSupportedESContentTypeRound59(rawCT) || isRawUploadEndpointRound59(r.URL.Path) {
		return true
	}
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	var peek [1]byte
	n, err := r.Body.Read(peek[:])
	if n == 0 && (err == io.EOF || err != nil) {
		return true
	}
	r.Body = &prependedBodyReadCloserRound59{
		Reader: io.MultiReader(bytes.NewReader(peek[:n]), r.Body),
		closer: r.Body,
	}
	if r.Method == http.MethodHead {
		ensureESCompatHeaders(w, r)
		w.WriteHeader(http.StatusNotAcceptable)
		return false
	}
	writeESError(w, http.StatusNotAcceptable, "status_exception",
		fmt.Sprintf("Content-Type header [%s] is not supported", rawCT))
	return false
}

// ============================================================================
// Round 59 F27: Ingest set (value/copy_from, media_type) & rename (override=false)
// ============================================================================

func validateIngestSetSpecRound59(specMap map[string]any) error {
	_, hasVal := specMap["value"]
	rawCF, hasCF := specMap["copy_from"]
	hasNonNilCF := hasCF && rawCF != nil
	if hasNonNilCF {
		cfStr, ok := rawCF.(string)
		if !ok || strings.TrimSpace(cfStr) == "" {
			return fmt.Errorf("illegal_argument_exception: [copy_from] must be a non-empty string")
		}
	}
	if hasVal && hasNonNilCF {
		return fmt.Errorf("illegal_argument_exception: cannot specify both [value] and [copy_from]")
	}
	if !hasVal && !hasNonNilCF {
		return fmt.Errorf("either [value] or [copy_from] must be present")
	}
	for _, bKey := range []string{"override", "ignore_empty_value", "ignore_missing"} {
		if rawB, hasB := specMap[bKey]; hasB && rawB != nil {
			if _, ok := rawB.(bool); !ok {
				return fmt.Errorf("illegal_argument_exception: [%s] must be a boolean", bKey)
			}
		}
	}
	if rawMT, hasMT := specMap["media_type"]; hasMT && rawMT != nil {
		mtStr, ok := rawMT.(string)
		if !ok {
			return fmt.Errorf("illegal_argument_exception: [media_type] must be a string")
		}
		mediaBase := strings.ToLower(strings.TrimSpace(strings.Split(mtStr, ";")[0]))
		switch mediaBase {
		case "application/json", "text/plain", "application/x-www-form-urlencoded":
		default:
			return fmt.Errorf("illegal_argument_exception: unsupported media_type [%s]", mtStr)
		}
	}
	return nil
}

func decodeIngestSetMediaTypeValueRound59(expandedVal any, rawMediaType string) (any, error) {
	if strings.TrimSpace(rawMediaType) == "" {
		return expandedVal, nil
	}
	strVal, isStr := expandedVal.(string)
	if !isStr {
		return expandedVal, nil
	}
	mediaBase := strings.ToLower(strings.TrimSpace(strings.Split(rawMediaType, ";")[0]))
	switch mediaBase {
	case "text/plain":
		return strVal, nil
	case "application/json":
		var parsed any
		dec := json.NewDecoder(strings.NewReader(strVal))
		dec.UseNumber()
		if err := dec.Decode(&parsed); err != nil {
			return nil, fmt.Errorf("illegal_argument_exception: failed to parse value as application/json: %v", err)
		}
		var trailing any
		if dec.Decode(&trailing) != io.EOF {
			return nil, fmt.Errorf("illegal_argument_exception: trailing content in application/json value")
		}
		return normalizeJSONNumbersForIngestRound59(parsed), nil
	case "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(strVal)
		if err != nil {
			return nil, fmt.Errorf("illegal_argument_exception: failed to parse value as application/x-www-form-urlencoded: %v", err)
		}
		out := make(map[string]any, len(vals))
		for k, vSlice := range vals {
			if len(vSlice) == 1 {
				out[k] = vSlice[0]
			} else {
				arr := make([]any, len(vSlice))
				for i, item := range vSlice {
					arr[i] = item
				}
				out[k] = arr
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("illegal_argument_exception: unsupported media_type [%s]", rawMediaType)
	}
}

func normalizeJSONNumbersForIngestRound59(v any) any {
	switch tv := v.(type) {
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv
		}
		if fv, err := tv.Float64(); err == nil {
			return fv
		}
		return tv.String()
	case map[string]any:
		out := make(map[string]any, len(tv))
		for k, el := range tv {
			out[k] = normalizeJSONNumbersForIngestRound59(el)
		}
		return out
	case []any:
		out := make([]any, len(tv))
		for i, el := range tv {
			out[i] = normalizeJSONNumbersForIngestRound59(el)
		}
		return out
	default:
		return v
	}
}

func validateIngestRenameOrCopySpecRound59(procType string, specMap map[string]any) error {
	for _, bKey := range []string{"override", "ignore_missing"} {
		if rawB, hasB := specMap[bKey]; hasB && rawB != nil {
			if _, ok := rawB.(bool); !ok {
				return fmt.Errorf("illegal_argument_exception: [%s] in [%s] must be a boolean", bKey, procType)
			}
		}
	}
	return nil
}

// ============================================================================
// Round 59 F28: Ingest grok & redact Shared Pattern Definitions & Validation
// ============================================================================

// buildEffectiveGrokDefs validates grok/redact options and returns merged pattern definitions.
func buildEffectiveGrokDefs(procType string, specMap map[string]any) (map[string]any, error) {
	ecsCompat := "disabled"
	if rawECS, hasECS := specMap["ecs_compatibility"]; hasECS && rawECS != nil {
		ecsStr, ok := rawECS.(string)
		if !ok || (ecsStr != "disabled" && ecsStr != "v1") {
			return nil, fmt.Errorf("illegal_argument_exception: invalid ecs_compatibility [%v], must be [disabled] or [v1]", rawECS)
		}
		ecsCompat = ecsStr
	}
	for _, bKey := range []string{"ignore_missing", "keep_empty_captures", "trace_match", "warn_on_match"} {
		if rawB, hasB := specMap[bKey]; hasB && rawB != nil {
			if _, ok := rawB.(bool); !ok {
				return nil, fmt.Errorf("illegal_argument_exception: [%s] must be a boolean", bKey)
			}
		}
	}
	if procType == "redact" {
		for _, sKey := range []string{"prefix", "suffix"} {
			if rawS, hasS := specMap[sKey]; hasS && rawS != nil {
				if _, ok := rawS.(string); !ok {
					return nil, fmt.Errorf("illegal_argument_exception: [%s] must be a string", sKey)
				}
			}
		}
	}
	var rawDefsMap map[string]any
	if rawPD, hasPD := specMap["pattern_definitions"]; hasPD && rawPD != nil {
		pm, ok := rawPD.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("illegal_argument_exception: [pattern_definitions] must be a map of strings")
		}
		for pk, pv := range pm {
			if _, okS := pv.(string); !okS {
				return nil, fmt.Errorf("illegal_argument_exception: pattern_definitions[%s] must be a string", pk)
			}
		}
		rawDefsMap = pm
	}
	if ecsCompat != "v1" && len(rawDefsMap) == 0 {
		return nil, nil
	}
	merged := make(map[string]any, len(ecsGrokPatterns)+len(rawDefsMap))
	if ecsCompat == "v1" {
		for k, v := range ecsGrokPatterns {
			merged[k] = v
		}
	}
	for k, v := range rawDefsMap {
		merged[k] = v
	}
	return merged, nil
}

// ============================================================================
// Round 59 F29: Ingest date / date_index_name Locale & Format Validation + bytes Bounds
// ============================================================================

var supportedIngestLocaleLangsRound59 = map[string]bool{
	"ar": true, "bg": true, "ca": true, "cs": true, "da": true, "de": true,
	"el": true, "en": true, "es": true, "et": true, "fa": true, "fi": true,
	"fr": true, "ga": true, "he": true, "hi": true, "hr": true, "hu": true,
	"id": true, "in": true, "is": true, "it": true, "iw": true, "ja": true,
	"ko": true, "lt": true, "lv": true, "mk": true, "ms": true, "mt": true,
	"nb": true, "nl": true, "nn": true, "no": true, "pl": true, "pt": true,
	"ro": true, "ru": true, "sk": true, "sl": true, "sq": true, "sr": true,
	"sv": true, "th": true, "tr": true, "uk": true, "und": true, "vi": true,
	"zh": true,
}

func validateAndExtractIngestLocaleLangRound59(rawLocale string) (string, error) {
	trimmed := strings.TrimSpace(rawLocale)
	if trimmed == "" || strings.EqualFold(trimmed, "ROOT") {
		return "en", nil
	}
	normalized := strings.ReplaceAll(trimmed, "_", "-")
	parts := strings.Split(normalized, "-")
	if len(parts) == 0 || len(parts) > 4 {
		return "", fmt.Errorf("illegal_argument_exception: invalid locale [%s]", rawLocale)
	}
	lang := strings.ToLower(parts[0])
	if !supportedIngestLocaleLangsRound59[lang] {
		return "", fmt.Errorf("illegal_argument_exception: unsupported or invalid locale [%s]", rawLocale)
	}
	for _, sub := range parts[1:] {
		if sub == "" || len(sub) > 8 {
			return "", fmt.Errorf("illegal_argument_exception: invalid locale subtag in [%s]", rawLocale)
		}
		for _, r := range sub {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return "", fmt.Errorf("illegal_argument_exception: invalid locale [%s]", rawLocale)
			}
		}
	}
	return lang, nil
}

var namedESDateFormatsRound59 = map[string]bool{
	"ISO8601": true, "UNIX": true, "UNIX_MS": true, "TAI64N": true, "tai64n": true,
	"epoch_millis": true, "epoch_second": true,
	"strict_date_optional_time": true, "date_optional_time": true, "strict_date_optional_time_nanos": true,
	"ordinal_date": true, "strict_ordinal_date": true,
	"ordinal_date_no_millis": true, "strict_ordinal_date_no_millis": true,
	"ordinal_date_time": true, "strict_ordinal_date_time": true,
	"ordinal_date_time_no_millis": true, "strict_ordinal_date_time_no_millis": true,
	"basic_ordinal_date": true, "strict_basic_ordinal_date": true,
	"basic_ordinal_date_time": true, "strict_basic_ordinal_date_time": true,
	"basic_ordinal_date_time_no_millis": true, "strict_basic_ordinal_date_time_no_millis": true,
	"basic_date": true, "strict_basic_date": true,
	"basic_date_time": true, "strict_basic_date_time": true,
	"basic_date_time_no_millis": true, "strict_basic_date_time_no_millis": true,
	"date": true, "strict_date": true, "year_month_day": true, "strict_year_month_day": true,
	"date_time": true, "strict_date_time": true,
	"date_time_no_millis": true, "strict_date_time_no_millis": true,
	"date_hour_minute_second": true, "strict_date_hour_minute_second": true,
	"date_hour_minute_second_millis": true, "strict_date_hour_minute_second_millis": true,
	"date_hour_minute_second_fraction": true, "strict_date_hour_minute_second_fraction": true,
	"rfc_1123_date_time": true,
}

// validateESDateFormatPatternRound59 checks Java DateTimeFormatter pattern letters outside single-quoted literals.
func validateESDateFormatPatternRound59(pat string) error {
	trimmed := strings.TrimSpace(pat)
	if trimmed == "" {
		return fmt.Errorf("illegal_argument_exception: date format pattern must not be empty")
	}
	if namedESDateFormatsRound59[trimmed] {
		return nil
	}
	inQuote := false
	for i := 0; i < len(pat); i++ {
		ch := pat[i]
		if ch == '\'' {
			if i+1 < len(pat) && pat[i+1] == '\'' {
				i++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			// Java DateTimeFormatter valid pattern letters (+ 'T'/'Z' commonly written unquoted in ISO strings)
			switch ch {
			case 'G', 'u', 'y', 'Y', 'D', 'M', 'L', 'd', 'Q', 'q', 'w', 'W',
				'E', 'e', 'c', 'F', 'a', 'H', 'k', 'K', 'h', 'm', 's', 'S',
				'A', 'n', 'N', 'V', 'z', 'O', 'X', 'x', 'Z', 'T':
			default:
				return fmt.Errorf("illegal_argument_exception: unknown pattern letter [%c] in date format [%s]", ch, pat)
			}
		}
	}
	if inQuote {
		return fmt.Errorf("illegal_argument_exception: unterminated quote in date format [%s]", pat)
	}
	return nil
}

func validateIngestDateCommonOptionsRound59(specMap map[string]any, fmtProp string) error {
	if rawIM, hasIM := specMap["ignore_missing"]; hasIM && rawIM != nil {
		if _, ok := rawIM.(bool); !ok {
			return fmt.Errorf("illegal_argument_exception: [ignore_missing] must be a boolean")
		}
	}
	if rawLoc, hasLoc := specMap["locale"]; hasLoc && rawLoc != nil {
		locStr, ok := rawLoc.(string)
		if !ok || strings.TrimSpace(locStr) == "" {
			return fmt.Errorf("illegal_argument_exception: [locale] must be a non-empty string")
		}
		if !strings.Contains(locStr, "{{") {
			if _, err := validateAndExtractIngestLocaleLangRound59(locStr); err != nil {
				return err
			}
		}
	}
	if fmtProp != "" {
		if rawOF, hasOF := specMap[fmtProp]; hasOF && rawOF != nil {
			ofStr, ok := rawOF.(string)
			if !ok || strings.TrimSpace(ofStr) == "" {
				return fmt.Errorf("illegal_argument_exception: [%s] must be a non-empty string", fmtProp)
			}
			if !strings.Contains(ofStr, "{{") {
				if err := validateESDateFormatPatternRound59(ofStr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type localizedDateTokensRound59 struct {
	monthsFull  [12]string
	monthsShort [12]string
	daysFull    [7]string // Sunday..Saturday
	daysShort   [7]string
}

var englishMonthsFullRound59 = [12]string{
	"January", "February", "March", "April", "May", "June",
	"July", "August", "September", "October", "November", "December",
}

var englishMonthsShortRound59 = [12]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

var englishDaysFullRound59 = [7]string{
	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
}

var englishDaysShortRound59 = [7]string{
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
}

var localeDateDictRound59 = map[string]localizedDateTokensRound59{
	"fr": {
		monthsFull:  [12]string{"janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"},
		monthsShort: [12]string{"janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."},
		daysFull:    [7]string{"dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"},
		daysShort:   [7]string{"dim.", "lun.", "mar.", "mer.", "jeu.", "ven.", "sam."},
	},
	"de": {
		monthsFull:  [12]string{"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"},
		monthsShort: [12]string{"Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"},
		daysFull:    [7]string{"Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"},
		daysShort:   [7]string{"So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"},
	},
	"es": {
		monthsFull:  [12]string{"enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"},
		monthsShort: [12]string{"ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"},
		daysFull:    [7]string{"domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"},
		daysShort:   [7]string{"dom", "lun", "mar", "mié", "jue", "vie", "sáb"},
	},
	"it": {
		monthsFull:  [12]string{"gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"},
		monthsShort: [12]string{"gen", "feb", "mar", "apr", "mag", "giu", "lug", "ago", "set", "ott", "nov", "dic"},
		daysFull:    [7]string{"domenica", "lunedì", "martedì", "mercoledì", "giovedì", "venerdì", "sabato"},
		daysShort:   [7]string{"dom", "lun", "mar", "mer", "gio", "ven", "sab"},
	},
	"pt": {
		monthsFull:  [12]string{"janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"},
		monthsShort: [12]string{"jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"},
		daysFull:    [7]string{"domingo", "segunda-feira", "terça-feira", "quarta-feira", "quinta-feira", "sexta-feira", "sábado"},
		daysShort:   [7]string{"dom", "seg", "ter", "qua", "qui", "sex", "sáb"},
	},
	"nl": {
		monthsFull:  [12]string{"januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"},
		monthsShort: [12]string{"jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec"},
		daysFull:    [7]string{"zondag", "maandag", "dinsdag", "woensdag", "donderdag", "vrijdag", "zaterdag"},
		daysShort:   [7]string{"zo", "ma", "di", "wo", "do", "vr", "za"},
	},
}

// Extra ASCII-normalized / dotless aliases commonly produced across JDK 8-21 CLDR locales.
var localeExtraMonthAliasesRound59 = map[string]map[string]string{
	"fr": {
		"fevrier": "February", "aout": "August", "decembre": "December",
		"janv": "Jan", "jan": "Jan", "fevr": "Feb", "févr": "Feb", "fev": "Feb",
		"avr": "Apr", "juil": "Jul", "sept": "Sep", "sep": "Sep", "oct": "Oct", "nov": "Nov", "dec": "Dec", "déc": "Dec",
	},
	"de": {
		"maerz": "March", "marz": "March", "märz": "March", "mr": "Mar", "mrz": "Mar", "mae": "Mar",
	},
	"es": {
		"setiembre": "September", "sept": "Sep",
	},
}

func isWordBoundaryRuneRound59(r rune) bool {
	return !unicode.IsLetter(r)
}

func replaceCaseInsensitiveWordRound59(input, target, replacement string) string {
	if target == "" {
		return input
	}
	inRunes := []rune(input)
	tgtRunes := []rune(strings.ToLower(target))
	tLen := len(tgtRunes)
	if len(inRunes) < tLen {
		return input
	}
	var out strings.Builder
	i := 0
	for i < len(inRunes) {
		if i+tLen <= len(inRunes) {
			prevOK := i == 0 || isWordBoundaryRuneRound59(inRunes[i-1])
			endIdx := i + tLen
			// If target ends with '.', boundary check is on the char after '.'
			nextOK := endIdx == len(inRunes) || isWordBoundaryRuneRound59(inRunes[endIdx]) || tgtRunes[tLen-1] == '.'
			if prevOK && nextOK {
				match := true
				for k := 0; k < tLen; k++ {
					if unicode.ToLower(inRunes[i+k]) != tgtRunes[k] {
						match = false
						break
					}
				}
				if match {
					out.WriteString(replacement)
					i += tLen
					continue
				}
			}
		}
		out.WriteRune(inRunes[i])
		i++
	}
	return out.String()
}

func normalizeLocalizedDateInputToEnglishRound59(rawVal, lang string) string {
	if lang == "" || lang == "en" {
		return rawVal
	}
	dict, ok := localeDateDictRound59[lang]
	if !ok {
		return rawVal
	}
	out := rawVal
	for i := 0; i < 12; i++ {
		out = replaceCaseInsensitiveWordRound59(out, dict.monthsFull[i], englishMonthsFullRound59[i])
	}
	for i := 0; i < 7; i++ {
		out = replaceCaseInsensitiveWordRound59(out, dict.daysFull[i], englishDaysFullRound59[i])
	}
	for i := 0; i < 12; i++ {
		out = replaceCaseInsensitiveWordRound59(out, dict.monthsShort[i], englishMonthsShortRound59[i])
	}
	if extras, hasEx := localeExtraMonthAliasesRound59[lang]; hasEx {
		keys := make([]string, 0, len(extras))
		for k := range extras {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
		for _, k := range keys {
			out = replaceCaseInsensitiveWordRound59(out, k, extras[k])
		}
	}
	for i := 0; i < 7; i++ {
		out = replaceCaseInsensitiveWordRound59(out, dict.daysShort[i], englishDaysShortRound59[i])
	}
	return out
}

func localizeFormattedDateOutputRound59(formatted, outFmt, lang string, t time.Time) string {
	if lang == "" || lang == "en" {
		return formatted
	}
	dict, ok := localeDateDictRound59[lang]
	if !ok {
		return formatted
	}
	mIdx := int(t.Month()) - 1
	dIdx := int(t.Weekday())
	out := formatted
	if strings.Contains(outFmt, "MMMM") && mIdx >= 0 && mIdx < 12 {
		out = strings.ReplaceAll(out, englishMonthsFullRound59[mIdx], dict.monthsFull[mIdx])
	} else if strings.Contains(outFmt, "MMM") && mIdx >= 0 && mIdx < 12 {
		out = strings.ReplaceAll(out, englishMonthsShortRound59[mIdx], dict.monthsShort[mIdx])
	}
	if strings.Contains(outFmt, "EEEE") && dIdx >= 0 && dIdx < 7 {
		out = strings.ReplaceAll(out, englishDaysFullRound59[dIdx], dict.daysFull[dIdx])
	} else if strings.Contains(outFmt, "EEE") && dIdx >= 0 && dIdx < 7 {
		out = strings.ReplaceAll(out, englishDaysShortRound59[dIdx], dict.daysShort[dIdx])
	}
	return out
}

func parseIngestDateValueWithLocaleRound59(rawVal string, formats []any, tzName, rawLocale string) (time.Time, string, error) {
	lang, err := validateAndExtractIngestLocaleLangRound59(rawLocale)
	if err != nil {
		return time.Time{}, "", err
	}
	normInput := normalizeLocalizedDateInputToEnglishRound59(rawVal, lang)
	t, pErr := parseIngestDateValue(normInput, formats, tzName)
	return t, lang, pErr
}

// parseStrictIngestBytesElementRound59 converts a string or numeric value to whole int64 bytes,
// rejecting NaN, Inf, negatives, fractional byte counts, and >= 2^63 overflow.
func parseStrictIngestBytesElementRound59(field string, el any) (int64, error) {
	switch ev := el.(type) {
	case string:
		return parseIngestByteSize(ev)
	case int:
		if ev < 0 {
			return 0, fmt.Errorf("illegal_argument_exception: unable to convert [%d] to bytes", ev)
		}
		return int64(ev), nil
	case int64:
		if ev < 0 {
			return 0, fmt.Errorf("illegal_argument_exception: unable to convert [%d] to bytes", ev)
		}
		return ev, nil
	case float64:
		if math.IsNaN(ev) || math.IsInf(ev, 0) || ev < 0 || math.Trunc(ev) != ev || ev >= math.Ldexp(1, 63) {
			return 0, fmt.Errorf("illegal_argument_exception: unable to convert [%v] to bytes", ev)
		}
		return int64(ev), nil
	case json.Number:
		if iv, err := ev.Int64(); err == nil {
			if iv < 0 {
				return 0, fmt.Errorf("illegal_argument_exception: unable to convert [%s] to bytes", ev.String())
			}
			return iv, nil
		}
		return parseIngestByteSize(ev.String())
	default:
		return 0, fmt.Errorf("illegal_argument_exception: field [%s] is not a string or integer byte value", field)
	}
}
