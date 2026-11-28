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
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// Round 61 F29: Bounded Compiled Regex LRU Cache & Pattern Length Guard
// ============================================================================

type esWireError string

func (e esWireError) Error() string { return string(e) }

const (
	maxRegexPatternLen           = 4096
	maxCompiledRegexCacheEntries = 1024
)

type regexLRUEntryRound61 struct {
	key string
	re  *regexp.Regexp
}

type regexLRUCacheRound61 struct {
	mu    sync.Mutex
	ll    *list.List
	items map[string]*list.Element
	cap   int
}

var globalIngestRegexCacheRound61 = &regexLRUCacheRound61{
	ll:    list.New(),
	items: make(map[string]*list.Element, 256),
	cap:   maxCompiledRegexCacheEntries,
}

func getOrCompileCachedIngestRegexRound61(pattern string, compileFn func(string) (*regexp.Regexp, error)) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("illegal_argument_exception: regex pattern length [%d] exceeds maximum [%d]", len(pattern), maxRegexPatternLen)
	}
	globalIngestRegexCacheRound61.mu.Lock()
	if el, ok := globalIngestRegexCacheRound61.items[pattern]; ok {
		globalIngestRegexCacheRound61.ll.MoveToFront(el)
		re := el.Value.(*regexLRUEntryRound61).re
		globalIngestRegexCacheRound61.mu.Unlock()
		return re, nil
	}
	globalIngestRegexCacheRound61.mu.Unlock()

	re, err := compileFn(pattern)
	if err != nil {
		return nil, err
	}

	globalIngestRegexCacheRound61.mu.Lock()
	if el, ok := globalIngestRegexCacheRound61.items[pattern]; ok {
		globalIngestRegexCacheRound61.ll.MoveToFront(el)
		globalIngestRegexCacheRound61.mu.Unlock()
		return el.Value.(*regexLRUEntryRound61).re, nil
	}
	if globalIngestRegexCacheRound61.ll.Len() >= globalIngestRegexCacheRound61.cap {
		if back := globalIngestRegexCacheRound61.ll.Back(); back != nil {
			ev := back.Value.(*regexLRUEntryRound61)
			delete(globalIngestRegexCacheRound61.items, ev.key)
			globalIngestRegexCacheRound61.ll.Remove(back)
		}
	}
	el := globalIngestRegexCacheRound61.ll.PushFront(&regexLRUEntryRound61{key: pattern, re: re})
	globalIngestRegexCacheRound61.items[pattern] = el
	globalIngestRegexCacheRound61.mu.Unlock()
	return re, nil
}

// ============================================================================
// Round 61 F2 & F6: CAT Byte / Time Unit Validation & Formatting + Snapshots
// ============================================================================

func parseCatByteUnitRound61(r *http.Request) (string, float64, error) {
	if r == nil || r.URL == nil || !r.URL.Query().Has("bytes") {
		return "", 1, nil
	}
	raw := strings.TrimSpace(r.URL.Query().Get("bytes"))
	switch strings.ToLower(raw) {
	case "b":
		return "b", 1, nil
	case "k", "kb":
		return "kb", 1024, nil
	case "m", "mb":
		return "mb", 1024 * 1024, nil
	case "g", "gb":
		return "gb", 1024 * 1024 * 1024, nil
	case "t", "tb":
		return "tb", 1024 * 1024 * 1024 * 1024, nil
	case "p", "pb":
		return "pb", 1024 * 1024 * 1024 * 1024 * 1024, nil
	default:
		return "", 0, fmt.Errorf("unable to parse bytes unit [%s]", raw)
	}
}

func formatHumanBytesRound61(bytesVal int64) string {
	if bytesVal <= 0 {
		return "0b"
	}
	const (
		kb = 1024.0
		mb = kb * 1024.0
		gb = mb * 1024.0
		tb = gb * 1024.0
	)
	fv := float64(bytesVal)
	switch {
	case fv >= tb:
		return formatCompactDecimalRound61(fv/tb) + "tb"
	case fv >= gb:
		return formatCompactDecimalRound61(fv/gb) + "gb"
	case fv >= mb:
		return formatCompactDecimalRound61(fv/mb) + "mb"
	case fv >= kb:
		return formatCompactDecimalRound61(fv/kb) + "kb"
	default:
		return strconv.FormatInt(bytesVal, 10) + "b"
	}
}

func formatCompactDecimalRound61(v float64) string {
	if math.Abs(v-math.Round(v)) < 1e-9 {
		return strconv.FormatInt(int64(math.Round(v)), 10)
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", v), "0"), ".")
}

func formatCatBytesValueRound61(bytesVal int64, unit string, div float64) string {
	if unit == "" || div <= 0 {
		return formatHumanBytesRound61(bytesVal)
	}
	scaled := int64(float64(bytesVal) / div)
	return strconv.FormatInt(scaled, 10)
}

func parseCatTimeUnitRound61(r *http.Request) (string, float64, error) {
	if r == nil || r.URL == nil || !r.URL.Query().Has("time") {
		return "", 1, nil
	}
	raw := strings.TrimSpace(r.URL.Query().Get("time"))
	switch raw {
	case "d":
		return "d", float64(24 * time.Hour), nil
	case "h":
		return "h", float64(time.Hour), nil
	case "m":
		return "m", float64(time.Minute), nil
	case "s":
		return "s", float64(time.Second), nil
	case "ms":
		return "ms", float64(time.Millisecond), nil
	case "micros":
		return "micros", float64(time.Microsecond), nil
	case "nanos":
		return "nanos", 1, nil
	default:
		return "", 0, fmt.Errorf("unable to parse time unit [%s]", raw)
	}
}

func formatDurationNanosHumanRound61(nanos int64) string {
	if nanos <= 0 {
		return "0s"
	}
	d := time.Duration(nanos)
	switch {
	case d >= 24*time.Hour:
		return formatCompactDecimalRound61(float64(d)/float64(24*time.Hour)) + "d"
	case d >= time.Hour:
		return formatCompactDecimalRound61(float64(d)/float64(time.Hour)) + "h"
	case d >= time.Minute:
		return formatCompactDecimalRound61(float64(d)/float64(time.Minute)) + "m"
	case d >= time.Second:
		return formatCompactDecimalRound61(float64(d)/float64(time.Second)) + "s"
	case d >= time.Millisecond:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	case d >= time.Microsecond:
		return strconv.FormatInt(d.Microseconds(), 10) + "micros"
	default:
		return strconv.FormatInt(nanos, 10) + "nanos"
	}
}

func formatCatTimeValueRound61(d time.Duration, unit string, div float64) string {
	if unit == "" || div <= 0 {
		return formatDurationNanosHumanRound61(d.Nanoseconds())
	}
	scaled := int64(float64(d.Nanoseconds()) / div)
	return strconv.FormatInt(scaled, 10)
}

func parseESPositiveDurationRound61(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, fmt.Errorf("duration cannot be empty")
	}
	if s == "-1" {
		return 0, nil
	}
	var unit string
	numPart := s
	for _, u := range []string{"nanos", "micros", "ms", "d", "h", "m", "s"} {
		if strings.HasSuffix(s, u) {
			unit = u
			numPart = strings.TrimSuffix(s, u)
			break
		}
	}
	if unit == "" {
		// Bare integer millis in ES time value parsing; reject non-numeric
		iv, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil || iv <= 0 {
			return 0, fmt.Errorf("failed to parse setting with value [%s] as a time value", raw)
		}
		return time.Duration(iv) * time.Millisecond, nil
	}
	fv, err := strconv.ParseFloat(numPart, 64)
	if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) || fv <= 0 {
		return 0, fmt.Errorf("failed to parse setting with value [%s] as a time value", raw)
	}
	var mult time.Duration
	switch unit {
	case "d":
		mult = 24 * time.Hour
	case "h":
		mult = time.Hour
	case "m":
		mult = time.Minute
	case "s":
		mult = time.Second
	case "ms":
		mult = time.Millisecond
	case "micros":
		mult = time.Microsecond
	case "nanos":
		mult = time.Nanosecond
	}
	return time.Duration(fv * float64(mult)), nil
}

func toFloat64Round61(v any) (float64, bool) {
	switch tv := v.(type) {
	case float64:
		return tv, true
	case float32:
		return float64(tv), true
	case int:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case int32:
		return float64(tv), true
	case json.Number:
		f, err := tv.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(tv), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func formatCatDurationNanosRound61(nanos int64, unit string, div float64, defaultStr string) string {
	if unit == "" || div <= 0 {
		if defaultStr != "" {
			return defaultStr
		}
		return formatDurationNanosHumanRound61(nanos)
	}
	scaled := int64(float64(nanos) / div)
	return strconv.FormatInt(scaled, 10)
}

// handleCatSnapshotsRound61 implements `GET /_cat/snapshots` and `GET /_cat/snapshots/{repository}`
// for Wave-2 `server.go` wiring, supporting repo-less requests, wildcards, `ignore_unavailable=true`,
// and `?time=` unit validation.
func (s *Server) handleCatSnapshotsRound61(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	timeUnit, timeDiv, timeErr := parseCatTimeUnitRound61(r)
	if timeErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", timeErr.Error())
		return
	}
	repoPat := strings.TrimSpace(r.PathValue("repository"))
	if repoPat == "" && r != nil && r.URL != nil {
		repoPat = strings.TrimSpace(r.URL.Query().Get("repository"))
	}
	ignoreUnavail := isTruthyBoolQueryParam(r, "ignore_unavailable")

	s.mu.RLock()
	var matchedRepos []string
	if repoPat == "" || repoPat == "*" || repoPat == "_all" {
		for rn := range s.snapshotRepos {
			matchedRepos = append(matchedRepos, rn)
		}
	} else {
		seen := make(map[string]bool)
		for _, part := range strings.Split(repoPat, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if p == "*" || p == "_all" {
				for rn := range s.snapshotRepos {
					if !seen[rn] {
						seen[rn] = true
						matchedRepos = append(matchedRepos, rn)
					}
				}
				continue
			}
			if strings.ContainsAny(p, "*?") {
				for rn := range s.snapshotRepos {
					if matchWildcardPattern(p, rn) && !seen[rn] {
						seen[rn] = true
						matchedRepos = append(matchedRepos, rn)
					}
				}
				continue
			}
			if _, ok := s.snapshotRepos[p]; !ok {
				if ignoreUnavail {
					continue
				}
				s.mu.RUnlock()
				writeESError(w, http.StatusNotFound, "repository_missing_exception", fmt.Sprintf("[%s] missing", p))
				return
			}
			if !seen[p] {
				seen[p] = true
				matchedRepos = append(matchedRepos, p)
			}
		}
	}
	sort.Strings(matchedRepos)
	var rows []map[string]any
	for _, repo := range matchedRepos {
		repoSnaps := s.snapshots[repo]
		snapNames := make([]string, 0, len(repoSnaps))
		for sn := range repoSnaps {
			snapNames = append(snapNames, sn)
		}
		sort.Strings(snapNames)
		for _, sn := range snapNames {
			snap := repoSnaps[sn]
			indicesCount := 0
			if idxList, ok := snap["indices"].([]any); ok {
				indicesCount = len(idxList)
			} else if idxStrs, ok := snap["indices"].([]string); ok {
				indicesCount = len(idxStrs)
			}
			stateStr, _ := snap["state"].(string)
			if stateStr == "" {
				stateStr = "SUCCESS"
			}
			startEpoch, _ := toInt64(snap["start_time_in_millis"])
			endEpoch, _ := toInt64(snap["end_time_in_millis"])
			durMillis, _ := toInt64(snap["duration_in_millis"])
			durStr := fmt.Sprintf("%dms", durMillis)
			if timeUnit != "" {
				durStr = formatCatDurationNanosRound61(durMillis*1_000_000, timeUnit, timeDiv, durStr)
			}
			startTS := "00:00:00"
			endTS := "00:00:00"
			if startEpoch > 0 {
				startTS = time.UnixMilli(startEpoch).UTC().Format("15:04:05")
			}
			if endEpoch > 0 {
				endTS = time.UnixMilli(endEpoch).UTC().Format("15:04:05")
			}
			rows = append(rows, map[string]any{
				"id":                sn,
				"repository":        repo,
				"status":            stateStr,
				"start_epoch":       fmt.Sprintf("%d", startEpoch/1000),
				"start_time":        startTS,
				"end_epoch":         fmt.Sprintf("%d", endEpoch/1000),
				"end_time":          endTS,
				"duration":          durStr,
				"indices":           fmt.Sprintf("%d", indicesCount),
				"successful_shards": fmt.Sprintf("%d", indicesCount),
				"failed_shards":     "0",
				"total_shards":      fmt.Sprintf("%d", indicesCount),
				"reason":            "",
			})
		}
	}
	s.mu.RUnlock()
	defaultCols := []string{"id", "status", "start_epoch", "start_time", "end_epoch", "end_time", "duration", "indices", "successful_shards", "failed_shards", "total_shards"}
	if s.isES8Mode(r) || repoPat == "" || repoPat == "*" || repoPat == "_all" || strings.Contains(repoPat, ",") || strings.ContainsAny(repoPat, "*?") {
		defaultCols = []string{"id", "repository", "status", "start_epoch", "start_time", "end_epoch", "end_time", "duration", "indices", "successful_shards", "failed_shards", "total_shards"}
	}
	helpCols := []string{"id", "repository", "status", "start_epoch", "start_time", "end_epoch", "end_time", "duration", "indices", "successful_shards", "failed_shards", "total_shards", "reason"}
	writeCatResponseWithHelpCols(w, r, defaultCols, helpCols, rows)
}

// ============================================================================
// Round 61 F26: Painless Contexts List, Context Detail, & Score Execution
// ============================================================================

// painlessScriptContextsListRound61 returns the sorted 23-element Painless context list
// matching ES `painless/71_context_api.yml` (`contexts[0] == "aggregation_selector"`,
// `contexts[22] == "update"`).
func painlessScriptContextsListRound61() []string {
	return []string{
		"aggregation_selector",
		"aggs_combine",
		"aggs_init",
		"aggs_map",
		"aggs_reduce",
		"boolean_field",
		"bucket_ks_test",
		"date_field",
		"double_field",
		"enrich",
		"field",
		"filter",
		"geo_point_field",
		"ingest",
		"ip_field",
		"keyword_field",
		"long_field",
		"moving_fn",
		"number_sort",
		"reindex",
		"score",
		"string_sort",
		"update",
	}
}

func isKnownPainlessContextRound61(ctxName string) bool {
	for _, c := range painlessScriptContextsListRound61() {
		if c == ctxName {
			return true
		}
	}
	switch ctxName {
	case "painless_test", "similarity", "similarity_weight", "terms_set", "significant_text", "template", "script_heuristic":
		return true
	}
	return false
}

func buildPainlessContextAPIPayloadRound61(ctxName string) map[string]any {
	classes := []map[string]any{
		{"name": "java.io.PrintStream", "imported": false, "methods": []map[string]any{}},
		{"name": "java.io.Serializable", "imported": false, "methods": []map[string]any{}},
		{"name": "java.lang.AbstractStringBuilder", "imported": false, "methods": []map[string]any{}},
		{"name": "java.lang.ArithmeticException", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.ArrayIndexOutOfBoundsException", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.ArrayStoreException", "imported": true, "methods": []map[string]any{}},
		{
			"name":     "java.lang.Appendable",
			"imported": true,
			"methods": []map[string]any{
				{
					"name":       "append",
					"return":     "java.lang.Appendable",
					"parameters": []string{"java.lang.CharSequence", "int", "int"},
				},
				{
					"name":       "append",
					"return":     "java.lang.Appendable",
					"parameters": []string{"char"},
				},
				{
					"name":       "append",
					"return":     "java.lang.Appendable",
					"parameters": []string{"java.lang.CharSequence"},
				},
			},
		},
		{"name": "java.lang.Boolean", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.Double", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.Long", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.Math", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.Object", "imported": true, "methods": []map[string]any{}},
		{"name": "java.lang.String", "imported": true, "methods": []map[string]any{}},
		{"name": "java.util.List", "imported": true, "methods": []map[string]any{}},
		{"name": "java.util.Map", "imported": true, "methods": []map[string]any{}},
	}
	importedMethods := []map[string]any{}
	classBindings := []map[string]any{}
	if ctxName == "score" {
		importedMethods = []map[string]any{
			{
				"name":       "saturation",
				"return":     "double",
				"parameters": []string{"double", "double"},
			},
			{
				"name":       "sigmoid",
				"return":     "double",
				"parameters": []string{"double", "double", "double"},
			},
			{
				"name":       "randomNotReproducible",
				"return":     "double",
				"parameters": []string{},
			},
		}
		classBindings = []map[string]any{
			{
				"name":       "decayDateExp",
				"return":     "double",
				"parameters": []string{"java.lang.Object", "java.lang.Object", "java.lang.Object", "double", "java.util.List"},
			},
			{
				"name":       "decayDateGauss",
				"return":     "double",
				"parameters": []string{"java.lang.Object", "java.lang.Object", "java.lang.Object", "double", "java.util.List"},
			},
			{
				"name":       "decayDateLinear",
				"return":     "double",
				"parameters": []string{"java.lang.Object", "java.lang.Object", "java.lang.Object", "double", "java.util.List"},
			},
			{
				"name":       "decayNumericExp",
				"return":     "double",
				"parameters": []string{"double", "double", "double", "double", "java.util.List"},
			},
		}
	}
	return map[string]any{
		"name":              ctxName,
		"classes":           classes,
		"imported_methods":  importedMethods,
		"class_bindings":    classBindings,
		"instance_bindings": []any{},
	}
}

// handlePainlessContextDetailRound61 serves `GET /_scripts/painless/_context` and
// `GET /_scripts/painless/_context/{context}` for Wave-2 `server.go` wiring.
func (s *Server) handlePainlessContextDetailRound61(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	ctxName := ""
	if r != nil {
		ctxName = strings.TrimSpace(r.PathValue("context"))
		if ctxName == "" && r.URL != nil {
			ctxName = strings.TrimSpace(r.URL.Query().Get("context"))
		}
	}
	if ctxName == "" || ctxName == "_context" {
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"contexts": painlessScriptContextsListRound61(),
		})
		return
	}
	if !isKnownPainlessContextRound61(ctxName) {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("Unable to find script context [%s] for lang [painless]", ctxName))
		return
	}
	writeJSONWithRequest(w, r, http.StatusOK, buildPainlessContextAPIPayloadRound61(ctxName))
}

// evalTransientDocQueryScoreRound61 computes a deterministic BM25-like relevance `_score`
// for a transient `context_setup.document` against `context_setup.query` in `/_scripts/painless/_execute`.
func evalTransientDocQueryScoreRound61(doc map[string]any, rawQuery any) (float64, error) {
	if rawQuery == nil {
		return 1.0, nil
	}
	qBytes, err := json.Marshal(rawQuery)
	if err != nil {
		return 0, err
	}
	var q esast.Query
	if err := json.Unmarshal(qBytes, &q); err != nil {
		return 0, err
	}
	score, matched := scoreDocAgainstESQueryRound61(doc, &q)
	if !matched {
		return 0.0, nil
	}
	return score, nil
}

func scoreDocAgainstESQueryRound61(doc map[string]any, q *esast.Query) (float64, bool) {
	if q == nil {
		return 1.0, true
	}
	if q.MatchAll != nil {
		boost := 1.0
		if rawBoost, ok := q.MatchAll["boost"]; ok {
			if b, okB := toFloat64Round61(rawBoost); okB {
				boost = b
			}
		}
		return boost, true
	}
	if q.MatchNone != nil {
		return 0.0, false
	}
	if len(q.Term) > 0 {
		for field, te := range q.Term {
			cleanField := strings.TrimSuffix(field, ".keyword")
			val, exists := getIngestPath(doc, cleanField)
			if !exists {
				return 0.0, false
			}
			target := fmt.Sprintf("%v", te.Value)
			if matchDocValueExactOrCI(val, target, te.CaseInsensitive) {
				boost := 1.0
				if te.HasBoost || te.Boost != 0 {
					boost = te.Boost
				}
				return 0.2876821 * boost, true
			}
			return 0.0, false
		}
	}
	if len(q.Match) > 0 {
		for field, me := range q.Match {
			cleanField := strings.TrimSuffix(field, ".keyword")
			val, exists := getIngestPath(doc, cleanField)
			if !exists || val == nil {
				return 0.0, false
			}
			qTokens := tokenizeSimpleStandardRound61(fmt.Sprintf("%v", me.Query))
			if len(qTokens) == 0 {
				return 0.0, false
			}
			docTokens := collectDocTokensRound61(val)
			if len(docTokens) == 0 {
				return 0.0, false
			}
			tfMap := make(map[string]int, len(docTokens))
			for _, dt := range docTokens {
				tfMap[dt]++
			}
			matchedCount := 0
			scoreSum := 0.0
			dl := float64(len(docTokens))
			for _, qt := range qTokens {
				if tf := tfMap[qt]; tf > 0 {
					matchedCount++
					// Single-doc Lucene BM25: idf = ln(1 + (1 - 1 + 0.5)/(1 + 0.5)) = ln(1 + 1/3) = 0.28768207245178085
					idf := math.Log(1.0 + 0.5/1.5)
					k1 := 1.2
					b := 0.75
					avgdl := dl
					normTF := (float64(tf) * (k1 + 1.0)) / (float64(tf) + k1*(1.0-b+b*(dl/avgdl)))
					scoreSum += idf * normTF / (k1 + 1.0) * (k1 + 1.0)
				}
			}
			op := strings.ToLower(strings.TrimSpace(me.Operator))
			if op == "and" && matchedCount < len(qTokens) {
				return 0.0, false
			}
			if matchedCount == 0 {
				return 0.0, false
			}
			boost := 1.0
			if me.HasBoost || me.Boost != 0 {
				boost = me.Boost
			}
			return scoreSum * boost, true
		}
	}
	if len(q.Range) > 0 {
		for field, re := range q.Range {
			cleanField := strings.TrimSuffix(field, ".keyword")
			val, exists := getIngestPath(doc, cleanField)
			if !exists || val == nil {
				return 0.0, false
			}
			if !matchRangeEntryRound61(val, re) {
				return 0.0, false
			}
		}
		return 1.0, true
	}
	if q.Exists != nil && q.Exists.Field != "" {
		val, exists := getIngestPath(doc, strings.TrimSuffix(q.Exists.Field, ".keyword"))
		if !exists || val == nil {
			return 0.0, false
		}
		return 1.0, true
	}
	if q.Bool != nil {
		totalScore := 0.0
		for i := range q.Bool.Must {
			sc, ok := scoreDocAgainstESQueryRound61(doc, &q.Bool.Must[i])
			if !ok {
				return 0.0, false
			}
			totalScore += sc
		}
		for i := range q.Bool.Filter {
			if _, ok := scoreDocAgainstESQueryRound61(doc, &q.Bool.Filter[i]); !ok {
				return 0.0, false
			}
		}
		for i := range q.Bool.MustNot {
			if _, ok := scoreDocAgainstESQueryRound61(doc, &q.Bool.MustNot[i]); ok {
				return 0.0, false
			}
		}
		if len(q.Bool.Should) > 0 {
			matchedShould := 0
			for i := range q.Bool.Should {
				if sc, ok := scoreDocAgainstESQueryRound61(doc, &q.Bool.Should[i]); ok {
					matchedShould++
					totalScore += sc
				}
			}
			needShould := 0
			if len(q.Bool.Must) == 0 && len(q.Bool.Filter) == 0 {
				needShould = 1
			}
			if matchedShould < needShould {
				return 0.0, false
			}
		}
		boost := 1.0
		if q.Bool.Boost != nil {
			boost = *q.Bool.Boost
		}
		return totalScore * boost, true
	}
	if q.ConstantScore != nil {
		if _, ok := scoreDocAgainstESQueryRound61(doc, &q.ConstantScore.Filter); !ok {
			return 0.0, false
		}
		boost := 1.0
		if q.ConstantScore.Boost != nil {
			boost = *q.ConstantScore.Boost
		}
		return boost, true
	}
	return 1.0, true
}

func matchDocValueExactOrCI(val any, target string, ci bool) bool {
	if arr, ok := val.([]any); ok {
		for _, el := range arr {
			if matchDocValueExactOrCI(el, target, ci) {
				return true
			}
		}
		return false
	}
	sv := fmt.Sprintf("%v", val)
	if ci {
		return strings.EqualFold(sv, target)
	}
	return sv == target
}

func tokenizeSimpleStandardRound61(s string) []string {
	var out []string
	var cur strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r > 127 {
			cur.WriteRune(unicode.ToLower(r))
		} else if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func collectDocTokensRound61(val any) []string {
	switch v := val.(type) {
	case string:
		return tokenizeSimpleStandardRound61(v)
	case []any:
		var out []string
		for _, el := range v {
			out = append(out, collectDocTokensRound61(el)...)
		}
		return out
	default:
		return tokenizeSimpleStandardRound61(fmt.Sprintf("%v", val))
	}
}

func matchRangeEntryRound61(val any, re esast.RangeCond) bool {
	gt, gte, lt, lte := re.NormalizedBounds()
	if fv, ok := toFloat64Round61(val); ok {
		if gt != nil {
			if b, okB := toFloat64Round61(gt); okB && !(fv > b) {
				return false
			}
		}
		if gte != nil {
			if b, okB := toFloat64Round61(gte); okB && !(fv >= b) {
				return false
			}
		}
		if lt != nil {
			if b, okB := toFloat64Round61(lt); okB && !(fv < b) {
				return false
			}
		}
		if lte != nil {
			if b, okB := toFloat64Round61(lte); okB && !(fv <= b) {
				return false
			}
		}
		return true
	}
	sv := fmt.Sprintf("%v", val)
	if gt != nil && sv <= fmt.Sprintf("%v", gt) {
		return false
	}
	if gte != nil && sv < fmt.Sprintf("%v", gte) {
		return false
	}
	if lt != nil && sv >= fmt.Sprintf("%v", lt) {
		return false
	}
	if lte != nil && sv > fmt.Sprintf("%v", lte) {
		return false
	}
	return true
}

// ============================================================================
// Round 61 F28: Mustache Truncated JSON Diagnostics + Bulk/Update Validators
// ============================================================================

var knownESQueryTypesRound61 = map[string]bool{
	"match": true, "match_all": true, "match_none": true, "match_phrase": true,
	"match_phrase_prefix": true, "match_bool_prefix": true, "multi_match": true,
	"common": true, "query_string": true, "simple_query_string": true,
	"term": true, "terms": true, "terms_set": true, "range": true, "exists": true,
	"prefix": true, "wildcard": true, "regexp": true, "fuzzy": true, "type": true,
	"ids": true, "bool": true, "boosting": true, "constant_score": true,
	"dis_max": true, "function_score": true, "script_score": true,
	"nested": true, "has_child": true, "has_parent": true, "parent_id": true,
	"geo_bounding_box": true, "geo_distance": true, "geo_polygon": true, "geo_shape": true,
	"shape": true, "intervals": true, "span_term": true, "span_multi": true,
	"span_first": true, "span_near": true, "span_or": true, "span_not": true,
	"span_containing": true, "span_within": true, "span_field_masking": true,
	"more_like_this": true, "wrapper": true, "pinned": true, "percolate": true,
	"rank_feature": true, "distance_feature": true, "script": true, "knn": true,
	"combined_fields": true, "semantic": true, "sparse_vector": true, "rule": true,
}

// classifyInvalidRenderedTemplateJSONRound61 inspects invalid rendered template JSON
// in streaming order so unknown query names before EOF yield `parsing_exception` while
// truncated JSON yields `x_content_e_o_f_exception` (`50_multi_search_template.yml`).
func classifyInvalidRenderedTemplateJSONRound61(raw []byte) (string, string) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
		}
		return "parsing_exception", err.Error()
	}
	if delim, ok := tok.(json.Delim); ok && delim == '{' {
		for dec.More() {
			kTok, kErr := dec.Token()
			if kErr != nil {
				if errors.Is(kErr, io.EOF) || errors.Is(kErr, io.ErrUnexpectedEOF) {
					return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
				}
				return "parsing_exception", kErr.Error()
			}
			key, _ := kTok.(string)
			if key == "query" {
				qOpen, qErr := dec.Token()
				if qErr != nil {
					if errors.Is(qErr, io.EOF) || errors.Is(qErr, io.ErrUnexpectedEOF) {
						return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
					}
					return "parsing_exception", qErr.Error()
				}
				if qDelim, okD := qOpen.(json.Delim); okD && qDelim == '{' && dec.More() {
					qtTok, qtErr := dec.Token()
					if qtErr != nil {
						if errors.Is(qtErr, io.EOF) || errors.Is(qtErr, io.ErrUnexpectedEOF) {
							return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
						}
						return "parsing_exception", qtErr.Error()
					}
					if qType, okS := qtTok.(string); okS && !knownESQueryTypesRound61[qType] {
						return "parsing_exception", fmt.Sprintf("[1:%d] unknown query [%s]", dec.InputOffset(), qType)
					}
				}
			}
			var skip json.RawMessage
			if sErr := dec.Decode(&skip); sErr != nil {
				if errors.Is(sErr, io.EOF) || errors.Is(sErr, io.ErrUnexpectedEOF) || strings.Contains(sErr.Error(), "unexpected EOF") || strings.Contains(sErr.Error(), "unexpected end of JSON input") {
					return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
				}
				return "parsing_exception", sErr.Error()
			}
		}
		if _, endErr := dec.Token(); endErr != nil {
			if errors.Is(endErr, io.EOF) || errors.Is(endErr, io.ErrUnexpectedEOF) {
				return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
			}
			return "parsing_exception", endErr.Error()
		}
	}
	return "x_content_e_o_f_exception", fmt.Sprintf("[1:%d] Unexpected end of file", len(raw)+1)
}

// validateBulkDeprecatedParamsRound61 validates ES 8 removed action metadata keys
// (`_type`, `type` URL param, `_parent`, `parent`, `retry_on_conflict` vs `retryOnConflict`)
// on `/_bulk` for Wave-2 `server.go` wiring (`bulk/60_deprecated.yml`).
func (s *Server) validateBulkDeprecatedParamsRound61(r *http.Request, rawBulk []byte) (int, string, string) {
	isES8 := s == nil || s.isES8Mode(r)
	if !isES8 {
		return 0, "", ""
	}
	if r != nil && r.URL != nil {
		if r.URL.Path != "" && strings.Count(strings.Trim(r.URL.Path, "/"), "/") >= 2 {
			// /{index}/{type}/_bulk removed in ES 8
			segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(segs) == 3 && segs[2] == "_bulk" {
				return http.StatusBadRequest, "illegal_argument_exception",
					"Action/metadata line [1] contains an unknown parameter [_type]"
			}
		}
		if r.URL.Query().Has("type") {
			return http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("request [%s] contains unrecognized parameter: [type]", r.URL.Path)
		}
	}
	rawLines := bytes.Split(rawBulk, []byte{'\n'})
	lineNo := 0
	for i := 0; i < len(rawLines); i++ {
		trimmed := bytes.TrimSpace(rawLines[i])
		if len(trimmed) == 0 {
			continue
		}
		lineNo++
		var actionEnv map[string]map[string]any
		if err := json.Unmarshal(trimmed, &actionEnv); err != nil {
			continue
		}
		for op, meta := range actionEnv {
			for k := range meta {
				switch k {
				case "_index", "_id", "routing", "pipeline", "version", "version_type",
					"if_seq_no", "if_primary_term", "require_alias", "dynamic_templates":
				case "retry_on_conflict":
					if op != "update" {
						return http.StatusBadRequest, "illegal_argument_exception",
							fmt.Sprintf("Action/metadata line [%d] contains an unknown parameter [%s]", lineNo, k)
					}
				default:
					return http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("Action/metadata line [%d] contains an unknown parameter [%s]", lineNo, k)
				}
			}
			if op != "delete" {
				i++
				for i < len(rawLines) && len(bytes.TrimSpace(rawLines[i])) == 0 {
					i++
				}
			}
		}
	}
	return 0, "", ""
}

var allowedUpdateRequestTopFieldsRound61 = []string{
	"doc",
	"doc_as_upsert",
	"script",
	"scripted_upsert",
	"upsert",
	"detect_noop",
	"_source",
}

// validateUpdateRequestUnknownFieldsRound61 validates top-level fields of an ES UpdateRequest
// body (both `POST /{index}/_update/{id}` and `_bulk` `update` payload lines), returning
// `x_content_parse_exception` with `did you mean [...]?` when a close match exists.
func validateUpdateRequestUnknownFieldsRound61(rawBody []byte) (int, string, string) {
	trimmed := bytes.TrimSpace(rawBody)
	if len(trimmed) == 0 {
		return 0, "", ""
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil {
		return 0, "", ""
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return 0, "", ""
	}
	for dec.More() {
		kt, kErr := dec.Token()
		if kErr != nil {
			break
		}
		key, ok := kt.(string)
		if !ok {
			break
		}
		allowed := false
		for _, a := range allowedUpdateRequestTopFieldsRound61 {
			if key == a {
				allowed = true
				break
			}
		}
		if !allowed {
			if suggestion := closestFieldSuggestionRound61(key, allowedUpdateRequestTopFieldsRound61); suggestion != "" {
				return http.StatusBadRequest, "x_content_parse_exception",
					fmt.Sprintf("[UpdateRequest] unknown field [%s], did you mean [%s]?", key, suggestion)
			}
			return http.StatusBadRequest, "x_content_parse_exception",
				fmt.Sprintf("[UpdateRequest] unknown field [%s]", key)
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			break
		}
	}
	return 0, "", ""
}

func closestFieldSuggestionRound61(input string, candidates []string) string {
	best := ""
	bestDist := 999
	for _, c := range candidates {
		d := levenshteinDistanceRound61(strings.ToLower(input), strings.ToLower(c))
		maxAllowed := len(c) / 2
		if maxAllowed < 2 {
			maxAllowed = 2
		}
		if d <= maxAllowed && d < bestDist {
			bestDist = d
			best = c
		}
	}
	return best
}

func levenshteinDistanceRound61(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := 0; j <= len(rb); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

// ============================================================================
// Round 61 F27: Live Ingest Byte Stats, Processor Types, & Write/Bulk Helpers
// ============================================================================

var errIngestCyclicSourceRound61 = errors.New("ingest_cyclic_source_round61")

type ingestProcStatCountersRound61 struct {
	procType     string
	procTag      string
	count        atomic.Int64
	timeInMillis atomic.Int64
	current      atomic.Int64
	failed       atomic.Int64
}

type ingestPipelineStatEntryRound61 struct {
	count                        atomic.Int64
	timeInMillis                 atomic.Int64
	current                      atomic.Int64
	failed                       atomic.Int64
	ingestedInBytes              atomic.Int64
	producedInBytes              atomic.Int64
	ingestedAsFirstPipelineBytes atomic.Int64
	producedAsFirstPipelineBytes atomic.Int64
	producedAsFinalPipelineBytes atomic.Int64
	mu                           sync.RWMutex
	processors                   []*ingestProcStatCountersRound61
}

type serverIngestStatsTrackerRound61 struct {
	totalCount                atomic.Int64
	totalTimeInMillis         atomic.Int64
	totalCurrent              atomic.Int64
	totalFailed               atomic.Int64
	totalIngestedInBytes      atomic.Int64
	totalProducedInBytes      atomic.Int64
	totalIngestedAsFirstBytes atomic.Int64
	totalProducedAsFirstBytes atomic.Int64
	totalProducedAsFinalBytes atomic.Int64
	mu                        sync.RWMutex
	pipelines                 map[string]*ingestPipelineStatEntryRound61
}

var serverIngestStatsRegistryRound61 sync.Map // map[*Server]*serverIngestStatsTrackerRound61

func (s *Server) getOrCreateIngestStatsTrackerRound61() *serverIngestStatsTrackerRound61 {
	if s == nil {
		return &serverIngestStatsTrackerRound61{pipelines: make(map[string]*ingestPipelineStatEntryRound61)}
	}
	if v, ok := serverIngestStatsRegistryRound61.Load(s); ok {
		return v.(*serverIngestStatsTrackerRound61)
	}
	tr := &serverIngestStatsTrackerRound61{
		pipelines: make(map[string]*ingestPipelineStatEntryRound61),
	}
	actual, _ := serverIngestStatsRegistryRound61.LoadOrStore(s, tr)
	return actual.(*serverIngestStatsTrackerRound61)
}

func buildPipelineProcessorStatHoldersRound61(pipe map[string]any) []*ingestProcStatCountersRound61 {
	if pipe == nil {
		return nil
	}
	rawProcs, _ := pipe["processors"].([]any)
	holders := make([]*ingestProcStatCountersRound61, 0, len(rawProcs))
	for _, p := range rawProcs {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		procType, procTag, _, _, _, _ := extractIngestProcessorSpecRound60(pm)
		if procType == "" {
			continue
		}
		holders = append(holders, &ingestProcStatCountersRound61{
			procType: procType,
			procTag:  procTag,
		})
	}
	return holders
}

func (s *Server) resetIngestPipelineStatsRound61(pipelineID string, pipe map[string]any) {
	if s == nil || pipelineID == "" {
		return
	}
	tr := s.getOrCreateIngestStatsTrackerRound61()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if pipe == nil {
		delete(tr.pipelines, pipelineID)
		return
	}
	tr.pipelines[pipelineID] = &ingestPipelineStatEntryRound61{
		processors: buildPipelineProcessorStatHoldersRound61(pipe),
	}
}

func (s *Server) getOrInitPipelineStatEntryRound61(pipelineID string, pipe map[string]any) *ingestPipelineStatEntryRound61 {
	tr := s.getOrCreateIngestStatsTrackerRound61()
	tr.mu.RLock()
	entry := tr.pipelines[pipelineID]
	tr.mu.RUnlock()
	if entry != nil {
		return entry
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if entry = tr.pipelines[pipelineID]; entry != nil {
		return entry
	}
	if pipe == nil && s != nil {
		s.mu.RLock()
		pipe = s.pipelines[pipelineID]
		s.mu.RUnlock()
	}
	entry = &ingestPipelineStatEntryRound61{
		processors: buildPipelineProcessorStatHoldersRound61(pipe),
	}
	tr.pipelines[pipelineID] = entry
	return entry
}

func (s *Server) recordIngestProcessorExecutionStatRound61(pipelineID string, procIdx int, elapsedMillis int64, failed bool) {
	if s == nil || pipelineID == "" || procIdx < 0 {
		return
	}
	entry := s.getOrInitPipelineStatEntryRound61(pipelineID, nil)
	entry.mu.RLock()
	var holder *ingestProcStatCountersRound61
	if procIdx < len(entry.processors) {
		holder = entry.processors[procIdx]
	}
	entry.mu.RUnlock()
	if holder == nil {
		return
	}
	holder.count.Add(1)
	if elapsedMillis > 0 {
		holder.timeInMillis.Add(elapsedMillis)
	}
	if failed {
		holder.failed.Add(1)
	}
}

// ingestProcessorTypes returns the sorted list of supported ingest processor descriptors
// (`[{"type": "append"}, ...]`) for `/_nodes/ingest` in Wave-2 `server.go`.
func (s *Server) ingestProcessorTypes() []map[string]any {
	names := []string{
		"append", "attachment", "bytes", "circle", "community_id", "compact", "convert",
		"copy", "csv", "date", "date_index_name", "dedup", "default", "dissect",
		"dot_expander", "drop", "enrich", "fail", "fingerprint", "foreach", "geo_grid", "geoip",
		"grok", "gsub", "html_strip", "inference", "join", "json", "kv", "lowercase",
		"network_direction", "pipeline", "redact", "registered_domain", "remove",
		"rename", "reroute", "script", "set", "set_security_user", "sort", "split",
		"terminate", "trim", "uppercase", "uri_parts", "urldecode", "urlencode", "user_agent",
	}
	sort.Strings(names)
	out := make([]map[string]any, len(names))
	for i, n := range names {
		out[i] = map[string]any{"type": n}
	}
	return out
}

// buildLiveIngestNodeStats builds the live ES 8 `ingest` stats map for `/_nodes/stats/ingest`
// and `/_info/ingest` (`GET /_cluster/info/ingest`), including byte counters and optional
// human-readable byte/time fields when `human == true`.
func (s *Server) buildLiveIngestNodeStats(human bool) map[string]any {
	tr := s.getOrCreateIngestStatsTrackerRound61()

	if s != nil {
		s.mu.RLock()
		pipeCopy := make(map[string]map[string]any, len(s.pipelines))
		for id, spec := range s.pipelines {
			pipeCopy[id] = spec
		}
		s.mu.RUnlock()
		for id, spec := range pipeCopy {
			_ = s.getOrInitPipelineStatEntryRound61(id, spec)
		}
	}

	totIngBytes := tr.totalIngestedInBytes.Load()
	totProdBytes := tr.totalProducedInBytes.Load()
	totFirstIngBytes := tr.totalIngestedAsFirstBytes.Load()
	totFirstProdBytes := tr.totalProducedAsFirstBytes.Load()
	totFinalProdBytes := tr.totalProducedAsFinalBytes.Load()
	totTimeMillis := tr.totalTimeInMillis.Load()
	totalMap := map[string]any{
		"count":                               tr.totalCount.Load(),
		"time_in_millis":                      totTimeMillis,
		"current":                             tr.totalCurrent.Load(),
		"failed":                              tr.totalFailed.Load(),
		"ingested_in_bytes":                   totIngBytes,
		"produced_in_bytes":                   totProdBytes,
		"ingested_as_first_pipeline_in_bytes": totFirstIngBytes,
		"produced_as_first_pipeline_in_bytes": totFirstProdBytes,
		"produced_as_final_pipeline_in_bytes": totFinalProdBytes,
	}
	if human {
		totalMap["time"] = formatDurationNanosHumanRound61(totTimeMillis * 1_000_000)
		totalMap["ingested"] = formatHumanBytesRound61(totIngBytes)
		totalMap["produced"] = formatHumanBytesRound61(totProdBytes)
		totalMap["ingested_as_first_pipeline"] = formatHumanBytesRound61(totFirstIngBytes)
		totalMap["produced_as_first_pipeline"] = formatHumanBytesRound61(totFirstProdBytes)
		totalMap["produced_as_final_pipeline"] = formatHumanBytesRound61(totFinalProdBytes)
	}

	tr.mu.RLock()
	pipelinesOut := make(map[string]any, len(tr.pipelines))
	for id, entry := range tr.pipelines {
		ingBytes := entry.ingestedInBytes.Load()
		prodBytes := entry.producedInBytes.Load()
		firstIngBytes := entry.ingestedAsFirstPipelineBytes.Load()
		firstProdBytes := entry.producedAsFirstPipelineBytes.Load()
		finalProdBytes := entry.producedAsFinalPipelineBytes.Load()
		tMillis := entry.timeInMillis.Load()

		entry.mu.RLock()
		procsOut := make([]map[string]any, 0, len(entry.processors))
		for _, pHolder := range entry.processors {
			ptMillis := pHolder.timeInMillis.Load()
			st := map[string]any{
				"count":          pHolder.count.Load(),
				"time_in_millis": ptMillis,
				"current":        pHolder.current.Load(),
				"failed":         pHolder.failed.Load(),
			}
			if human {
				st["time"] = formatDurationNanosHumanRound61(ptMillis * 1_000_000)
			}
			pBody := map[string]any{
				"type":  pHolder.procType,
				"stats": st,
			}
			if pHolder.procTag != "" {
				pBody["tag"] = pHolder.procTag
			}
			procsOut = append(procsOut, map[string]any{
				pHolder.procType: pBody,
			})
		}
		entry.mu.RUnlock()

		pm := map[string]any{
			"count":                               entry.count.Load(),
			"time_in_millis":                      tMillis,
			"current":                             entry.current.Load(),
			"failed":                              entry.failed.Load(),
			"ingested_in_bytes":                   ingBytes,
			"produced_in_bytes":                   prodBytes,
			"ingested_as_first_pipeline_in_bytes": firstIngBytes,
			"produced_as_first_pipeline_in_bytes": firstProdBytes,
			"produced_as_final_pipeline_in_bytes": finalProdBytes,
			"processors":                          procsOut,
		}
		if human {
			pm["time"] = formatDurationNanosHumanRound61(tMillis * 1_000_000)
			pm["ingested"] = formatHumanBytesRound61(ingBytes)
			pm["produced"] = formatHumanBytesRound61(prodBytes)
			pm["ingested_as_first_pipeline"] = formatHumanBytesRound61(firstIngBytes)
			pm["produced_as_first_pipeline"] = formatHumanBytesRound61(firstProdBytes)
			pm["produced_as_final_pipeline"] = formatHumanBytesRound61(finalProdBytes)
		}
		pipelinesOut[id] = pm
	}
	tr.mu.RUnlock()

	return map[string]any{
		"total":     totalMap,
		"pipelines": pipelinesOut,
	}
}

func summarizeIngestPipelineMapRound61(pipe map[string]any) map[string]any {
	out := make(map[string]any, 2)
	if pipe == nil {
		return out
	}
	if ver, ok := pipe["version"]; ok {
		out["version"] = ver
	}
	if meta, ok := pipe["_meta"]; ok {
		out["_meta"] = meta
	}
	return out
}

// IngestWriteResultRound61 captures the full post-ingest result for single-doc index/create,
// bulk index/create/upsert, and reindex writes, including ingest-mutated OCC/version metadata.
type IngestWriteResultRound61 struct {
	Doc               json.RawMessage
	TargetIndex       string
	ResolvedWriteIdx  string
	DocID             string
	Routing           string
	Dropped           bool
	ExecutedPipelines []string
	HasVersion        bool
	Version           int64
	VersionType       string
	HasIfSeqNo        bool
	IfSeqNo           int64
	HasIfPrimaryTerm  bool
	IfPrimaryTerm     int64
	DynamicTemplates  map[string]string
}

// applyWritePipelinesFullRound61 runs the full ingest chain (explicit/default pipeline,
// multi-hop `reroute`/dynamic `_index` `default_pipeline` + `final_pipeline`), validates
// post-ingest `require_alias`, and extracts ingest-mutated `_version` / `_if_seq_no` OCC fields.
func (s *Server) applyWritePipelinesFullRound61(
	rawTargetIndex, docID, reqPipeline, defaultPipeline, initialRouting string,
	rawDoc json.RawMessage,
	requireAlias bool,
) (IngestWriteResultRound61, int, string, string) {
	return s.applyWritePipelinesFullWithTypeR67(rawTargetIndex, "", docID, reqPipeline, defaultPipeline, initialRouting, rawDoc, requireAlias)
}

func (s *Server) applyWritePipelinesFullWithTypeR67(
	rawTargetIndex, docType, docID, reqPipeline, defaultPipeline, initialRouting string,
	rawDoc json.RawMessage,
	requireAlias bool,
) (IngestWriteResultRound61, int, string, string) {
	res := IngestWriteResultRound61{
		Doc:         rawDoc,
		TargetIndex: rawTargetIndex,
		DocID:       docID,
		Routing:     initialRouting,
	}
	savedAtt, savedUA, hookErr := s.collectPipelineHooksForWriteRound63(rawTargetIndex, reqPipeline, defaultPipeline, rawDoc)
	if hookErr != nil {
		return res, http.StatusBadRequest, "illegal_argument_exception", cleanIngestErrorReasonRound60(hookErr.Error())
	}
	cur, curIdx, curID, curRouting, dropped, execPipes, ingestMeta, err := s.applyEffectiveAndFinalPipelinesWithMetaAndTypeR67(
		rawTargetIndex, docType, docID, reqPipeline, defaultPipeline, initialRouting, rawDoc,
	)
	res.ExecutedPipelines = execPipes
	if err != nil {
		if errors.Is(err, errIngestCyclicSourceRound61) {
			pipeName := strings.TrimSpace(reqPipeline)
			if len(execPipes) > 0 && execPipes[len(execPipes)-1] != "" {
				pipeName = execPipes[len(execPipes)-1]
			} else if pipeName == "" {
				pipeName = strings.TrimSpace(defaultPipeline)
			}
			errIdx := curIdx
			if errIdx == "" {
				errIdx = rawTargetIndex
			}
			errID := curID
			if errID == "" {
				errID = docID
			}
			if errID == "" {
				errID = "null"
			}
			return res, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Failed to generate the source document for ingest pipeline [%s] for document [%s/%s]", pipeName, errIdx, errID)
		}
		et := "illegal_argument_exception"
		if s != nil {
			et = s.ingestErrorTypeForReqRound60(nil, err)
		}
		return res, http.StatusBadRequest, et, cleanIngestErrorReasonRound60(err.Error())
	}
	res.Doc = s.applyPostIngestEnrichmentsRound63(cur, savedAtt, savedUA)
	if curIdx != "" {
		res.TargetIndex = curIdx
	}
	if curID != "" {
		res.DocID = curID
	}
	res.Routing = curRouting
	res.Dropped = dropped
	if ingestMeta != nil {
		if v, ok := toInt64(ingestMeta["__mutated_version"]); ok {
			res.HasVersion = true
			res.Version = v
		}
		if vt, ok := ingestMeta["__mutated_version_type"].(string); ok && vt != "" {
			res.VersionType = vt
		} else if res.HasVersion && res.Version > 0 {
			res.VersionType = "external"
		}
		if sn, ok := toInt64(ingestMeta["__mutated_if_seq_no"]); ok {
			res.HasIfSeqNo = true
			res.IfSeqNo = sn
		}
		if pt, ok := toInt64(ingestMeta["__mutated_if_primary_term"]); ok {
			res.HasIfPrimaryTerm = true
			res.IfPrimaryTerm = pt
		}
		if dt, ok := ingestMeta["__mutated_dynamic_templates"].(map[string]string); ok && len(dt) > 0 {
			res.DynamicTemplates = dt
		}
	}
	if dropped {
		return res, 0, "", ""
	}
	if stR, etR, erR := s.finalizeReroutedDestinationRound63(rawTargetIndex, &res); stR != 0 || res.Dropped {
		return res, stR, etR, erR
	}
	if requireAlias && s != nil {
		if !s.isAliasOrDataStreamTargetRound61(res.TargetIndex) {
			return res, http.StatusNotFound, "index_not_found_exception",
				fmt.Sprintf("no such alias [%s]", res.TargetIndex)
		}
	}
	if s != nil && res.ResolvedWriteIdx == "" {
		if resolved, _, wErr := s.resolveWriteIndexWithFilter(res.TargetIndex); wErr == nil && resolved != "" {
			res.ResolvedWriteIdx = resolved
		} else {
			res.ResolvedWriteIdx = s.resolveIndexName(res.TargetIndex)
		}
	} else if s == nil {
		res.ResolvedWriteIdx = res.TargetIndex
	}
	return res, 0, "", ""
}

func (s *Server) isAliasOrDataStreamTargetRound61(target string) bool {
	if s == nil || target == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dataStreams[target] != nil {
		return true
	}
	return len(s.aliases[target]) > 0
}

// applyBulkUpsertIngestRound61 executes ingest pipelines on a bulk/update upsert document,
// propagating `drop` (`noop` result) and `fail` / processor errors for Wave-2 `server.go`.
func (s *Server) applyBulkUpsertIngestRound61(
	targetIndex, docID, reqPipeline, routing string,
	upsertDoc json.RawMessage,
	requireAlias bool,
) (IngestWriteResultRound61, int, string, string) {
	res, st, et, er := s.applyWritePipelinesFullRound61(targetIndex, docID, reqPipeline, "", routing, upsertDoc, requireAlias)
	if st != 0 && (et == "fail_processor_exception" || et == "ingest_processor_exception") {
		et = "fail_processor_exception"
		st = http.StatusInternalServerError
	}
	return res, st, et, er
}

// ValidateExplicitPipelineParamRound62 rejects an explicitly supplied empty `?pipeline=` query
// parameter (`ingest/200_default_pipeline.yml`: `pipeline: ""` -> HTTP 400).
func ValidateExplicitPipelineParamRound62(r *http.Request) (int, string, string) {
	if r != nil && r.URL != nil && r.URL.Query().Has("pipeline") {
		if strings.TrimSpace(r.URL.Query().Get("pipeline")) == "" {
			return http.StatusBadRequest, "illegal_argument_exception", "pipeline id must not be empty"
		}
	}
	return 0, "", ""
}

// BulkUpsertDropVersionRound62 returns the ES 8 sentinel `_version: -3` (`Version.DROPPED_BY_INGEST`)
// for an upsert document dropped by an ingest `drop` processor (`ingest/220_drop_processor.yml`).
func BulkUpsertDropVersionRound62() int64 {
	return -3
}

// formatBulkFailedItemWithPipelinesRound61 attaches `executed_pipelines` to a bulk item
// response map (`nil` when no pipeline ran, or `executed` slice when pipelines ran) whenever
// `?list_executed_pipelines=true` is set.
func formatBulkFailedItemWithPipelinesRound61(item map[string]any, listExecuted bool, executed []string) {
	if !listExecuted || item == nil {
		return
	}
	if len(executed) == 0 {
		item["executed_pipelines"] = nil
		return
	}
	item["executed_pipelines"] = executed
}

// ============================================================================
// Round 61 F27: ISO Week-Year (`YYYY`, `ww`, `e`) Formatting Support
// ============================================================================

func isBuiltinNamedESDateFormatRound61(rawFmt string) bool {
	trimmed := strings.TrimSpace(rawFmt)
	if trimmed == "" {
		return true
	}
	if strings.Contains(trimmed, "||") {
		trimmed = strings.TrimSpace(strings.Split(trimmed, "||")[0])
	}
	fl := strings.ToLower(trimmed)
	if validNamedESDateFormatsR61Search[fl] {
		return true
	}
	switch fl {
	case "unix", "unix_ms", "tai64n":
		return true
	}
	for _, pfx := range []string{
		"epoch_", "strict_", "basic_", "iso", "date", "hour", "time", "t_time", "ordinal", "week", "year", "rfc",
	} {
		if strings.HasPrefix(fl, pfx) {
			return true
		}
	}
	return false
}

func isASCIIAlphaNotERound61(b byte) bool {
	return ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) && b != 'e'
}

func formatIngestDateWithWeekYearRound61(t time.Time, rawFmt string) (string, bool) {
	if isBuiltinNamedESDateFormatRound61(rawFmt) {
		return "", false
	}
	if strings.Contains(rawFmt, "||") {
		rawFmt = strings.TrimSpace(strings.Split(rawFmt, "||")[0])
		if isBuiltinNamedESDateFormatRound61(rawFmt) {
			return "", false
		}
	}
	hasUnquotedWeekToken := false
	inQuote := false
	for i := 0; i < len(rawFmt); i++ {
		if rawFmt[i] == '\'' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if rawFmt[i] == 'Y' || rawFmt[i] == 'w' {
			hasUnquotedWeekToken = true
			break
		}
		if rawFmt[i] == 'e' {
			prevAlpha := i > 0 && isASCIIAlphaNotERound61(rawFmt[i-1])
			nextAlpha := i+1 < len(rawFmt) && isASCIIAlphaNotERound61(rawFmt[i+1])
			if !prevAlpha && !nextAlpha {
				hasUnquotedWeekToken = true
				break
			}
		}
	}
	if !hasUnquotedWeekToken {
		return "", false
	}
	isoYear, isoWeek := t.ISOWeek()
	isoDay := int(t.Weekday())
	if isoDay == 0 {
		isoDay = 7
	}
	var out strings.Builder
	for i := 0; i < len(rawFmt); {
		if rawFmt[i] == '\'' {
			if i+1 < len(rawFmt) && rawFmt[i+1] == '\'' {
				out.WriteByte('\'')
				i += 2
				continue
			}
			endQ := strings.IndexByte(rawFmt[i+1:], '\'')
			if endQ < 0 {
				out.WriteString(rawFmt[i+1:])
				break
			}
			out.WriteString(rawFmt[i+1 : i+1+endQ])
			i += endQ + 2
			continue
		}
		ch := rawFmt[i]
		j := i + 1
		for j < len(rawFmt) && rawFmt[j] == ch {
			j++
		}
		count := j - i
		switch ch {
		case 'Y', 'x':
			if count == 2 {
				_, _ = fmt.Fprintf(&out, "%02d", isoYear%100)
			} else {
				_, _ = fmt.Fprintf(&out, "%0*d", count, isoYear)
			}
		case 'w':
			_, _ = fmt.Fprintf(&out, "%0*d", count, isoWeek)
		case 'e':
			_, _ = fmt.Fprintf(&out, "%0*d", count, isoDay)
		default:
			subLayout := convertESDateFormatToGoLayouts(rawFmt[i:j])
			if len(subLayout) > 0 {
				out.WriteString(t.Format(subLayout[0]))
			} else {
				out.WriteString(rawFmt[i:j])
			}
		}
		i = j
	}
	return out.String(), true
}

// ============================================================================
// Round 61 F20, F21, F22, F23: Tasks, UBQ/DBQ Preflight, OCC 409, & Remote Reindex
// ============================================================================

var serverRemoteReindexTransportsRound61 sync.Map     // map[*Server]http.RoundTripper
var serverRemoteReindexSecurityConfigRound62 sync.Map // map[*Server]*remoteReindexSecurityConfigRound62

type remoteReindexSecurityConfigRound62 struct {
	mu              sync.RWMutex
	staticWhitelist string
	hasWhitelist    bool
	allowPrivateIPs bool
	lookupNetIP     func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (s *Server) getOrCreateRemoteReindexSecurityConfigRound62() *remoteReindexSecurityConfigRound62 {
	if s == nil {
		return &remoteReindexSecurityConfigRound62{}
	}
	if v, ok := serverRemoteReindexSecurityConfigRound62.Load(s); ok {
		return v.(*remoteReindexSecurityConfigRound62)
	}
	cfg := &remoteReindexSecurityConfigRound62{}
	actual, _ := serverRemoteReindexSecurityConfigRound62.LoadOrStore(s, cfg)
	return actual.(*remoteReindexSecurityConfigRound62)
}

// SetStaticRemoteReindexWhitelist configures the node-static `reindex.remote.whitelist`
// (`--reindex-remote-whitelist` / `DORIS_ES_REINDEX_REMOTE_WHITELIST`) on `s`.
func (s *Server) SetStaticRemoteReindexWhitelist(whitelist string) {
	if s == nil {
		return
	}
	cfg := s.getOrCreateRemoteReindexSecurityConfigRound62()
	cfg.mu.Lock()
	trimmed := strings.TrimSpace(whitelist)
	cfg.staticWhitelist = trimmed
	cfg.hasWhitelist = trimmed != ""
	cfg.mu.Unlock()
}

func (s *Server) getStaticRemoteReindexWhitelistRound62() (string, bool) {
	if s == nil {
		return "", false
	}
	v, ok := serverRemoteReindexSecurityConfigRound62.Load(s)
	if !ok {
		return "", false
	}
	cfg := v.(*remoteReindexSecurityConfigRound62)
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return cfg.staticWhitelist, cfg.hasWhitelist
}

// SetRemoteReindexAllowPrivateIPs configures whether outbound remote `_reindex` connections
// are allowed to connect to loopback, RFC1918/RFC4193 private, link-local, or CGNAT IPs
// (`--reindex-remote-allow-private` / `DORIS_ES_REINDEX_REMOTE_ALLOW_PRIVATE`, default false).
func (s *Server) SetRemoteReindexAllowPrivateIPs(allow bool) {
	if s == nil {
		return
	}
	cfg := s.getOrCreateRemoteReindexSecurityConfigRound62()
	cfg.mu.Lock()
	cfg.allowPrivateIPs = allow
	cfg.mu.Unlock()
}

func (s *Server) getRemoteReindexAllowPrivateIPsRound62() bool {
	if s == nil {
		return false
	}
	v, ok := serverRemoteReindexSecurityConfigRound62.Load(s)
	if !ok {
		return false
	}
	cfg := v.(*remoteReindexSecurityConfigRound62)
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return cfg.allowPrivateIPs
}

func (s *Server) setRemoteReindexLookupNetIPForTestRound62(fn func(ctx context.Context, network, host string) ([]netip.Addr, error)) {
	if s == nil {
		return
	}
	cfg := s.getOrCreateRemoteReindexSecurityConfigRound62()
	cfg.mu.Lock()
	cfg.lookupNetIP = fn
	cfg.mu.Unlock()
}

func (s *Server) getRemoteReindexLookupNetIPRound62() func(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if s != nil {
		if v, ok := serverRemoteReindexSecurityConfigRound62.Load(s); ok {
			cfg := v.(*remoteReindexSecurityConfigRound62)
			cfg.mu.RLock()
			fn := cfg.lookupNetIP
			cfg.mu.RUnlock()
			if fn != nil {
				return fn
			}
		}
	}
	return net.DefaultResolver.LookupNetIP
}

// SetRemoteReindexTransport configures a custom `http.RoundTripper` for `source.remote`
// reindex requests on `s` (used by unit/integration tests without opening raw sockets).
func (s *Server) SetRemoteReindexTransport(rt http.RoundTripper) {
	if s == nil {
		return
	}
	if rt == nil {
		serverRemoteReindexTransportsRound61.Delete(s)
		return
	}
	serverRemoteReindexTransportsRound61.Store(s, rt)
}

func (s *Server) getRemoteReindexTransportRound61() http.RoundTripper {
	if s == nil {
		return nil
	}
	if v, ok := serverRemoteReindexTransportsRound61.Load(s); ok {
		if rt, okRT := v.(http.RoundTripper); okRT {
			return rt
		}
	}
	return nil
}

func sanitizeWarningHeaderTokenRound64(s string, escapeQuotes bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' || c < 0x20 || c == 0x7f {
			if c == '\t' {
				b.WriteByte(' ')
			}
			continue
		}
		if escapeQuotes && (c == '\\' || c == '"') {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func emitESDeprecationWarningRound61(w http.ResponseWriter, s *Server, r *http.Request, msg string) {
	if w == nil || msg == "" {
		return
	}
	ver := "8.15.5"
	if s != nil {
		ver = s.effectiveClusterESVersionNumber(r)
	}
	cleanVer := sanitizeWarningHeaderTokenRound64(ver, false)
	if cleanVer == "" {
		cleanVer = "8.15.5"
	}
	escapedMsg := sanitizeWarningHeaderTokenRound64(msg, true)
	if escapedMsg == "" {
		return
	}
	hdrVal := fmt.Sprintf(`299 Elasticsearch-%s-doris4x "%s"`, cleanVer, escapedMsg)
	for _, existing := range w.Header().Values("Warning") {
		if existing == hdrVal {
			return
		}
	}
	w.Header().Add("Warning", hdrVal)
}

func (s *Server) hasPersistedTasksRecordsRound62() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	_, hasTasksIdx := s.indices[".tasks"]
	s.mu.RUnlock()
	if hasTasksIdx {
		return true
	}
	reg := s.getTaskRegistry()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	for _, e := range reg.tasks {
		if e == nil {
			continue
		}
		e.mu.Lock()
		done := e.completed
		e.mu.Unlock()
		if done {
			return true
		}
	}
	return false
}

// emitSystemIndexTasksWarningIfNeededRound61 emits the ES deprecation Warning header when
// accessing `.tasks` directly (e.g. `.tasks/_refresh` or `.tasks/_search`) OR via an all-indices
// operation (`rawIndex == ""`, `_all`, `*`) when persisted `.tasks` documents/records exist.
func (s *Server) emitSystemIndexTasksWarningIfNeededRound61(w http.ResponseWriter, r *http.Request, indices []string) {
	const tasksSysWarning = "this request accesses system indices: [.tasks], but in a future major version, direct access to system indices will be prevented by default"
	hasAllOrEmpty := len(indices) == 0
	for _, idx := range indices {
		trimmed := strings.TrimSpace(idx)
		if trimmed == ".tasks" || strings.HasPrefix(trimmed, ".tasks") {
			emitESDeprecationWarningRound61(w, s, r, tasksSysWarning)
			return
		}
		if trimmed == "" || trimmed == "_all" || trimmed == "*" {
			hasAllOrEmpty = true
		}
	}
	if !hasAllOrEmpty || !s.hasPersistedTasksRecordsRound62() {
		return
	}
	includeHidden := true
	if r != nil && r.URL != nil && r.URL.Query().Has("expand_wildcards") {
		ew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("expand_wildcards")))
		includeHidden = strings.Contains(ew, "hidden") || strings.Contains(ew, "all")
	} else if s != nil && r != nil && s.isES8Mode(r) {
		includeHidden = false
	}
	if includeHidden {
		emitESDeprecationWarningRound61(w, s, r, tasksSysWarning)
	}
}

// resolveAutoSlicesForIndicesRound61 sums primary shard counts across `indices` (minimum 1)
// so `slices=auto` resolves shard-aware slice counts for Reindex / UBQ / DBQ.
func (s *Server) resolveAutoSlicesForIndicesRound61(indices []string) int {
	if s == nil || len(indices) == 0 {
		return 1
	}
	totalShards := 0
	for _, idx := range indices {
		sc, _, _ := s.getIndexShardAndReplicaCounts(idx)
		if sc < 1 {
			sc = 1
		}
		totalShards += sc
	}
	if totalShards < 1 {
		return 1
	}
	return totalShards
}

func buildInitialSliceProgressListRound61(slicesCount int, rps float64) []any {
	if slicesCount <= 1 {
		return nil
	}
	return buildByQuerySlicesBreakdown(slicesCount, 0, 0, 0, 0, 0, 0, 0, rps)
}

func populateCompletedSliceStatusesRound61(slicesCount int, total, created, updated, deleted, versionConflicts, noops, batches int64, rps float64) []any {
	if slicesCount <= 1 {
		return nil
	}
	return buildByQuerySlicesBreakdown(slicesCount, int(total), int(updated), int(created), int(deleted), int(versionConflicts), int(noops), int(batches), rps)
}

// withSyncByQueryTaskRound61 registers a synchronous (`wait_for_completion=true`) Reindex/UBQ/DBQ
// task in `s.getTaskRegistry()` so live `_tasks`, `_cat/tasks`, `_rethrottle`, `throttled_millis`, and
// `task.status.slices` work identically for sync and async executions.
func (s *Server) withSyncByQueryTaskRound61(
	r *http.Request,
	action, desc string,
	rps float64,
	slicesCount int,
) (*http.Request, *taskEntry, func(resp map[string]any)) {
	if s == nil || r == nil || taskFromContextRound60(r.Context()) != nil {
		existing := taskFromContextRound60(r.Context())
		if existing != nil && slicesCount > 1 {
			existing.mu.Lock()
			if len(existing.slices) == 0 {
				existing.slices = buildInitialSliceProgressListRound61(slicesCount, rps)
			}
			existing.mu.Unlock()
		}
		return r, existing, func(resp map[string]any) {
			if existing != nil && resp != nil {
				existing.mu.Lock()
				resp["throttled_millis"] = existing.throttledMillis
				effRPS := rps
				if existing.requestsPerSec != 0 {
					effRPS = existing.requestsPerSec
				}
				if slicesCount > 1 {
					tot, _ := toInt64(resp["total"])
					cr, _ := toInt64(resp["created"])
					up, _ := toInt64(resp["updated"])
					del, _ := toInt64(resp["deleted"])
					vc, _ := toInt64(resp["version_conflicts"])
					np, _ := toInt64(resp["noops"])
					bt, _ := toInt64(resp["batches"])
					existing.slices = populateCompletedSliceStatusesRound61(slicesCount, tot, cr, up, del, vc, np, bt, effRPS)
					resp["slices"] = existingSlicesCopyRound61(existing.slices)
				}
				existing.mu.Unlock()
			}
		}
	}
	hdrs := extractTaskHeadersFromRequest(r)
	taskCtx, cancelFn := context.WithCancel(r.Context())
	reg := s.getTaskRegistry()
	entry := reg.register(action, desc, rps, hdrs, cancelFn)
	if slicesCount > 1 {
		entry.mu.Lock()
		entry.slices = buildInitialSliceProgressListRound61(slicesCount, rps)
		entry.mu.Unlock()
	}
	cloned := r.WithContext(context.WithValue(taskCtx, taskEntryContextKey{}, entry))
	finish := func(resp map[string]any) {
		entry.mu.Lock()
		tm := entry.throttledMillis
		effRPS := rps
		if entry.requestsPerSec != 0 {
			effRPS = entry.requestsPerSec
		}
		if resp != nil {
			resp["throttled_millis"] = tm
			if slicesCount > 1 {
				tot, _ := toInt64(resp["total"])
				cr, _ := toInt64(resp["created"])
				up, _ := toInt64(resp["updated"])
				del, _ := toInt64(resp["deleted"])
				vc, _ := toInt64(resp["version_conflicts"])
				np, _ := toInt64(resp["noops"])
				bt, _ := toInt64(resp["batches"])
				entry.slices = populateCompletedSliceStatusesRound61(slicesCount, tot, cr, up, del, vc, np, bt, effRPS)
				resp["slices"] = existingSlicesCopyRound61(entry.slices)
			}
		}
		entry.mu.Unlock()
		entry.markDone(resp, nil)
		reg.unregisterSyncCompleted(entry.fullID)
		cancelFn()
	}
	return cloned, entry, finish
}

func existingSlicesCopyRound61(s []any) []any {
	if len(s) == 0 {
		return nil
	}
	cp := make([]any, len(s))
	copy(cp, s)
	return cp
}

// validateByQueryPreflightWithWarningsRound61 validates UBQ / DBQ request parameters and JSON body
// BEFORE index lookup, emitting RFC 7234 `Warning` headers on deprecated parameters (`size` in ES 7)
// and returning `(rps, slicesCount, isAutoSlices, waitForCompletion, status, errType, errReason)`.
func (s *Server) validateByQueryPreflightWithWarningsRound61(
	w http.ResponseWriter,
	r *http.Request,
	bodyBytes []byte,
	isDeleteByQuery bool,
) (float64, int, bool, bool, int, string, string) {
	isES8 := s == nil || s.isES8Mode(r)
	waitFC := true
	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if q.Has("wait_for_completion") {
			bv, _, bErr := parseStrictQueryBoolParamRound59(r, "wait_for_completion")
			if bErr != nil {
				return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", bErr.Error()
			}
			waitFC = bv
		}
		for _, boolParam := range []string{"allow_no_indices", "ignore_unavailable", "analyze_wildcard", "lowercase_expanded_terms", "lenient"} {
			if q.Has(boolParam) {
				if _, _, bErr := parseStrictQueryBoolParamRound59(r, boolParam); bErr != nil {
					return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", bErr.Error()
				}
			}
		}
		if q.Has("scroll") {
			if _, dErr := parseESPositiveDurationRound61(q.Get("scroll")); dErr != nil {
				return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", dErr.Error()
			}
		}
		if q.Has("timeout") {
			if _, dErr := parseESPositiveDurationRound61(q.Get("timeout")); dErr != nil {
				return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", dErr.Error()
			}
		}
		if q.Has("conflicts") {
			cf := strings.TrimSpace(q.Get("conflicts"))
			if cf != "" && cf != "proceed" && cf != "abort" {
				return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("conflicts may only be \"proceed\" or \"abort\" but was [%s]", cf)
			}
		}
		if q.Has("scroll_size") {
			ss, sErr := strconv.Atoi(strings.TrimSpace(q.Get("scroll_size")))
			if sErr != nil {
				return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Failed to parse int parameter [scroll_size] with value [%s]", q.Get("scroll_size"))
			}
			if ss <= 0 {
				return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("scroll_size cannot be less than or equal to 0, was [%d]", ss)
			}
		}
		if q.Has("from") {
			return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", "from is not supported in this context"
		}
		if q.Has("stored_fields") {
			return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", "stored_fields is not supported in this context"
		}
		if strings.EqualFold(strings.TrimSpace(q.Get("_source")), "false") {
			return 0, 1, false, true, http.StatusBadRequest, "illegal_argument_exception", "_source:false is not supported in this context"
		}
	}

	var rawMap map[string]any
	hasURISearchQuery := r != nil && r.URL != nil && (strings.TrimSpace(r.URL.Query().Get("q")) != "" || strings.TrimSpace(r.URL.Query().Get("df")) != "")
	hasNonEmptyBody := len(bytes.TrimSpace(bodyBytes)) > 0
	if hasNonEmptyBody {
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err != nil {
			return 0, 1, false, waitFC, http.StatusBadRequest, "x_content_parse_exception", err.Error()
		}
	}
	opLabel := "update_by_query"
	if isDeleteByQuery {
		opLabel = "delete_by_query"
	}
	for k := range rawMap {
		switch k {
		case "query", "sort", "_source", "size", "max_docs", "conflicts", "requests_per_second", "slices", "slice", "runtime_mappings", "stats":
		case "script":
			if isDeleteByQuery {
				return 0, 1, false, waitFC, http.StatusBadRequest, "parsing_exception",
					fmt.Sprintf("[%s] unknown field [%s]", opLabel, k)
			}
		case "from":
			return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", "from is not supported in this context"
		case "stored_fields":
			return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", "stored_fields is not supported in this context"
		default:
			return 0, 1, false, waitFC, http.StatusBadRequest, "parsing_exception",
				fmt.Sprintf("[%s] unknown field [%s]", opLabel, k)
		}
	}
	if srcVal, hasSrc := rawMap["_source"]; hasSrc {
		if srcFlag, isBool := srcVal.(bool); isBool && !srcFlag {
			return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", "_source:false is not supported in this context"
		}
		if srcStr, isStr := srcVal.(string); isStr && strings.EqualFold(strings.TrimSpace(srcStr), "false") {
			return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", "_source:false is not supported in this context"
		}
	}
	if !hasNonEmptyBody && isDeleteByQuery && !hasURISearchQuery {
		return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", "Required [body]"
	}
	if isDeleteByQuery && !hasURISearchQuery && (rawMap == nil || rawMap["query"] == nil) {
		return 0, 1, false, waitFC, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: query is missing;"
	}
	if cfRaw, hasCF := rawMap["conflicts"]; hasCF && cfRaw != nil {
		cfStr, ok := cfRaw.(string)
		if !ok || (cfStr != "proceed" && cfStr != "abort") {
			return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("conflicts may only be \"proceed\" or \"abort\" but was [%v]", cfRaw)
		}
	}
	rps, rpsErr := parseRequestsPerSecondStrictRound61(r, rawMap["requests_per_second"])
	if rpsErr != nil {
		return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", rpsErr.Error()
	}
	slicesCount, isAutoSlices, slicesErr := parseSlicesSpecRound61(r, rawMap["slices"])
	if slicesErr != nil {
		return 0, 1, false, waitFC, http.StatusBadRequest, "illegal_argument_exception", slicesErr.Error()
	}
	if _, status, et, er := validateMaxDocsAndSizePreflightRound61(w, s, r, isES8, rawMap, slicesCount, isAutoSlices, true); status != 0 {
		return 0, 1, false, waitFC, status, et, er
	}
	if rawSlice, hasSlice := rawMap["slice"]; hasSlice && rawSlice != nil {
		if status, et, er := validateManualSliceObjectRound61(rawSlice, slicesCount, isAutoSlices); status != 0 {
			return 0, 1, false, waitFC, status, et, er
		}
	}
	return rps, slicesCount, isAutoSlices, waitFC, 0, "", ""
}

func parseRequestsPerSecondStrictRound61(r *http.Request, bodyRPS any) (float64, error) {
	if r != nil && r.URL != nil && r.URL.Query().Has("requests_per_second") {
		raw := strings.TrimSpace(r.URL.Query().Get("requests_per_second"))
		return parseSingleRPSValueStrictRound61(raw)
	}
	if bodyRPS != nil {
		switch v := bodyRPS.(type) {
		case string:
			return parseSingleRPSValueStrictRound61(strings.TrimSpace(v))
		default:
			fv, ok := toFloat64Round61(bodyRPS)
			if !ok || math.IsNaN(fv) || math.IsInf(fv, 0) {
				return 0, esWireError("[requests_per_second] must be a float greater than 0. Use -1 to disable throttling.")
			}
			if fv == -1 || math.IsInf(fv, 1) {
				return -1, nil
			}
			if fv <= 0 {
				return 0, esWireError("[requests_per_second] must be a float greater than 0. Use -1 to disable throttling.")
			}
			return fv, nil
		}
	}
	return -1, nil
}

func parseSingleRPSValueStrictRound61(raw string) (float64, error) {
	if raw == "" || strings.EqualFold(raw, "unlimited") {
		return 0, esWireError("[requests_per_second] must be a float greater than 0. Use -1 to disable throttling.")
	}
	if strings.EqualFold(raw, "infinity") {
		return -1, nil
	}
	fv, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(fv) {
		return 0, esWireError("[requests_per_second] must be a float greater than 0. Use -1 to disable throttling.")
	}
	if math.IsInf(fv, 1) || fv == -1 {
		return -1, nil
	}
	if fv <= 0 {
		return 0, esWireError("[requests_per_second] must be a float greater than 0. Use -1 to disable throttling.")
	}
	return fv, nil
}

func parseSlicesSpecRound61(r *http.Request, bodySlices any) (int, bool, error) {
	parseRaw := func(raw string) (int, bool, error) {
		if raw == "auto" {
			return 1, true, nil
		}
		iv, err := strconv.Atoi(raw)
		if err != nil || iv < 1 {
			return 0, false, fmt.Errorf("[slices] must be a positive integer or the string \"auto\" but was [%s]", raw)
		}
		if iv > 1024 {
			return 0, false, fmt.Errorf("[slices] [%d] cannot be greater than [index.max_slices_per_scroll] [1024]", iv)
		}
		return iv, false, nil
	}
	if r != nil && r.URL != nil && r.URL.Query().Has("slices") {
		return parseRaw(strings.TrimSpace(r.URL.Query().Get("slices")))
	}
	if bodySlices != nil {
		switch v := bodySlices.(type) {
		case string:
			return parseRaw(strings.TrimSpace(v))
		case json.Number:
			iv, err := v.Int64()
			if err != nil || iv < 1 {
				return 0, false, fmt.Errorf("[slices] must be a positive integer or the string \"auto\" but was [%s]", v.String())
			}
			if iv > 1024 {
				return 0, false, fmt.Errorf("[slices] [%d] cannot be greater than [index.max_slices_per_scroll] [1024]", iv)
			}
			return int(iv), false, nil
		default:
			iv, ok := toInt64(bodySlices)
			if !ok || iv < 1 {
				return 0, false, fmt.Errorf("[slices] must be a positive integer or the string \"auto\" but was [%v]", bodySlices)
			}
			if iv > 1024 {
				return 0, false, fmt.Errorf("[slices] [%d] cannot be greater than [index.max_slices_per_scroll] [1024]", iv)
			}
			return int(iv), false, nil
		}
	}
	return 1, false, nil
}

func validateMaxDocsAndSizePreflightRound61(
	w http.ResponseWriter,
	s *Server,
	r *http.Request,
	isES8 bool,
	rawMap map[string]any,
	slicesCount int,
	isAutoSlices bool,
	isByQuery bool,
) (int, int, string, string) {
	var hasVal bool
	var resolved int

	recordCandidate := func(v int) (int, string, string) {
		if v < 0 {
			return http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("[max_docs] parameter cannot be negative, found [%d]", v)
		}
		if v == 0 {
			return http.StatusBadRequest, "illegal_argument_exception",
				"[max_docs] must be >= 1"
		}
		if hasVal && resolved != v {
			return http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("[max_docs] set to two different values [%d] and [%d]", resolved, v)
		}
		hasVal = true
		resolved = v
		return 0, "", ""
	}

	var emitSizeDeprecation bool
	// Check body fields first so body vs URL conflict reports `[body] and [url]` (`20_validation.yml`).
	if rawSize, hasBodySize := rawMap["size"]; hasBodySize && rawSize != nil {
		if isES8 {
			if isByQuery {
				return 0, http.StatusBadRequest, "parsing_exception",
					"Unknown key for a VALUE_NUMBER in [size]."
			}
			return 0, http.StatusBadRequest, "illegal_argument_exception",
				"invalid parameter [size], use [max_docs] instead"
		}
		sv64, ok := toInt64(rawSize)
		if !ok {
			return 0, http.StatusBadRequest, "x_content_parse_exception",
				fmt.Sprintf("For input string: \"%v\"", rawSize)
		}
		emitSizeDeprecation = true
		if st, et, er := recordCandidate(int(sv64)); st != 0 {
			return 0, st, et, er
		}
	}
	if rawMD, hasBodyMD := rawMap["max_docs"]; hasBodyMD && rawMD != nil {
		mv64, ok := toInt64(rawMD)
		if !ok {
			return 0, http.StatusBadRequest, "x_content_parse_exception",
				fmt.Sprintf("For input string: \"%v\"", rawMD)
		}
		if st, et, er := recordCandidate(int(mv64)); st != 0 {
			return 0, st, et, er
		}
	}

	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if q.Has("size") {
			if isES8 {
				if isByQuery {
					return 0, http.StatusBadRequest, "illegal_argument_exception",
						fmt.Sprintf("request [%s] contains unrecognized parameter: [size] -> did you mean [slices]?", r.URL.Path)
				}
				return 0, http.StatusBadRequest, "illegal_argument_exception",
					"invalid parameter [size], use [max_docs] instead"
			}
			sv, err := strconv.Atoi(strings.TrimSpace(q.Get("size")))
			if err != nil {
				return 0, http.StatusBadRequest, "number_format_exception",
					fmt.Sprintf("For input string: \"%s\"", q.Get("size"))
			}
			emitSizeDeprecation = true
			if st, et, er := recordCandidate(sv); st != 0 {
				return 0, st, et, er
			}
		}
		if q.Has("max_docs") {
			mv, err := strconv.Atoi(strings.TrimSpace(q.Get("max_docs")))
			if err != nil {
				return 0, http.StatusBadRequest, "number_format_exception",
					fmt.Sprintf("For input string: \"%s\"", q.Get("max_docs"))
			}
			if st, et, er := recordCandidate(mv); st != 0 {
				return 0, st, et, er
			}
		}
	}

	if hasVal && !isAutoSlices && slicesCount > 1 && resolved < slicesCount {
		return 0, http.StatusBadRequest, "illegal_argument_exception",
			"[max_docs] should be >= [slices]"
	}
	if emitSizeDeprecation {
		emitESDeprecationWarningRound61(w, s, r, "Deprecated field [size] used, expected [max_docs] instead")
	}
	return resolved, 0, "", ""
}

func validateManualSliceObjectRound61(rawSlice any, slicesCount int, isAutoSlices bool) (int, string, string) {
	if slicesCount > 1 || isAutoSlices {
		return http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: can't provide both slices and slice;"
	}
	sm, ok := rawSlice.(map[string]any)
	if !ok {
		return http.StatusBadRequest, "parsing_exception", "[slice] must be an object"
	}
	for k := range sm {
		if k != "id" && k != "max" && k != "field" {
			return http.StatusBadRequest, "parsing_exception", fmt.Sprintf("[slice] unknown field [%s]", k)
		}
	}
	idVal, okID := toInt64(sm["id"])
	maxVal, okMax := toInt64(sm["max"])
	if !okID || !okMax {
		return http.StatusBadRequest, "parsing_exception", "[slice] requires integer [id] and [max]"
	}
	if maxVal <= 1 {
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("[max] must be greater than 1, got [%d]", maxVal)
	}
	if idVal < 0 || idVal >= maxVal {
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("[id] [%d] must be >= 0 and < [max] [%d]", idVal, maxVal)
	}
	return 0, "", ""
}

// extractJSONObjectKeysOrderedRound61 preserves exact JSON field order inside an object
// (needed for `Unsupported fields in [remote]: [foo,bar]`).
func extractJSONObjectKeysOrderedRound61(rawObj []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(rawObj))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		kt, kErr := dec.Token()
		if kErr != nil {
			break
		}
		if ks, ok := kt.(string); ok {
			keys = append(keys, ks)
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			break
		}
	}
	return keys
}

// extractNestedJSONObjectKeysOrderedRound62 extracts the ordered keys of `rawBody[outerKey][innerKey]`
// using a streaming JSON token scan so input key order is preserved verbatim without map randomization.
func extractNestedJSONObjectKeysOrderedRound62(rawBody []byte, outerKey, innerKey string) []string {
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	for dec.More() {
		kt, kErr := dec.Token()
		if kErr != nil {
			return nil
		}
		ks, _ := kt.(string)
		if ks != outerKey {
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return nil
			}
			continue
		}
		var outerRaw json.RawMessage
		if dec.Decode(&outerRaw) != nil {
			return nil
		}
		innerDec := json.NewDecoder(bytes.NewReader(outerRaw))
		iTok, iErr := innerDec.Token()
		if iErr != nil || iTok != json.Delim('{') {
			return nil
		}
		for innerDec.More() {
			ikt, ikErr := innerDec.Token()
			if ikErr != nil {
				return nil
			}
			iks, _ := ikt.(string)
			var valRaw json.RawMessage
			if innerDec.Decode(&valRaw) != nil {
				return nil
			}
			if iks == innerKey {
				return extractJSONObjectKeysOrderedRound61(valRaw)
			}
		}
		return nil
	}
	return nil
}

func validateReindexSourceQueryShapeRound62(rawBody []byte, rawQuery any) (int, string, string) {
	if rawQuery == nil {
		return 0, "", ""
	}
	qMap, ok := rawQuery.(map[string]any)
	if !ok {
		return http.StatusBadRequest, "parsing_exception", "[query] query malformed, must start with start_object"
	}
	ordered := extractNestedJSONObjectKeysOrderedRound62(rawBody, "source", "query")
	if len(ordered) == 0 {
		for k := range qMap {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
	}
	for _, qk := range ordered {
		qv, exists := qMap[qk]
		if !exists {
			continue
		}
		if _, okObj := qv.(map[string]any); !okObj {
			return http.StatusBadRequest, "parsing_exception",
				fmt.Sprintf("[%s] query malformed, no start_object after query name", qk)
		}
	}
	return 0, "", ""
}

// validateReindexPreflightRound61 performs full F20 preflight validation BEFORE index or
// remote whitelist lookup, emitting ES deprecation Warning headers when needed.
func (s *Server) validateReindexPreflightRound61(
	w http.ResponseWriter,
	r *http.Request,
	bodyBytes []byte,
) (float64, int, bool, bool, int, map[string]any, int, string, string) {
	isES8 := s == nil || s.isES8Mode(r)
	waitFC := true
	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if q.Has("wait_for_completion") {
			bv, _, bErr := parseStrictQueryBoolParamRound59(r, "wait_for_completion")
			if bErr != nil {
				return 0, 1, false, true, 0, nil, http.StatusBadRequest, "illegal_argument_exception", bErr.Error()
			}
			waitFC = bv
		}
		if q.Has("scroll") {
			if _, dErr := parseESPositiveDurationRound61(q.Get("scroll")); dErr != nil {
				return 0, 1, false, true, 0, nil, http.StatusBadRequest, "illegal_argument_exception", dErr.Error()
			}
		}
		if q.Has("timeout") {
			if _, dErr := parseESPositiveDurationRound61(q.Get("timeout")); dErr != nil {
				return 0, 1, false, true, 0, nil, http.StatusBadRequest, "illegal_argument_exception", dErr.Error()
			}
		}
		if q.Has("conflicts") {
			cf := strings.TrimSpace(q.Get("conflicts"))
			if cf != "" && cf != "proceed" && cf != "abort" {
				return 0, 1, false, true, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("conflicts may only be \"proceed\" or \"abort\" but was [%s]", cf)
			}
		}
		if q.Has("scroll_size") {
			ss, sErr := strconv.Atoi(strings.TrimSpace(q.Get("scroll_size")))
			if sErr != nil {
				return 0, 1, false, true, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Failed to parse int parameter [scroll_size] with value [%s]", q.Get("scroll_size"))
			}
			if ss <= 0 {
				return 0, 1, false, true, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("scroll_size cannot be less than or equal to 0, was [%d]", ss)
			}
		}
	}

	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: source is missing;2: dest is missing;"
	}
	var rawMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&rawMap); err != nil {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "x_content_parse_exception", err.Error()
	}
	if rawMap == nil {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: source is missing;2: dest is missing;"
	}
	for k := range rawMap {
		switch k {
		case "source", "dest", "conflicts", "size", "max_docs", "script", "requests_per_second", "slices", "slice":
		default:
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "x_content_parse_exception",
				fmt.Sprintf("[reindex] unknown field [%s]", k)
		}
	}
	if cfRaw, hasCF := rawMap["conflicts"]; hasCF && cfRaw != nil {
		cfStr, ok := cfRaw.(string)
		if !ok || (cfStr != "proceed" && cfStr != "abort") {
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("conflicts may only be \"proceed\" or \"abort\" but was [%v]", cfRaw)
		}
	}
	srcObj, hasSrc := rawMap["source"].(map[string]any)
	dstObj, hasDst := rawMap["dest"].(map[string]any)
	var emitSortDeprecation bool
	if hasSrc {
		if rawSort, hasSort := srcObj["sort"]; hasSort && rawSort != nil {
			emitSortDeprecation = true
		}
		for k := range srcObj {
			switch k {
			case "index", "type", "query", "sort", "_source", "size", "remote", "slice", "routing", "runtime_mappings":
			case "from":
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", "from is not supported in this context"
			case "stored_fields":
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", "stored_fields is not supported in this context"
			default:
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "parsing_exception",
					fmt.Sprintf("Unknown key for a START_OBJECT in [%s].", k)
			}
		}
		if srcFlag, isBool := srcObj["_source"].(bool); isBool && !srcFlag {
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", "_source:false is not supported in this context"
		}
		if rawSrcSize, hasSrcSize := srcObj["size"]; hasSrcSize && rawSrcSize != nil {
			var srcBatch int64
			var okInt bool
			switch sv := rawSrcSize.(type) {
			case json.Number:
				if iv, err := sv.Int64(); err == nil {
					srcBatch, okInt = iv, true
				} else {
					return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "number_format_exception",
						fmt.Sprintf("For input string: \"%s\"", sv.String())
				}
			case string:
				iv, err := strconv.ParseInt(strings.TrimSpace(sv), 10, 64)
				if err != nil {
					return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "number_format_exception",
						fmt.Sprintf("For input string: \"%s\"", sv)
				}
				srcBatch, okInt = iv, true
			default:
				srcBatch, okInt = toInt64(rawSrcSize)
			}
			if !okInt {
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "number_format_exception",
					fmt.Sprintf("For input string: \"%v\"", rawSrcSize)
			}
			if srcBatch <= 0 {
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("size cannot be less than or equal to 0, was [%d]", srcBatch)
			}
		}
	}
	if hasDst {
		for k := range dstObj {
			switch k {
			case "index", "type", "version_type", "op_type", "routing", "pipeline":
			default:
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "x_content_parse_exception",
					fmt.Sprintf("[dest] unknown field [%s]", k)
			}
		}
		if opTypeRaw, hasOp := dstObj["op_type"]; hasOp && opTypeRaw != nil {
			opStr, ok := opTypeRaw.(string)
			if !ok || (opStr != "index" && opStr != "create") {
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("op_type must be [index] or [create], found [%v]", opTypeRaw)
			}
		}
		if vtRaw, hasVT := dstObj["version_type"]; hasVT && vtRaw != nil {
			vtStr, ok := vtRaw.(string)
			if !ok || (vtStr != "" && vtStr != "internal" && vtStr != "external" && vtStr != "external_gt" && vtStr != "external_gte" && vtStr != "force") {
				return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("No version type match [%v]", vtRaw)
			}
		}
	}

	rps, rpsErr := parseRequestsPerSecondStrictRound61(r, rawMap["requests_per_second"])
	if rpsErr != nil {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", rpsErr.Error()
	}
	slicesCount, isAutoSlices, slicesErr := parseSlicesSpecRound61(r, rawMap["slices"])
	if slicesErr != nil {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", slicesErr.Error()
	}
	resolvedMaxDocs, mdStatus, mdET, mdER := validateMaxDocsAndSizePreflightRound61(w, s, r, isES8, rawMap, slicesCount, isAutoSlices, false)
	if mdStatus != 0 {
		return 0, 1, false, waitFC, 0, nil, mdStatus, mdET, mdER
	}

	if !hasSrc && !hasDst {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: source is missing;2: dest is missing;"
	}
	if !hasDst {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: dest is missing;"
	}
	dstIndexStr, _ := dstObj["index"].(string)
	if strings.TrimSpace(dstIndexStr) == "" {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: index must be specified;"
	}
	if !hasSrc {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: source is missing;"
	}
	srcIdxPresent := false
	switch v := srcObj["index"].(type) {
	case string:
		srcIdxPresent = strings.TrimSpace(v) != ""
	case []any:
		srcIdxPresent = len(v) > 0
	}
	if !srcIdxPresent {
		return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
			"Validation Failed: 1: source.index is missing;"
	}
	if rawSlice, hasSlice := srcObj["slice"]; hasSlice && rawSlice != nil {
		if st, et, er := validateManualSliceObjectRound61(rawSlice, slicesCount, isAutoSlices); st != 0 {
			return 0, 1, false, waitFC, 0, nil, st, et, er
		}
	}

	var remMap map[string]any
	if rawRem, hasRem := srcObj["remote"]; hasRem && rawRem != nil {
		rm, okR := rawRem.(map[string]any)
		if !okR {
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", "[remote] must be an object"
		}
		if slicesCount > 1 || isAutoSlices || srcObj["slice"] != nil {
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: can't slice a reindex from a remote cluster;"
		}
		hostStr, _ := rm["host"].(string)
		if err := validateRemoteReindexHostSyntaxRound61(hostStr); err != nil {
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception", err.Error()
		}
		orderedKeys := extractNestedJSONObjectKeysOrderedRound62(bodyBytes, "source", "remote")
		if len(orderedKeys) == 0 {
			var rawTop struct {
				Source struct {
					Remote json.RawMessage `json:"remote"`
				} `json:"source"`
			}
			_ = json.Unmarshal(bodyBytes, &rawTop)
			orderedKeys = extractJSONObjectKeysOrderedRound61(rawTop.Source.Remote)
		}
		if len(orderedKeys) == 0 {
			for k := range rm {
				orderedKeys = append(orderedKeys, k)
			}
			sort.Strings(orderedKeys)
		}
		var badRemKeys []string
		for _, rk := range orderedKeys {
			switch rk {
			case "host", "username", "password", "socket_timeout", "connect_timeout", "headers", "ssl":
			default:
				badRemKeys = append(badRemKeys, rk)
			}
		}
		if len(badRemKeys) > 0 {
			badRemKeys = orderReindexRemoteUnknownKeysRound63(orderedKeys, badRemKeys, len(rm))
			return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "illegal_argument_exception",
				"Unsupported fields in [remote]: [" + strings.Join(badRemKeys, ",") + "]"
		}
		for _, toKey := range []string{"socket_timeout", "connect_timeout"} {
			if rawTO, hasTO := rm[toKey]; hasTO && rawTO != nil {
				toStr := strings.TrimSpace(fmt.Sprintf("%v", rawTO))
				if _, toErr := parseESPositiveDurationRound61(toStr); toErr != nil {
					return 0, 1, false, waitFC, 0, nil, http.StatusBadRequest, "number_format_exception",
						fmt.Sprintf("For input string: \"%s\"", toStr)
				}
			}
		}
		if wlSt, wlET, wlER := s.validateReindexRemoteWhitelistRound60(rm); wlSt != 0 {
			return 0, 1, false, waitFC, 0, nil, wlSt, wlET, wlER
		}
		remMap = rm
	}

	if qSt, qET, qER := validateReindexSourceQueryShapeRound62(bodyBytes, srcObj["query"]); qSt != 0 {
		return 0, 1, false, waitFC, 0, nil, qSt, qET, qER
	}

	if emitSortDeprecation {
		emitESDeprecationWarningRound61(w, s, r, "The sort option in reindex is deprecated. Instead consider using query filtering to find the desired subset of data.")
	}
	return rps, slicesCount, isAutoSlices, waitFC, resolvedMaxDocs, remMap, 0, "", ""
}

func validateRemoteReindexHostSyntaxRound61(rawHost string) error {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return fmt.Errorf("[host] is required for remote reindex")
	}
	u, err := url.Parse(rawHost)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("[host] must be of the form [scheme]://[host]:[port], found [%s]", rawHost)
	}
	if u.User != nil {
		return fmt.Errorf("[host] must not include userinfo credentials; use [remote.username] and [remote.password] instead")
	}
	if (u.Path != "" && u.Path != "/") || (u.RawPath != "" && u.RawPath != "/") {
		return fmt.Errorf("[host] must be of the form [scheme]://[host]:[port] without path segments, found [%s]", rawHost)
	}
	hasExplicitPortSep := false
	if strings.HasPrefix(u.Host, "[") {
		if rb := strings.IndexByte(u.Host, ']'); rb >= 0 && rb+1 < len(u.Host) && u.Host[rb+1] == ':' {
			hasExplicitPortSep = true
		}
	} else if strings.Contains(u.Host, ":") {
		hasExplicitPortSep = true
	}
	if hasExplicitPortSep {
		portStr := u.Port()
		if portStr == "" {
			return fmt.Errorf("[host] must be of the form [scheme]://[host]:[port], found [%s]", rawHost)
		}
		if p, pErr := strconv.Atoi(portStr); pErr != nil || p < 0 || p > 65535 {
			return fmt.Errorf("[host] must be of the form [scheme]://[host]:[port], found [%s]", rawHost)
		}
	}
	return nil
}

// checkDestAutoCreateIndexExactRound61 validates `action.auto_create_index` with exact ES
// messages matching `reindex/25_no_auto_create.yml`.
func (s *Server) checkDestAutoCreateIndexExactRound61(destIndex string) (int, string, string) {
	if s == nil {
		return 0, "", ""
	}
	s.mu.RLock()
	rawSetting, hasSetting := s.getClusterSettingStringLocked("action.auto_create_index")
	s.mu.RUnlock()
	rawSetting = strings.TrimSpace(rawSetting)
	if !hasSetting || rawSetting == "" || strings.EqualFold(rawSetting, "true") {
		return 0, "", ""
	}
	if strings.EqualFold(rawSetting, "false") {
		return http.StatusNotFound, "index_not_found_exception",
			fmt.Sprintf("no such index [%s] and [action.auto_create_index] is [false]", destIndex)
	}
	for _, rawToken := range strings.Split(rawSetting, ",") {
		tok := strings.TrimSpace(rawToken)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			pat := strings.TrimPrefix(tok, "-")
			if pat == "*" || matchWildcardPattern(pat, destIndex) {
				return http.StatusNotFound, "index_not_found_exception",
					fmt.Sprintf("no such index [%s] and [action.auto_create_index] contains [%s] which forbids automatic creation of the index", destIndex, tok)
			}
			continue
		}
		pat := strings.TrimPrefix(tok, "+")
		if pat == "*" || matchWildcardPattern(pat, destIndex) {
			return 0, "", ""
		}
	}
	return http.StatusNotFound, "index_not_found_exception",
		fmt.Sprintf("no such index [%s] and [action.auto_create_index] ([%s]) doesn't match", destIndex, rawSetting)
}

// checkSourceStoredCheckRound61 checks if `_source` is disabled on `srcSchema` (`_source.enabled: false`),
// returning ES 7/8 exact error reason `didn't store _source` (`20_validation.yml`).
func (s *Server) checkSourceStoredCheckRound61(r *http.Request, srcIdx, docID string, srcSchema *schema.IndexSchema) (int, string, string) {
	if srcSchema == nil || srcSchema.RawMapping == nil || len(srcSchema.RawMapping.Source) == 0 {
		return 0, "", ""
	}
	enabledVal, ok := srcSchema.RawMapping.Source["enabled"].(bool)
	if ok && !enabledVal {
		if s != nil && !s.isES8Mode(r) {
			return http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("[%s][_doc][%s] didn't store _source", srcIdx, docID)
		}
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("[%s][%s] didn't store _source", srcIdx, docID)
	}
	return 0, "", ""
}

// checkByQueryWaitForActiveShardsRound61 enforces `wait_for_active_shards` on a single-node
// cluster (`1` active primary shard, `0` replicas assigned). When `wait_for_active_shards` requires
// more than 1 active shard copy (e.g. `2` or `all` when `number_of_replicas >= 1`), returns HTTP `503`
// with the ES `ByQuery` status envelope and `unavailable_shards_exception` inside `failures`.
func (s *Server) checkByQueryWaitForActiveShardsRound61(
	r *http.Request,
	targetIndices []string,
	start time.Time,
	rps float64,
	slicesCount int,
) (int, map[string]any) {
	if s == nil || r == nil || r.URL == nil || !r.URL.Query().Has("wait_for_active_shards") {
		return 0, nil
	}
	rawW := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("wait_for_active_shards")))
	if rawW == "" || rawW == "0" || rawW == "1" || rawW == "index-setting" {
		return 0, nil
	}
	for _, idx := range targetIndices {
		_, replicas, _ := s.getIndexShardAndReplicaCounts(idx)
		if replicas < 0 {
			replicas = 0
		}
		totalCopies := 1 + replicas
		var needed int
		if rawW == "all" {
			needed = totalCopies
		} else if iv, err := strconv.Atoi(rawW); err == nil {
			needed = iv
		} else {
			return http.StatusBadRequest, map[string]any{
				"error": map[string]any{
					"root_cause": []map[string]any{{"type": "illegal_argument_exception", "reason": fmt.Sprintf("invalid wait_for_active_shards [%s]", rawW)}},
					"type":       "illegal_argument_exception",
					"reason":     fmt.Sprintf("invalid wait_for_active_shards [%s]", rawW),
				},
				"status": http.StatusBadRequest,
			}
		}
		if needed > 1 {
			timeoutStr := "1m"
			if r != nil && r.URL != nil {
				if qto := strings.TrimSpace(r.URL.Query().Get("timeout")); qto != "" {
					timeoutStr = qto
				}
			}
			causeReason := fmt.Sprintf("[%s][0] Not enough active copies to meet shard count of [%d] (have 1, needed %d). Timeout: [%s], request: [BulkShardRequest [[%s][0]] containing [index {[%s][1], source[n/a, actual length: [2kb], max length: 2kb]}]]", idx, needed, needed, timeoutStr, idx, idx)
			failureItem := map[string]any{
				"index":  idx,
				"shard":  0,
				"node":   taskLocalNodeID,
				"status": http.StatusServiceUnavailable,
				"cause": map[string]any{
					"type":   "unavailable_shards_exception",
					"reason": causeReason,
				},
			}
			resp := map[string]any{
				"took":                   time.Since(start).Milliseconds(),
				"timed_out":              false,
				"total":                  int64(0),
				"updated":                int64(0),
				"created":                int64(0),
				"deleted":                int64(0),
				"batches":                int64(1),
				"version_conflicts":      int64(0),
				"noops":                  int64(0),
				"retries":                map[string]any{"bulk": 0, "search": 0},
				"throttled_millis":       int64(0),
				"requests_per_second":    rps,
				"throttled_until_millis": int64(0),
				"failures":               []any{failureItem},
			}
			if slicesCount > 1 {
				resp["slices"] = populateCompletedSliceStatusesRound61(slicesCount, 0, 0, 0, 0, 0, 0, 1, rps)
			}
			return http.StatusServiceUnavailable, resp
		}
	}
	return 0, nil
}

func indexUUIDForNameRound61(indexName string) string {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(indexName); i++ {
		h ^= uint64(indexName[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("uuid-%016x", h)
}

// buildByQueryConflictFailureItemRound61 builds an ES `version_conflict_engine_exception`
// entry for the `failures` array of a `ByQuery` (`_reindex`, `_update_by_query`, `_delete_by_query`) response.
func (s *Server) buildByQueryConflictFailureItemRound61(r *http.Request, indexName, docID, reason string) map[string]any {
	item := map[string]any{
		"index": indexName,
		"id":    docID,
		"cause": map[string]any{
			"type":       "version_conflict_engine_exception",
			"reason":     reason,
			"index_uuid": indexUUIDForNameRound61(indexName),
			"shard":      "0",
			"index":      indexName,
		},
		"status": http.StatusConflict,
	}
	if s != nil && !s.isES8Mode(r) {
		item["type"] = "_doc"
	}
	return item
}

// writeByQueryConflictResponseRound61 writes the HTTP 409 Conflict ByQuery JSON status report
// (with `failures` and `version_conflicts` — NOT a top-level `error` object!).
func (s *Server) writeByQueryConflictResponseRound61(w http.ResponseWriter, r *http.Request, respMap map[string]any) {
	writeJSONWithRequest(w, r, http.StatusConflict, respMap)
}

// writeByQuerySearchPhaseFailureRound61 formats a search-phase failure (e.g. runtime Painless
// script exception or invalid query) with per-shard `failed_shards` (`35_search_failures.yml`).
func (s *Server) writeByQuerySearchPhaseFailureRound61(w http.ResponseWriter, r *http.Request, indexName string, err error) {
	errMsg := "search phase execution failed"
	if err != nil {
		errMsg = err.Error()
	}
	causeType := "query_shard_exception"
	causeReason := errMsg
	var causedBy map[string]any
	if strings.HasPrefix(errMsg, "all_shards_failed|") {
		parts := strings.SplitN(errMsg, "|", 3)
		if len(parts) == 3 {
			causeType = parts[1]
			innerRaw := parts[2]
			if causeType == "script_exception" {
				if innerRaw == "compile error" {
					causeReason = "compile error"
				} else {
					causeReason = "runtime error"
					innerType, innerReason := classifyInnerScriptExceptionRound60(innerRaw)
					if idx := strings.Index(innerReason, " (java.lang."); idx > 0 && strings.HasSuffix(innerReason, ")") {
						innerReason = innerReason[:idx]
					}
					causedBy = map[string]any{
						"type":   innerType,
						"reason": innerReason,
					}
				}
			} else {
				causeReason = innerRaw
			}
		}
	} else if strings.Contains(errMsg, "script_exception") || strings.Contains(errMsg, "runtime error") || strings.Contains(errMsg, "by zero") {
		causeType = "script_exception"
		causeReason = "runtime error"
		innerType, innerReason := classifyInnerScriptExceptionRound60(errMsg)
		if idx := strings.Index(innerReason, " (java.lang."); idx > 0 && strings.HasSuffix(innerReason, ")") {
			innerReason = innerReason[:idx]
		}
		if strings.Contains(errMsg, "by zero") && innerType == "illegal_argument_exception" {
			innerType = "arithmetic_exception"
		}
		causedBy = map[string]any{
			"type":   innerType,
			"reason": innerReason,
		}
	}
	topReason := "all shards failed"
	if s != nil && indexName != "" {
		if numShards, _, _ := s.getIndexShardAndReplicaCounts(indexName); numShards > 1 {
			topReason = "Partial shards failure"
		}
	}
	reasonMap := map[string]any{
		"type":       causeType,
		"reason":     causeReason,
		"index_uuid": indexUUIDForNameRound61(indexName),
		"index":      indexName,
	}
	if causedBy != nil {
		reasonMap["caused_by"] = causedBy
	}
	shardFailure := map[string]any{
		"shard":  0,
		"index":  indexName,
		"node":   taskLocalNodeID,
		"reason": reasonMap,
	}
	writeJSONWithRequest(w, r, http.StatusBadRequest, map[string]any{
		"error": map[string]any{
			"root_cause": []map[string]any{
				{
					"type":   causeType,
					"reason": causeReason,
				},
			},
			"type":          "search_phase_execution_exception",
			"reason":        topReason,
			"phase":         "query",
			"grouped":       true,
			"failed_shards": []any{shardFailure},
		},
		"status": http.StatusBadRequest,
	})
}

// checkRuntimeQueryScriptWhenZeroSQLHitsRound61 evaluates runtime query scripts against a single
// candidate document in `srcIdx` when SQL pushdown returned 0 rows (e.g. SQL `1 / 0` evaluating to
// `NULL`/false instead of throwing Painless `ArithmeticException: / by zero`).
func (s *Server) checkRuntimeQueryScriptWhenZeroSQLHitsRound61(
	ctx context.Context,
	srcIdx string,
	srcSchema *schema.IndexSchema,
	tr *transpiler.Transpiler,
	aliasFilter, effQuery *esast.Query,
) error {
	if s == nil || tr == nil || effQuery == nil {
		return nil
	}
	one := 1
	probePlan, pErr := tr.BuildSearchPlan(&esast.SearchRequest{
		Query:          aliasFilter,
		Size:           &one,
		TrackTotalHits: false,
		Sort:           esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}}},
	})
	if pErr != nil || probePlan.HitsSQL == "" {
		return nil
	}
	probeHits, qErr := s.backend.QueryHits(ctx, probePlan.HitsSQL)
	if qErr != nil || len(probeHits) == 0 {
		return nil
	}
	h := probeHits[0]
	var rawMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(h.Source))
	dec.UseNumber()
	_ = dec.Decode(&rawMap)
	if rawMap == nil {
		rawMap = make(map[string]any)
	}
	rawMap["__meta_id"] = h.ID
	rawMap["__meta_index"] = srcIdx
	rawMap["__meta_version"] = h.Version
	return checkRuntimeQueryScriptsOnDocRound60(srcSchema, rawMap, effQuery, h.Score)
}

// snapshotIndexDocVersionsRound61 captures point-in-time document versions (`_seq_no` proxy)
// at the start of a `_reindex` / UBQ / DBQ scroll so concurrent writes during execution trigger
// optimistic concurrency (`version_conflict_engine_exception`)!
func (s *Server) snapshotIndexDocVersionsRound61(indices []string) map[string]map[string]int64 {
	snap := make(map[string]map[string]int64, len(indices))
	if s == nil {
		return snap
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, idx := range indices {
		sub := make(map[string]int64)
		for docID, ver := range s.docVersions[idx] {
			sub[docID] = ver
		}
		if unref := s.unrefreshedDocs[idx]; len(unref) > 0 {
			for _, shardMap := range unref {
				for docID, st := range shardMap {
					if !st.existedBefore {
						delete(sub, docID)
					} else {
						sub[docID] = st.prevHit.Version
					}
				}
			}
		}
		snap[idx] = sub
	}
	return snap
}

// snapshotLiveIndexDocVersionsRound61 captures live `s.docVersions[idx][docID]` at the moment
// a scroll starts so concurrent mutations during multi-batch execution can be detected.
func (s *Server) snapshotLiveIndexDocVersionsRound61(indices []string) map[string]map[string]int64 {
	snap := make(map[string]map[string]int64, len(indices))
	if s == nil {
		return snap
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, idx := range indices {
		sub := make(map[string]int64, len(s.docVersions[idx]))
		for docID, ver := range s.docVersions[idx] {
			sub[docID] = ver
		}
		snap[idx] = sub
	}
	return snap
}

// checkByQueryPointInTimeConflictRound61 checks whether `docID` in `indexName` has mutated since
// the refreshed point-in-time snapshot `snapVersions` (via `unrefreshedDocs` or concurrent writes),
// returning the ES `seqNo` optimistic concurrency conflict message (`update_by_query/10_basic.yml`).
func (s *Server) checkByQueryPointInTimeConflictRound61(indexName, docID string, snapVersions map[string]map[string]int64) (bool, string) {
	if s == nil || snapVersions == nil {
		return false, ""
	}
	idxSnap := snapVersions[indexName]
	snapVer, existedAtSnap := idxSnap[docID]
	s.mu.RLock()
	curVer := s.docVersions[indexName][docID]
	curSeq := s.docSeqNos[indexName][docID]
	s.mu.RUnlock()
	if !existedAtSnap || curVer != snapVer {
		reqSeq := snapVer - 1
		if reqSeq < 0 {
			reqSeq = 0
		}
		actualSeq := curSeq
		if actualSeq <= reqSeq {
			actualSeq = reqSeq + 1
		}
		return true, fmt.Sprintf("[%s]: version conflict, required seqNo [%d], primary term [1]. current document has seqNo [%d] and primary term [1]", docID, reqSeq, actualSeq)
	}
	return false, ""
}

// ============================================================================
// Round 61 F23: SSRF-Hardened `source.remote` Reindex HTTP Scroll Client
// ============================================================================

const (
	maxRemoteReindexResponseBytes = 100 << 20 // 100 MiB
	maxRemoteReindexTimeout       = 60 * time.Second
)

var (
	errRemoteReindexSSRFBlockedRound62 = errors.New("remote reindex blocked disallowed IP address")
	cgnatPrefixRound62                 = netip.MustParsePrefix("100.64.0.0/10")
	ipv4ThisNetPrefixRound62           = netip.MustParsePrefix("0.0.0.0/8")
	ipv4ReservedPrefixRound62          = netip.MustParsePrefix("240.0.0.0/4")
)

func isBlockedRemoteReindexIPRound62(rawAddr netip.Addr) bool {
	if !rawAddr.IsValid() {
		return true
	}
	ip := rawAddr.Unmap()
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	if ip.Is4() && (cgnatPrefixRound62.Contains(ip) || ipv4ThisNetPrefixRound62.Contains(ip) || ipv4ReservedPrefixRound62.Contains(ip)) {
		return true
	}
	return false
}

func (s *Server) buildRemoteReindexDialContextRound62(connectTimeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: -1}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		portNum, pErr := strconv.Atoi(port)
		if pErr != nil || portNum <= 0 || portNum > 65535 {
			return nil, fmt.Errorf("invalid remote port")
		}
		cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
		var addrs []netip.Addr
		if literalIP, parseErr := netip.ParseAddr(cleanHost); parseErr == nil {
			addrs = []netip.Addr{literalIP}
		} else {
			lookupFn := s.getRemoteReindexLookupNetIPRound62()
			resolved, lErr := lookupFn(ctx, "ip", cleanHost)
			if lErr != nil {
				return nil, lErr
			}
			addrs = resolved
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no IP addresses resolved")
		}
		allowPrivate := s.getRemoteReindexAllowPrivateIPsRound62()
		validated := make([]netip.Addr, 0, len(addrs))
		for _, rawAddr := range addrs {
			unmapped := rawAddr.Unmap()
			if !allowPrivate && isBlockedRemoteReindexIPRound62(unmapped) {
				return nil, errRemoteReindexSSRFBlockedRound62
			}
			validated = append(validated, unmapped)
		}
		var lastErr error
		for _, ip := range validated {
			conn, dErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dErr == nil {
				return conn, nil
			}
			lastErr = dErr
		}
		return nil, lastErr
	}
}

func isBlockedRemoteReindexHeaderRound62(headerName, headerVal string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(headerName))
	if trimmed == "" || strings.ContainsAny(headerName, "\r\n") || strings.ContainsAny(headerVal, "\r\n") {
		return true
	}
	switch trimmed {
	case "host",
		"authorization",
		"content-length",
		"transfer-encoding",
		"connection",
		"upgrade",
		"proxy-authorization",
		"te",
		"trailer",
		"keep-alive",
		"proxy-authenticate",
		"proxy-connection":
		return true
	default:
		return false
	}
}

func sanitizeRemoteReindexConnectErrorRound62(baseHost string, err error) string {
	safeHost := strings.TrimSpace(baseHost)
	if u, pErr := url.Parse(safeHost); pErr == nil && u.Host != "" {
		safeHost = u.Scheme + "://" + u.Host
	}
	if errors.Is(err, errRemoteReindexSSRFBlockedRound62) {
		return fmt.Sprintf("connect_exception: remote host [%s] resolved to a disallowed non-public IP address", safeHost)
	}
	return fmt.Sprintf("connect_exception: failed to connect to remote host [%s]", safeHost)
}

func (s *Server) buildRemoteReindexHTTPClientRound61(remMap map[string]any) (*http.Client, func()) {
	connectTimeout := 30 * time.Second
	socketTimeout := 30 * time.Second
	if rawCT, ok := remMap["connect_timeout"]; ok && rawCT != nil {
		if d, err := parseESPositiveDurationRound61(strings.TrimSpace(fmt.Sprintf("%v", rawCT))); err == nil {
			connectTimeout = d
		}
	}
	if rawST, ok := remMap["socket_timeout"]; ok && rawST != nil {
		if d, err := parseESPositiveDurationRound61(strings.TrimSpace(fmt.Sprintf("%v", rawST))); err == nil {
			socketTimeout = d
		}
	}
	if connectTimeout > maxRemoteReindexTimeout {
		connectTimeout = maxRemoteReindexTimeout
	}
	if socketTimeout > maxRemoteReindexTimeout {
		socketTimeout = maxRemoteReindexTimeout
	}
	cleanup := func() {}
	rt := s.getRemoteReindexTransportRound61()
	if rt == nil {
		tr := &http.Transport{
			Proxy:                 nil, // SSRF hardening: never route through ambient HTTP_PROXY
			DialContext:           s.buildRemoteReindexDialContextRound62(connectTimeout),
			ResponseHeaderTimeout: socketTimeout,
			TLSHandshakeTimeout:   connectTimeout,
			DisableKeepAlives:     true,
		}
		rt = tr
		cleanup = tr.CloseIdleConnections
	}
	totalTimeout := socketTimeout + connectTimeout
	if socketTimeout < connectTimeout {
		totalTimeout = socketTimeout * 2
	}
	if totalTimeout > 2*maxRemoteReindexTimeout {
		totalTimeout = 2 * maxRemoteReindexTimeout
	}
	return &http.Client{
		Transport: rt,
		Timeout:   totalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, cleanup
}

func convertLegacyParentHitToJoinRound61(srcDoc json.RawMessage, parentID, hitType string, destSchema *schema.IndexSchema) json.RawMessage {
	if parentID == "" || destSchema == nil || destSchema.RawMapping == nil {
		return srcDoc
	}
	var joinFieldName, childRelName string
	for fname, prop := range destSchema.RawMapping.Properties {
		if prop.Type == "join" {
			joinFieldName = fname
			for _, rawChild := range prop.Relations {
				switch cv := rawChild.(type) {
				case string:
					if childRelName == "" || cv == hitType {
						childRelName = cv
					}
				case []any:
					for _, el := range cv {
						if cs, ok := el.(string); ok && (childRelName == "" || cs == hitType) {
							childRelName = cs
						}
					}
				}
			}
			break
		}
	}
	if joinFieldName == "" {
		return srcDoc
	}
	if childRelName == "" {
		childRelName = hitType
		if childRelName == "" || childRelName == "_doc" {
			childRelName = "child"
		}
	}
	var docMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(srcDoc))
	dec.UseNumber()
	if err := dec.Decode(&docMap); err != nil || docMap == nil {
		return srcDoc
	}
	if _, exists := docMap[joinFieldName]; !exists {
		docMap[joinFieldName] = map[string]any{
			"name":   childRelName,
			"parent": parentID,
		}
		if out, err := json.Marshal(docMap); err == nil {
			return out
		}
	}
	return srcDoc
}

// executeRemoteReindexRound61 executes `source.remote` reindexing via HTTP scroll against a
// whitelisted remote cluster (`F23`).
func (s *Server) executeRemoteReindexRound61(
	w http.ResponseWriter,
	r *http.Request,
	start time.Time,
	bodyBytes []byte,
	remMap map[string]any,
	rps float64,
	waitFC bool,
	resolvedMaxDocs int,
) {
	if !waitFC {
		var savedBody []byte
		if len(bodyBytes) > 0 {
			savedBody = append([]byte(nil), bodyBytes...)
		}
		s.launchAsyncTaskRound60(w, r, savedBody, "indices:data/write/reindex", "reindex from remote", rps, func(rec http.ResponseWriter, bgReq *http.Request) {
			s.executeRemoteReindexRound61(rec, bgReq, time.Now(), savedBody, remMap, rps, true, resolvedMaxDocs)
		})
		return
	}

	var parsed struct {
		Conflicts string `json:"conflicts,omitempty"`
		Source    struct {
			Index   any          `json:"index"`
			Query   *esast.Query `json:"query,omitempty"`
			Source  any          `json:"_source,omitempty"`
			Size    *int         `json:"size,omitempty"`
			Routing string       `json:"routing,omitempty"`
		} `json:"source"`
		Dest struct {
			Index       string `json:"index"`
			OpType      string `json:"op_type,omitempty"`
			VersionType string `json:"version_type,omitempty"`
			Routing     string `json:"routing,omitempty"`
			Pipeline    string `json:"pipeline,omitempty"`
		} `json:"dest"`
		Script *painless.ScriptSpec `json:"script,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		writeESError(w, http.StatusBadRequest, "x_content_parse_exception", err.Error())
		return
	}
	s.resolvePainlessScriptSpecFromRaw(&parsed.Script, bodyBytes)

	rawDestIndex := strings.TrimSpace(parsed.Dest.Index)
	destIndex, _, destWriteErr := s.resolveWriteIndexWithFilter(rawDestIndex)
	if destWriteErr != nil {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", destWriteErr.Error())
		return
	}
	if destIndex == "" {
		destIndex = s.resolveIndexName(rawDestIndex)
	}
	s.mu.RLock()
	_, destExisted := s.indices[destIndex]
	destClosed := s.closedIndices[destIndex]
	s.mu.RUnlock()
	if destClosed {
		writeESError(w, http.StatusBadRequest, "index_closed_exception", fmt.Sprintf("closed [%s]", destIndex))
		return
	}
	if !destExisted {
		if st, et, er := s.checkDestAutoCreateIndexExactRound61(destIndex); st != 0 {
			writeESError(w, st, et, er)
			return
		}
	}

	var srcIndices []string
	switch v := parsed.Source.Index.(type) {
	case string:
		for _, p := range strings.Split(v, ",") {
			if t := strings.TrimSpace(p); t != "" {
				srcIndices = append(srcIndices, t)
			}
		}
	case []any:
		for _, item := range v {
			if sv, ok := item.(string); ok && strings.TrimSpace(sv) != "" {
				srcIndices = append(srcIndices, strings.TrimSpace(sv))
			}
		}
	}
	remoteIndexPath := url.PathEscape(strings.Join(srcIndices, ","))
	baseHost := strings.TrimRight(strings.TrimSpace(fmt.Sprintf("%v", remMap["host"])), "/")
	username, _ := remMap["username"].(string)
	password, _ := remMap["password"].(string)
	customHdrs, _ := remMap["headers"].(map[string]any)

	batchSize := 1000
	if parsed.Source.Size != nil && *parsed.Source.Size > 0 {
		batchSize = *parsed.Source.Size
	}
	if resolvedMaxDocs > 0 && resolvedMaxDocs < batchSize {
		batchSize = resolvedMaxDocs
	}

	client, closeTransport := s.buildRemoteReindexHTTPClientRound61(remMap)
	defer closeTransport()
	doRemoteJSON := func(method, fullURL string, reqPayload any) (int, map[string]any, error) {
		var bodyReader io.Reader
		if reqPayload != nil {
			b, err := json.Marshal(reqPayload)
			if err != nil {
				return 0, nil, err
			}
			bodyReader = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(r.Context(), method, fullURL, bodyReader)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if username != "" || password != "" {
			req.SetBasicAuth(username, password)
		}
		for hk, hv := range customHdrs {
			valStr := fmt.Sprintf("%v", hv)
			if isBlockedRemoteReindexHeaderRound62(hk, valStr) {
				continue
			}
			req.Header.Set(hk, valStr)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return resp.StatusCode, nil, fmt.Errorf("remote redirect status [%d] is not allowed", resp.StatusCode)
		}
		respBytes, rErr := io.ReadAll(io.LimitReader(resp.Body, maxRemoteReindexResponseBytes+1))
		if rErr != nil {
			return resp.StatusCode, nil, rErr
		}
		if len(respBytes) > maxRemoteReindexResponseBytes {
			return resp.StatusCode, nil, fmt.Errorf("remote response exceeded maximum size [%d]", maxRemoteReindexResponseBytes)
		}
		var out map[string]any
		if len(bytes.TrimSpace(respBytes)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(respBytes))
			dec.UseNumber()
			if dErr := dec.Decode(&out); dErr != nil {
				return resp.StatusCode, nil, dErr
			}
		}
		return resp.StatusCode, out, nil
	}

	searchBody := map[string]any{
		"size": batchSize,
		"sort": []any{"_doc"},
	}
	if parsed.Source.Query != nil {
		searchBody["query"] = parsed.Source.Query
	}
	if parsed.Source.Source != nil {
		searchBody["_source"] = parsed.Source.Source
	}
	searchURL := fmt.Sprintf("%s/%s/_search?scroll=5m&version=true", baseHost, remoteIndexPath)
	if parsed.Source.Routing != "" {
		searchURL += "&routing=" + url.QueryEscape(parsed.Source.Routing)
	}

	r, taskEntry, finishSyncTask := s.withSyncByQueryTaskRound61(r, "indices:data/write/reindex", "reindex from remote", rps, 1)
	defer func() {
		if taskEntry != nil {
			select {
			case <-taskEntry.doneCh:
			default:
				finishSyncTask(nil)
			}
		}
	}()

	statusCode, pageMap, netErr := doRemoteJSON(http.MethodPost, searchURL, searchBody)
	if netErr != nil {
		writeESError(w, http.StatusInternalServerError, "connect_exception", sanitizeRemoteReindexConnectErrorRound62(baseHost, netErr))
		return
	}
	if statusCode >= 400 {
		errType := "illegal_argument_exception"
		errReason := fmt.Sprintf("remote returned HTTP %d", statusCode)
		if errObj, ok := pageMap["error"].(map[string]any); ok {
			if et, okS := errObj["type"].(string); okS && et != "" {
				errType = et
			}
			if er, okS := errObj["reason"].(string); okS && er != "" {
				errReason = er
			}
		}
		writeESError(w, statusCode, errType, errReason)
		return
	}

	scrollID, _ := pageMap["_scroll_id"].(string)
	defer func() {
		if scrollID != "" {
			clearCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			b, _ := json.Marshal(map[string]any{"scroll_id": scrollID})
			if req, err := http.NewRequestWithContext(clearCtx, http.MethodDelete, baseHost+"/_search/scroll", bytes.NewReader(b)); err == nil {
				req.Header.Set("Content-Type", "application/json")
				if username != "" || password != "" {
					req.SetBasicAuth(username, password)
				}
				if resp, err := client.Do(req); err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}
		}
	}()

	proceedOnConflict := parsed.Conflicts == "proceed" || r.URL.Query().Get("conflicts") == "proceed"
	var destSchema *schema.IndexSchema
	getDestSchema := func(targetIdx string) *schema.IndexSchema {
		if targetIdx == destIndex {
			if destSchema == nil {
				destSchema = s.ensureWritableIndexSchema(r.Context(), destIndex)
			}
			return destSchema
		}
		return s.ensureWritableIndexSchema(r.Context(), targetIdx)
	}

	var totalMatched, totalCreated, totalUpdated, totalDeleted, totalNoops, totalConflicts, batches int64
	var failures []any

	for {
		hitsEnv, _ := pageMap["hits"].(map[string]any)
		rawHits, _ := hitsEnv["hits"].([]any)
		if len(rawHits) == 0 {
			break
		}
		batches++
		var bufByDest map[string]*bytes.Buffer
		batchDocs := 0
		stopLoop := false

		for _, item := range rawHits {
			if resolvedMaxDocs > 0 && totalMatched >= int64(resolvedMaxDocs) {
				stopLoop = true
				break
			}
			hm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			totalMatched++
			batchDocs++

			docID, _ := hm["_id"].(string)
			hitType, _ := hm["_type"].(string)
			parentID, _ := hm["_parent"].(string)
			if parentID == "" {
				if fMap, okF := hm["fields"].(map[string]any); okF {
					if pv, okP := fMap["_parent"]; okP && pv != nil {
						parentID = fmt.Sprintf("%v", pv)
					}
				}
			}
			srcRouting, _ := hm["_routing"].(string)
			if srcRouting == "" && parentID != "" {
				srcRouting = parentID
			}
			srcVer, _ := toInt64(hm["_version"])
			if srcVer <= 0 {
				srcVer = 1
			}
			rawSrcBytes, _ := json.Marshal(hm["_source"])
			if hm["_source"] == nil {
				rawSrcBytes = []byte("{}")
			}

			opRes := "index"
			curDoc := json.RawMessage(rawSrcBytes)
			targetIdx := destIndex
			targetID := docID
			effRouting := srcRouting
			switch parsed.Dest.Routing {
			case "discard":
				effRouting = ""
			case "", "keep":
			default:
				if strings.HasPrefix(parsed.Dest.Routing, "=") {
					effRouting = strings.TrimPrefix(parsed.Dest.Routing, "=")
				} else {
					effRouting = parsed.Dest.Routing
				}
			}

			if parsed.Script != nil && parsed.Script.Source != "" {
				updSpec := &painless.UpdateRequest{
					Script:            parsed.Script,
					AllowMetaMutation: true,
					MetaID:            targetID,
					MetaIndex:         targetIdx,
					MetaRouting:       effRouting,
					MetaVersion:       srcVer,
					MetaOp:            "index",
				}
				if parsed.Dest.OpType == "create" {
					updSpec.MetaOp = "create"
				}
				mutatedDoc, scOp, scErr := painless.ApplyUpdateWithResult(curDoc, updSpec, true)
				if scErr != nil {
					writeESError(w, http.StatusBadRequest, updateScriptErrorType(scErr), scErr.Error())
					return
				}
				switch scOp {
				case "noop":
					opRes = "noop"
				case "deleted":
					opRes = "delete"
				default:
					curDoc = mutatedDoc
				}
				if sIdx := strings.TrimSpace(updSpec.MetaIndex); sIdx != "" {
					targetIdx = sIdx
				}
				if updSpec.MetaID != "" {
					targetID = updSpec.MetaID
				} else {
					targetID = esast.NextAutoID()
				}
				effRouting = updSpec.MetaRouting
			}

			switch opRes {
			case "noop":
				totalNoops++
				continue
			case "delete":
				tSchema := getDestSchema(targetIdx)
				delVer := srcVer + 1
				delRow, err := schema.ShredDocument(tSchema, targetID, delVer, true, json.RawMessage(`{}`))
				if err == nil {
					seqNo := s.allocIndexSeqNo(r.Context(), targetIdx)
					_ = s.streamLoad(r.Context(), tSchema.DorisTable, append(delRow, '\n'), true)
					s.setDocRouting(targetIdx, targetID, "")
					s.recordDocDeleteMetaRound60(targetIdx, targetID, delVer, seqNo, false)
					totalDeleted++
				}
				continue
			}

			ingRes, ingSt, ingET, ingER := s.applyWritePipelinesFullRound61(targetIdx, targetID, parsed.Dest.Pipeline, "", effRouting, curDoc, false)
			if ingSt != 0 {
				writeESError(w, ingSt, ingET, ingER)
				return
			}
			if ingRes.Dropped {
				totalNoops++
				continue
			}
			targetIdx = ingRes.ResolvedWriteIdx
			targetID = ingRes.DocID
			effRouting = ingRes.Routing
			curDoc = ingRes.Doc

			tSchema := getDestSchema(targetIdx)
			if parentID != "" {
				curDoc = convertLegacyParentHitToJoinRound61(curDoc, parentID, hitType, tSchema)
			}

			s.mu.RLock()
			curVer := s.docVersions[targetIdx][targetID]
			s.mu.RUnlock()
			existed := curVer > 0
			if parsed.Dest.OpType == "create" && existed {
				totalConflicts++
				if !proceedOnConflict {
					fItem := s.buildByQueryConflictFailureItemRound61(r, targetIdx, targetID,
						fmt.Sprintf("[%s]: version conflict, document already exists (current version [%d])", targetID, curVer))
					failures = append(failures, fItem)
					resp := map[string]any{
						"took":                   time.Since(start).Milliseconds(),
						"timed_out":              false,
						"total":                  totalMatched,
						"updated":                totalUpdated,
						"created":                totalCreated,
						"deleted":                totalDeleted,
						"batches":                batches,
						"version_conflicts":      totalConflicts,
						"noops":                  totalNoops,
						"retries":                map[string]any{"bulk": 0, "search": 0},
						"throttled_millis":       int64(0),
						"requests_per_second":    rps,
						"throttled_until_millis": int64(0),
						"failures":               failures,
					}
					finishSyncTask(resp)
					s.writeByQueryConflictResponseRound61(w, r, resp)
					return
				}
				continue
			}

			nextVer := curVer + 1
			if parsed.Dest.VersionType == "external" || parsed.Dest.VersionType == "external_gte" {
				if (parsed.Dest.VersionType == "external" && srcVer <= curVer) || (parsed.Dest.VersionType == "external_gte" && srcVer < curVer) {
					totalConflicts++
					if !proceedOnConflict {
						fItem := s.buildByQueryConflictFailureItemRound61(r, targetIdx, targetID,
							fmt.Sprintf("[%s]: version conflict, current version [%d] is higher or equal to the one provided [%d]", targetID, curVer, srcVer))
						failures = append(failures, fItem)
						resp := map[string]any{
							"took":                   time.Since(start).Milliseconds(),
							"timed_out":              false,
							"total":                  totalMatched,
							"updated":                totalUpdated,
							"created":                totalCreated,
							"deleted":                totalDeleted,
							"batches":                batches,
							"version_conflicts":      totalConflicts,
							"noops":                  totalNoops,
							"retries":                map[string]any{"bulk": 0, "search": 0},
							"throttled_millis":       int64(0),
							"requests_per_second":    rps,
							"throttled_until_millis": int64(0),
							"failures":               failures,
						}
						finishSyncTask(resp)
						s.writeByQueryConflictResponseRound61(w, r, resp)
						return
					}
					continue
				}
				nextVer = srcVer
			}

			shredded, sErr := schema.ShredDocument(tSchema, targetID, nextVer, false, curDoc)
			if sErr != nil {
				writeESError(w, http.StatusBadRequest, shredErrorType(sErr), sErr.Error())
				return
			}
			if bufByDest == nil {
				bufByDest = make(map[string]*bytes.Buffer)
			}
			b := bufByDest[targetIdx]
			if b == nil {
				b = &bytes.Buffer{}
				bufByDest[targetIdx] = b
			}
			b.Write(shredded)
			b.WriteByte('\n')
			seqNo := s.allocIndexSeqNo(r.Context(), targetIdx)
			s.setDocRouting(targetIdx, targetID, effRouting)
			s.recordDocWriteMetaRound60(targetIdx, targetID, nextVer, seqNo)
			if existed {
				totalUpdated++
			} else {
				totalCreated++
			}
		}

		for tIdx, b := range bufByDest {
			if b.Len() > 0 {
				tSchema := getDestSchema(tIdx)
				if err := s.streamLoad(r.Context(), tSchema.DorisTable, b.Bytes(), true); err != nil {
					writeESError(w, http.StatusInternalServerError, "doris_stream_load_exception", err.Error())
					return
				}
			}
		}

		if tEntry := taskFromContextRound60(r.Context()); tEntry != nil {
			tEntry.mu.Lock()
			tEntry.total = int(totalMatched)
			tEntry.created = int(totalCreated)
			tEntry.updated = int(totalUpdated)
			tEntry.deleted = int(totalDeleted)
			tEntry.versionConflicts = int(totalConflicts)
			tEntry.noops = int(totalNoops)
			tEntry.mu.Unlock()
		}
		if err := applyTaskThrottleAndProgressRound60(r.Context(), batchDocs, rps); err != nil {
			writeESError(w, http.StatusInternalServerError, "task_cancelled_exception", "reindex task cancelled")
			return
		}
		if stopLoop || scrollID == "" || len(rawHits) < batchSize || (resolvedMaxDocs > 0 && totalMatched >= int64(resolvedMaxDocs)) {
			break
		}
		scCode, nextMap, scNetErr := doRemoteJSON(http.MethodPost, baseHost+"/_search/scroll", map[string]any{
			"scroll":    "5m",
			"scroll_id": scrollID,
		})
		if scNetErr != nil {
			writeESError(w, http.StatusInternalServerError, "connect_exception", sanitizeRemoteReindexConnectErrorRound62(baseHost, scNetErr))
			return
		}
		if scCode >= 400 {
			writeESError(w, scCode, "search_phase_execution_exception", "remote scroll failed")
			return
		}
		if nextID, ok := nextMap["_scroll_id"].(string); ok && nextID != "" {
			scrollID = nextID
		}
		pageMap = nextMap
	}

	if destSchema == nil && !destExisted && totalMatched == 0 {
		destSchema = s.ensureWritableIndexSchema(r.Context(), destIndex)
	}
	s.queryCache.InvalidateAll()
	if failures == nil {
		failures = []any{}
	}
	resp := map[string]any{
		"took":                   time.Since(start).Milliseconds(),
		"timed_out":              false,
		"total":                  totalMatched,
		"updated":                totalUpdated,
		"created":                totalCreated,
		"deleted":                totalDeleted,
		"batches":                batches,
		"version_conflicts":      totalConflicts,
		"noops":                  totalNoops,
		"retries":                map[string]any{"bulk": 0, "search": 0},
		"throttled_millis":       int64(0),
		"requests_per_second":    rps,
		"throttled_until_millis": int64(0),
		"failures":               failures,
	}
	finishSyncTask(resp)
	writeJSONWithRequest(w, r, http.StatusOK, resp)
}
