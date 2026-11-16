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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// formatJavaDoubleRound60 formats a float64 matching Java Double.toString(double),
// ensuring finite whole numbers carry a trailing ".0" (e.g. -9.0 -> "-9.0", 1.0 -> "1.0").
func formatJavaDoubleRound60(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "Infinity"
	}
	if math.IsInf(v, -1) {
		return "-Infinity"
	}
	abs := math.Abs(v)
	if abs == 0 || (abs >= 1e-3 && abs < 1e7) {
		s := strconv.FormatFloat(v, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	s := strconv.FormatFloat(v, 'E', -1, 64)
	if idx := strings.IndexByte(s, 'E'); idx > 0 {
		mant := s[:idx]
		exp := s[idx+1:]
		exp = strings.TrimPrefix(exp, "+")
		if strings.HasPrefix(exp, "-0") && len(exp) > 2 {
			exp = "-" + strings.TrimLeft(exp[1:], "0")
		} else if strings.HasPrefix(exp, "0") && len(exp) > 1 {
			exp = strings.TrimLeft(exp, "0")
		}
		if exp == "" || exp == "-" {
			exp += "0"
		}
		if !strings.Contains(mant, ".") {
			mant += ".0"
		}
		return mant + "E" + exp
	}
	return s
}

func formatTermsScriptScalarKeyRound60(el any, tSpec *esast.TermsAggSpec, hasFieldBinding bool, fieldBinding schema.FieldBinding) string {
	if el == nil {
		return ""
	}
	vt := ""
	if tSpec != nil {
		vt = strings.ToLower(strings.TrimSpace(tSpec.ValueType))
	}
	wantsInteger := vt == "long" || vt == "integer" || vt == "short" || vt == "byte" || vt == "unsigned_long" || vt == "date"
	if !wantsInteger && vt == "" && tSpec != nil && tSpec.Field != "" && hasFieldBinding {
		switch fieldBinding.ESType {
		case "long", "integer", "short", "byte", "unsigned_long", "date", "date_nanos":
			wantsInteger = true
		}
		if fieldBinding.DorisType == schema.DorisLargeInt || fieldBinding.DorisType == schema.DorisBigInt || fieldBinding.DorisType == schema.DorisInt {
			wantsInteger = true
		}
	}
	if wantsInteger {
		if fv, ok := el.(float64); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) {
			return strconv.FormatInt(int64(fv), 10)
		}
	}
	if tSpec != nil && tSpec.Field == "" && vt == "" {
		if fv, ok := el.(float64); ok {
			return formatJavaDoubleRound60(fv)
		}
	}
	return painless.FormatValueSafe(el)
}

func formatSearchShardScriptFailureReasonRound60(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "all_shards_failed|") {
		return msg
	}
	if errors.Is(err, painless.ErrSelfReferencingIterable) {
		return "all_shards_failed|illegal_argument_exception|Iterable object is self-referencing itself (ScriptBytesValues value)"
	}
	if strings.HasPrefix(msg, "illegal_argument_exception: script score function must") {
		return "all_shards_failed|illegal_argument_exception|" + strings.TrimPrefix(msg, "illegal_argument_exception: ")
	}
	var compErr *painless.ScriptCompileError
	if errors.As(err, &compErr) && compErr != nil {
		return "all_shards_failed|script_exception|compile error"
	}
	return "all_shards_failed|script_exception|" + msg
}

func resolveDocES8ModeRound61(doc map[string]any) bool {
	if doc != nil {
		if b, ok := doc["__keep_boolean_dups"].(bool); ok {
			return b
		}
	}
	return true
}

func extractPainlessSourceIfApplicableRound60(raw any) (string, bool) {
	if raw == nil {
		return "", false
	}
	switch v := raw.(type) {
	case *esast.ScriptSpec:
		if v == nil {
			return "", false
		}
		lang := strings.ToLower(strings.TrimSpace(v.Lang))
		if lang != "" && lang != "painless" {
			return "", false
		}
		src := strings.TrimSpace(v.Source)
		return src, src != ""
	case esast.ScriptSpec:
		lang := strings.ToLower(strings.TrimSpace(v.Lang))
		if lang != "" && lang != "painless" {
			return "", false
		}
		src := strings.TrimSpace(v.Source)
		return src, src != ""
	case string:
		src := strings.TrimSpace(v)
		return src, src != ""
	case map[string]any:
		if sub, hasSub := v["script"]; hasSub && sub != nil {
			return extractPainlessSourceIfApplicableRound60(sub)
		}
		if lang, okL := v["lang"].(string); okL {
			lt := strings.ToLower(strings.TrimSpace(lang))
			if lt != "" && lt != "painless" {
				return "", false
			}
		}
		for _, k := range []string{"source", "inline", "code"} {
			if s, okS := v[k].(string); okS && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), true
			}
		}
	}
	return "", false
}

func validateIntervalsRuleScriptsRound60(rule *esast.IntervalsRule) error {
	if rule == nil {
		return nil
	}
	checkFilter := func(f *esast.IntervalsFilter) error {
		if f == nil {
			return nil
		}
		if src, ok := extractPainlessSourceIfApplicableRound60(f.Script); ok {
			if err := painless.CompileValidate(src); err != nil {
				return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
			}
		}
		for _, sub := range []*esast.IntervalsRule{
			f.Containing, f.NotContaining, f.ContainedBy, f.NotContainedBy,
			f.Overlapping, f.NotOverlapping, f.After, f.Before,
		} {
			if err := validateIntervalsRuleScriptsRound60(sub); err != nil {
				return err
			}
		}
		return nil
	}
	if rule.Match != nil {
		if err := checkFilter(rule.Match.Filter); err != nil {
			return err
		}
	}
	if rule.Prefix != nil {
		if err := checkFilter(rule.Prefix.Filter); err != nil {
			return err
		}
	}
	if rule.Wildcard != nil {
		if err := checkFilter(rule.Wildcard.Filter); err != nil {
			return err
		}
	}
	if rule.Fuzzy != nil {
		if err := checkFilter(rule.Fuzzy.Filter); err != nil {
			return err
		}
	}
	if rule.AllOf != nil {
		if err := checkFilter(rule.AllOf.Filter); err != nil {
			return err
		}
		for i := range rule.AllOf.Intervals {
			if err := validateIntervalsRuleScriptsRound60(&rule.AllOf.Intervals[i]); err != nil {
				return err
			}
		}
	}
	if rule.AnyOf != nil {
		if err := checkFilter(rule.AnyOf.Filter); err != nil {
			return err
		}
		for i := range rule.AnyOf.Intervals {
			if err := validateIntervalsRuleScriptsRound60(&rule.AnyOf.Intervals[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateQueryScriptsCompileRound60(q *esast.Query) error {
	if q == nil {
		return nil
	}
	if q.Script != nil {
		if src, ok := extractPainlessSourceIfApplicableRound60(q.Script.Script); ok {
			if err := painless.CompileValidate(src); err != nil {
				return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
			}
		}
	}
	if q.ScriptScore != nil {
		if src, ok := extractPainlessSourceIfApplicableRound60(q.ScriptScore.Script); ok {
			if err := painless.CompileValidate(src); err != nil {
				return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
			}
		}
		if err := validateQueryScriptsCompileRound60(q.ScriptScore.Query); err != nil {
			return err
		}
	}
	if q.FunctionScore != nil {
		for i := range q.FunctionScore.Functions {
			fn := &q.FunctionScore.Functions[i]
			if fn.ScriptScore != nil {
				if src, ok := extractPainlessSourceIfApplicableRound60(fn.ScriptScore.Script); ok {
					if err := painless.CompileValidate(src); err != nil {
						return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
					}
				}
			}
			if err := validateQueryScriptsCompileRound60(fn.Filter); err != nil {
				return err
			}
		}
		if err := validateQueryScriptsCompileRound60(q.FunctionScore.Query); err != nil {
			return err
		}
	}
	for _, r := range q.Intervals {
		rc := r
		if err := validateIntervalsRuleScriptsRound60(&rc); err != nil {
			return err
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if err := validateQueryScriptsCompileRound60(&q.Bool.Must[i]); err != nil {
				return err
			}
		}
		for i := range q.Bool.Filter {
			if err := validateQueryScriptsCompileRound60(&q.Bool.Filter[i]); err != nil {
				return err
			}
		}
		for i := range q.Bool.Should {
			if err := validateQueryScriptsCompileRound60(&q.Bool.Should[i]); err != nil {
				return err
			}
		}
		for i := range q.Bool.MustNot {
			if err := validateQueryScriptsCompileRound60(&q.Bool.MustNot[i]); err != nil {
				return err
			}
		}
	}
	if q.ConstantScore != nil {
		if err := validateQueryScriptsCompileRound60(&q.ConstantScore.Filter); err != nil {
			return err
		}
	}
	if q.Boosting != nil {
		if err := validateQueryScriptsCompileRound60(&q.Boosting.Positive); err != nil {
			return err
		}
		if err := validateQueryScriptsCompileRound60(&q.Boosting.Negative); err != nil {
			return err
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if err := validateQueryScriptsCompileRound60(&q.DisMax.Queries[i]); err != nil {
				return err
			}
		}
	}
	if q.Nested != nil {
		if err := validateQueryScriptsCompileRound60(&q.Nested.Query); err != nil {
			return err
		}
	}
	if q.HasChild != nil {
		if err := validateQueryScriptsCompileRound60(&q.HasChild.Query); err != nil {
			return err
		}
	}
	if q.HasParent != nil {
		if err := validateQueryScriptsCompileRound60(&q.HasParent.Query); err != nil {
			return err
		}
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		if err := validateQueryScriptsCompileRound60(q.Pinned.Organic); err != nil {
			return err
		}
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		if err := validateQueryScriptsCompileRound60(q.Wrapper.Decoded); err != nil {
			return err
		}
	}
	return nil
}

func validateAggsScriptsCompileRound60(aggs map[string]esast.AggSpec) error {
	for _, spec := range aggs {
		checkAny := func(raw any) error {
			if src, ok := extractPainlessSourceIfApplicableRound60(raw); ok {
				if err := painless.CompileValidate(src); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
			}
			return nil
		}
		if spec.Terms != nil {
			if err := checkAny(spec.Terms.Script); err != nil {
				return err
			}
		}
		if spec.Histogram != nil {
			if err := checkAny(spec.Histogram.Script); err != nil {
				return err
			}
		}
		if spec.DateHistogram != nil {
			if err := checkAny(spec.DateHistogram.Script); err != nil {
				return err
			}
		}
		if spec.Range != nil {
			if err := checkAny(spec.Range.Script); err != nil {
				return err
			}
		}
		if spec.DateRange != nil {
			if err := checkAny(spec.DateRange.Script); err != nil {
				return err
			}
		}
		for _, mSpec := range []*esast.MetricAggSpec{
			spec.Avg, spec.Sum, spec.Min, spec.Max, spec.ValueCount,
			spec.Stats, spec.ExtendedStats, spec.Cardinality, spec.MedianAbsoluteDeviation,
		} {
			if mSpec != nil {
				if err := checkAny(mSpec.Script); err != nil {
					return err
				}
			}
		}
		if spec.WeightedAvg != nil {
			if err := checkAny(spec.WeightedAvg.Value.Script); err != nil {
				return err
			}
			if err := checkAny(spec.WeightedAvg.Weight.Script); err != nil {
				return err
			}
		}
		if spec.Percentiles != nil {
			if err := checkAny(spec.Percentiles.Script); err != nil {
				return err
			}
		}
		if spec.PercentileRanks != nil {
			if err := checkAny(spec.PercentileRanks.Script); err != nil {
				return err
			}
		}
		if spec.Boxplot != nil {
			if err := checkAny(spec.Boxplot.Script); err != nil {
				return err
			}
		}
		if spec.StringStats != nil {
			if err := checkAny(spec.StringStats.Script); err != nil {
				return err
			}
		}
		if spec.ScriptedMetric != nil {
			for _, smS := range []any{
				spec.ScriptedMetric.InitScript,
				spec.ScriptedMetric.MapScript,
				spec.ScriptedMetric.CombineScript,
				spec.ScriptedMetric.ReduceScript,
			} {
				if err := checkAny(smS); err != nil {
					return err
				}
			}
		}
		if spec.BucketScript != nil {
			if err := checkAny(spec.BucketScript.Script); err != nil {
				return err
			}
		}
		if spec.BucketSelector != nil {
			if err := checkAny(spec.BucketSelector.Script); err != nil {
				return err
			}
		}
		if ma := spec.EffectiveMovingAvg(); ma != nil {
			if err := checkAny(ma.Script); err != nil {
				return err
			}
		}
		if spec.Filter != nil {
			if err := validateQueryScriptsCompileRound60(spec.Filter); err != nil {
				return err
			}
		}
		if spec.Filters != nil {
			for _, fq := range spec.Filters.Filters {
				fqc := fq
				if err := validateQueryScriptsCompileRound60(&fqc); err != nil {
					return err
				}
			}
			for i := range spec.Filters.AnonymousFilters {
				if err := validateQueryScriptsCompileRound60(&spec.Filters.AnonymousFilters[i]); err != nil {
					return err
				}
			}
		}
		if sub := spec.SubAggs(); len(sub) > 0 {
			if err := validateAggsScriptsCompileRound60(sub); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateSearchRequestScriptsRound60 runs upfront static Painless CompileValidate
// across all script bearing clauses in a SearchRequest before SQL execution.
func validateSearchRequestScriptsRound60(req *esast.SearchRequest) error {
	if req == nil {
		return nil
	}
	if err := validateQueryScriptsCompileRound60(req.Query); err != nil {
		return err
	}
	if err := validateQueryScriptsCompileRound60(req.PostFilter); err != nil {
		return err
	}
	for _, rm := range req.RuntimeMappings {
		if src, ok := extractPainlessSourceIfApplicableRound60(rm.Script); ok {
			if err := painless.CompileValidate(src); err != nil {
				return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
			}
		}
	}
	if len(req.RuntimeMappings) > 0 {
		if _, err := TopoSortRuntimeMappingsRound61(req.RuntimeMappings); err != nil {
			clean := strings.TrimPrefix(err.Error(), "illegal_argument_exception: ")
			return fmt.Errorf("all_shards_failed|illegal_argument_exception|%s", clean)
		}
	}
	for _, s := range req.Sort {
		// IMPORTANT: SortEntry.Script is also used for _geo_distance maps; only validate when Field == "_script"!
		if s.Entry.Field == "_script" && s.Entry.Script != nil {
			if src, ok := extractPainlessSourceIfApplicableRound60(s.Entry.Script); ok {
				if err := painless.CompileValidate(src); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
			}
		}
	}
	if err := validateAggsScriptsCompileRound60(req.EffectiveAggs()); err != nil {
		return err
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil {
			if err := validateQueryScriptsCompileRound60(req.Rescore[i].Query.RescoreQuery); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeHitDocMapRound60(h HitRow) map[string]any {
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
	if h.HasSeqNo {
		doc["__meta_seq_no"] = h.SeqNo
	}
	return doc
}

func checkRuntimeQueryScriptsOnDocRound60(idxSchema *schema.IndexSchema, doc map[string]any, q *esast.Query, baseScore float64) error {
	if q == nil {
		return nil
	}
	if q.Script != nil && q.Script.Script != nil {
		if src, ok := extractPainlessSourceIfApplicableRound60(q.Script.Script); ok {
			_, params := extractScriptSourceAndParams(q.Script.Script)
			evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, doc, resolveDocES8ModeRound61(doc))
			cp := make(map[string]any, len(params)+1)
			for k, v := range params {
				cp[k] = v
			}
			cp["_score"] = baseScore
			if _, err := painless.EvalFilter(evalDoc, src, cp); err != nil {
				return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
			}
		}
	}
	for fieldName, rule := range q.Intervals {
		rc := rule
		if !transpiler.RuleHasIntervalsScript(&rc) {
			continue
		}
		analyzer := "standard"
		if idxSchema != nil {
			b := idxSchema.ResolveField(fieldName)
			if b.SearchAnalyzer != "" {
				analyzer = b.SearchAnalyzer
			} else if b.Analyzer != "" {
				analyzer = b.Analyzer
			}
		}
		clean := strings.TrimSuffix(strings.TrimSuffix(fieldName, ".keyword"), ".ngram")
		for _, rv := range collectSchemaAwareScalarValues(doc, fieldName, strings.Split(clean, "."), idxSchema) {
			txt := painless.FormatValueSafe(rv)
			_, _, err := transpiler.EvaluateIntervalsRule(&rc, txt, analyzer, func(sc *esast.ScriptSpec, span transpiler.IntervalsSpan) (bool, error) {
				if sc == nil {
					return true, nil
				}
				src, params := extractScriptSourceAndParams(sc)
				if src == "" {
					return true, nil
				}
				evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, doc, resolveDocES8ModeRound61(doc))
				cp := make(map[string]any, len(params)+2)
				for k, v := range params {
					cp[k] = v
				}
				cp["interval"] = map[string]any{
					"start": int64(span.Start),
					"end":   int64(span.End),
					"gaps":  int64(span.Gaps),
				}
				return painless.EvalFilter(evalDoc, src, cp)
			})
			if err != nil {
				return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
			}
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.Bool.Must[i], 1.0); err != nil {
				return err
			}
		}
		for i := range q.Bool.Filter {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.Bool.Filter[i], baseScore); err != nil {
				return err
			}
		}
		for i := range q.Bool.Should {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.Bool.Should[i], 1.0); err != nil {
				return err
			}
		}
		for i := range q.Bool.MustNot {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.Bool.MustNot[i], 0.0); err != nil {
				return err
			}
		}
	}
	if q.ConstantScore != nil {
		if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.ConstantScore.Filter, baseScore); err != nil {
			return err
		}
	}
	if q.Boosting != nil {
		if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.Boosting.Positive, baseScore); err != nil {
			return err
		}
		if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.Boosting.Negative, baseScore); err != nil {
			return err
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, &q.DisMax.Queries[i], baseScore); err != nil {
				return err
			}
		}
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, q.FunctionScore.Query, baseScore); err != nil {
				return err
			}
		}
		for i := range q.FunctionScore.Functions {
			fn := &q.FunctionScore.Functions[i]
			if fn.Filter != nil {
				if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, fn.Filter, baseScore); err != nil {
					return err
				}
			}
		}
	}
	if q.ScriptScore != nil {
		if q.ScriptScore.Query != nil {
			if err := checkRuntimeQueryScriptsOnDocRound60(idxSchema, doc, q.ScriptScore.Query, baseScore); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkRuntimeAggScriptsOnDocRound60(idxSchema *schema.IndexSchema, doc map[string]any, score float64, aggs map[string]esast.AggSpec) error {
	evalSingleDocScript := func(rawScript any, field string, missing any, isMetricAgg bool) error {
		src, ok := extractPainlessSourceIfApplicableRound60(rawScript)
		if !ok {
			return nil
		}
		_, params := extractScriptSourceAndParams(rawScript)
		evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, doc, resolveDocES8ModeRound61(doc))
		cp := make(map[string]any, len(params)+3)
		for k, v := range params {
			cp[k] = v
		}
		cp["_score"] = score
		if field != "" {
			clean := strings.TrimSuffix(strings.TrimSuffix(field, ".keyword"), ".ngram")
			pathSegs := strings.Split(clean, ".")
			if idxSchema != nil {
				if b := idxSchema.ResolveField(field); len(b.SourceJSONPath) > 0 {
					pathSegs = b.SourceJSONPath
				}
			}
			vals := collectSchemaAwareScalarValues(doc, field, pathSegs, idxSchema)
			if len(vals) == 0 && missing != nil {
				vals = []any{missing}
			}
			if len(vals) == 0 {
				if !isMetricAgg || strings.Contains(src, "_value") {
					return nil
				}
			} else {
				cp["_value"] = vals[0]
			}
		}
		if isMetricAgg && (field == "" || !strings.Contains(src, "_value")) {
			if missing != nil {
				matches := reScriptDocFieldRef.FindAllStringSubmatch(src, -1)
				for _, m := range matches {
					if len(m) < 2 {
						continue
					}
					rawField := strings.TrimSuffix(strings.TrimSuffix(m[1], ".keyword"), ".ngram")
					if rawField == "" || rawField == "_id" || rawField == "_index" || rawField == "_version" {
						continue
					}
					if len(collectScalarValuesAtPath(evalDoc, strings.Split(rawField, "."))) == 0 {
						evalDoc = cloneDocWithFieldPath(evalDoc, rawField, missing)
					}
				}
			} else if _, isMiss := scriptHasMissingDocValueRef(evalDoc, src); isMiss {
				return nil
			}
		}
		val, err := painless.Eval(evalDoc, src, cp)
		if err != nil {
			return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
		}
		if err := painless.ValidateAcyclicValue(val); err != nil {
			return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
		}
		return nil
	}

	for _, spec := range aggs {
		if spec.Terms != nil && spec.Terms.Script != nil {
			if err := evalSingleDocScript(spec.Terms.Script, spec.Terms.Field, spec.Terms.Missing, false); err != nil {
				return err
			}
		}
		for _, mSpec := range []*esast.MetricAggSpec{
			spec.Avg, spec.Sum, spec.Min, spec.Max, spec.ValueCount,
			spec.Stats, spec.ExtendedStats, spec.Cardinality, spec.MedianAbsoluteDeviation,
		} {
			if mSpec != nil && mSpec.Script != nil {
				if err := evalSingleDocScript(mSpec.Script, mSpec.Field, mSpec.Missing, true); err != nil {
					return err
				}
			}
		}
		if spec.ScriptedMetric != nil {
			sm := spec.ScriptedMetric
			state := make(map[string]any)
			mkP := func(extra map[string]any) map[string]any {
				p := make(map[string]any, len(sm.Params)+len(extra)+3)
				for k, v := range sm.Params {
					p[k] = v
				}
				for k, v := range extra {
					p[k] = v
				}
				p["state"] = state
				p["_agg"] = state
				p["_score"] = score
				return p
			}
			if src, ok := extractPainlessSourceIfApplicableRound60(sm.InitScript); ok {
				_, p := extractScriptSourceAndParams(sm.InitScript)
				if _, err := painless.Eval(map[string]any{}, src, mkP(p)); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
			}
			if src, ok := extractPainlessSourceIfApplicableRound60(sm.MapScript); ok {
				_, p := extractScriptSourceAndParams(sm.MapScript)
				evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, doc, resolveDocES8ModeRound61(doc))
				val, err := painless.Eval(evalDoc, src, mkP(p))
				if err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
				if err := painless.ValidateAcyclicValue(val); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
				if err := painless.ValidateAcyclicValue(state); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
			}
			var combined any = state
			if src, ok := extractPainlessSourceIfApplicableRound60(sm.CombineScript); ok {
				_, p := extractScriptSourceAndParams(sm.CombineScript)
				cp := mkP(p)
				val, err := painless.Eval(map[string]any{}, src, cp)
				if err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
				if err := painless.ValidateAcyclicValue(val); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
				if _, hadRet := cp["__had_explicit_return"]; val != nil || hadRet {
					combined = val
				}
			}
			if src, ok := extractPainlessSourceIfApplicableRound60(sm.ReduceScript); ok {
				_, p := extractScriptSourceAndParams(sm.ReduceScript)
				rp := make(map[string]any, len(sm.Params)+len(p)+2)
				for k, v := range sm.Params {
					rp[k] = v
				}
				for k, v := range p {
					rp[k] = v
				}
				rp["states"] = []any{combined}
				rp["_aggs"] = []any{combined}
				val, err := painless.Eval(map[string]any{}, src, rp)
				if err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
				if err := painless.ValidateAcyclicValue(val); err != nil {
					return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
				}
			}
		}
		if sub := spec.SubAggs(); len(sub) > 0 {
			if err := checkRuntimeAggScriptsOnDocRound60(idxSchema, doc, score, sub); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateRuntimeSearchScriptsOnHitsRound60 checks runtime Painless script execution and
// cyclic return values (ErrSelfReferencingIterable) across query filters, intervals scripts,
// script_fields, sort._script, and aggregation scripts BEFORE hit/bucket materialization.
func validateRuntimeSearchScriptsOnHitsRound60(idxSchema *schema.IndexSchema, req *esast.SearchRequest, hits []HitRow) error {
	if req == nil || len(hits) == 0 {
		return nil
	}
	hasWork := queryHasRuntimeScript(req.Query) ||
		queryHasRuntimeScript(req.PostFilter) ||
		len(req.RuntimeMappings) > 0 ||
		(idxSchema != nil && idxSchema.RawMapping != nil && len(idxSchema.RawMapping.Runtime) > 0) ||
		aggsHaveRuntimeScript(req.EffectiveAggs())
	if !hasWork {
		for _, s := range req.Sort {
			if s.Entry.Field == "_script" && s.Entry.Script != nil {
				hasWork = true
				break
			}
		}
	}
	if !hasWork {
		return nil
	}
	effAggs := req.EffectiveAggs()
	for _, h := range hits {
		effSch := idxSchema
		if h.Schema != nil {
			effSch = h.Schema
		}
		doc := decodeHitDocMapRound60(h)
		isES8 := resolveDocES8ModeRound61(doc)
		rtEvalDoc, _, rtErr := EvalRuntimeMappingsOnDocTopologicalRound61(effSch, req.RuntimeMappings, doc, isES8)
		if rtErr != nil {
			if strings.HasPrefix(rtErr.Error(), "illegal_argument_exception: ") {
				return fmt.Errorf("all_shards_failed|illegal_argument_exception|%s", strings.TrimPrefix(rtErr.Error(), "illegal_argument_exception: "))
			}
			return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(rtErr))
		}
		if err := checkRuntimeQueryScriptsOnDocRound60(effSch, doc, req.Query, h.Score); err != nil {
			return err
		}
		if !evalQueryScriptFilterOnDocWithScore(effSch, doc, req.Query, h.Score) {
			continue
		}
		if err := checkRuntimeQueryScriptsOnDocRound60(effSch, doc, req.PostFilter, h.Score); err != nil {
			return err
		}
		for _, s := range req.Sort {
			if s.Entry.Field == "_script" && s.Entry.Script != nil {
				if src, ok := extractPainlessSourceIfApplicableRound60(s.Entry.Script); ok {
					_, params := extractScriptSourceAndParams(s.Entry.Script)
					evalDoc := rtEvalDoc
					if evalDoc == nil {
						evalDoc = PrepareDocForRuntimeScriptRound61(effSch, doc, isES8)
					}
					cp := make(map[string]any, len(params)+1)
					for k, v := range params {
						cp[k] = v
					}
					cp["_score"] = h.Score
					val, err := painless.Eval(evalDoc, src, cp)
					if err != nil {
						return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
					}
					if err := painless.ValidateAcyclicValue(val); err != nil {
						return fmt.Errorf("%s", formatSearchShardScriptFailureReasonRound60(err))
					}
				}
			}
		}
		if len(effAggs) > 0 {
			if err := checkRuntimeAggScriptsOnDocRound60(effSch, doc, h.Score, effAggs); err != nil {
				return err
			}
		}
	}
	return nil
}

// evalMovingFnWindowNullableRound60 evaluates Elasticsearch `moving_fn` window scripts (`F25`),
// supporting empty windows (`shift: 0` on first bucket -> `MovingFunctions.sum` = 0.0,
// `max`/`min`/`unweightedAvg`/`linearWeightedAvg`/`ewma`/`stdDev` = null).
func evalMovingFnWindowNullableRound60(slice []float64, maSpec *esast.MovingAvgAggSpec) (float64, bool) {
	if maSpec == nil {
		return 0, false
	}
	if src, scriptParams := extractScriptSourceAndParams(maSpec.Script); strings.TrimSpace(src) != "" {
		valsAny := make([]any, len(slice))
		for i, v := range slice {
			valsAny[i] = v
		}
		p := make(map[string]any, len(scriptParams)+1)
		for k, v := range scriptParams {
			p[k] = v
		}
		p["values"] = valsAny
		res, err := painless.Eval(map[string]any{}, src, p)
		if err != nil || res == nil {
			return 0, false
		}
		fv, ok := toFloat64(res)
		if !ok || math.IsNaN(fv) || math.IsInf(fv, 0) {
			return 0, false
		}
		return fv, true
	}
	if len(slice) == 0 {
		return 0, false
	}
	v := evalMovingWindow(slice, maSpec)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

func runtimeFieldTypeToEmitContextRound60(esType string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "boolean":
		return "boolean_field", true
	case "long", "integer", "short", "byte", "unsigned_long":
		return "long_field", true
	case "double", "float", "half_float", "scaled_float":
		return "double_field", true
	case "keyword", "constant_keyword", "wildcard":
		return "keyword_field", true
	case "date", "date_nanos":
		return "date_field", true
	case "ip":
		return "ip_field", true
	case "geo_point":
		return "geo_point_field", true
	}
	return "", false
}

func extractExplainTopBoostRound60(q *esast.Query) (float64, bool) {
	if q == nil {
		return 1.0, false
	}
	if q.MatchAll != nil {
		if rawB, ok := q.MatchAll["boost"]; ok && rawB != nil {
			if fv, okF := toFloat64(rawB); okF {
				return fv, true
			}
		}
	}
	for _, te := range q.Term {
		if te.HasBoost || (te.Boost != 0 && te.Boost != 1.0) {
			return te.Boost, true
		}
	}
	for _, me := range q.Match {
		if me.Boost != 0 && me.Boost != 1.0 {
			return me.Boost, true
		}
	}
	if q.Terms != nil && (q.Terms.HasBoost || (q.Terms.Boost != 0 && q.Terms.Boost != 1.0)) {
		return q.Terms.Boost, true
	}
	if q.QueryString != nil && q.QueryString.Boost != nil {
		return *q.QueryString.Boost, true
	}
	if q.SimpleQueryString != nil && q.SimpleQueryString.Boost != nil {
		return *q.SimpleQueryString.Boost, true
	}
	if q.MultiMatch != nil && q.MultiMatch.Boost != nil {
		return *q.MultiMatch.Boost, true
	}
	if q.Ids != nil && q.Ids.Boost != nil {
		return *q.Ids.Boost, true
	}
	if q.Exists != nil && q.Exists.Boost != nil {
		return *q.Exists.Boost, true
	}
	if q.ConstantScore != nil && q.ConstantScore.Boost != nil {
		return *q.ConstantScore.Boost, true
	}
	if q.Bool != nil && q.Bool.Boost != nil {
		return *q.Bool.Boost, true
	}
	if q.DisMax != nil && q.DisMax.Boost != nil {
		return *q.DisMax.Boost, true
	}
	if q.Boosting != nil && q.Boosting.Boost != nil {
		return *q.Boosting.Boost, true
	}
	if q.FunctionScore != nil && q.FunctionScore.Boost != nil {
		return *q.FunctionScore.Boost, true
	}
	if q.ScriptScore != nil && q.ScriptScore.Boost != nil {
		return *q.ScriptScore.Boost, true
	}
	return 1.0, false
}
