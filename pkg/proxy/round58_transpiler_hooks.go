package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// canonicalIPHexRound58 converts a scalar IP representation (IPv4 or IPv6)
// into a canonical 32-character uppercase RFC 4291 hex string so IPv4 and IPv6
// values compare in 128-bit address order.
func canonicalIPHexRound58(raw any) (string, bool) {
	if raw == nil {
		return "", false
	}
	var s string
	switch v := raw.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return "", false
	}
	return schema.CanonicalIPToUpperHex16(s)
}

// compareCanonicalIPValuesRound58 compares two IP values (IPv4, IPv6, or
// IPv4-mapped IPv6) in canonical 128-bit unsigned network byte order.
// Returns (cmp, true) when both inputs parse as valid IPs, or (0, false) otherwise.
func compareCanonicalIPValuesRound58(a, b any) (int, bool) {
	ha, okA := canonicalIPHexRound58(a)
	if !okA {
		return 0, false
	}
	hb, okB := canonicalIPHexRound58(b)
	if !okB {
		return 0, false
	}
	return strings.Compare(ha, hb), true
}

// epochNanosToUTCTimeRound58 converts signed epoch nanoseconds into a UTC time.Time
// with normalized non-negative sub-second nanoseconds [0, 999_999_999].
func epochNanosToUTCTimeRound58(ns int64) time.Time {
	sec := ns / 1_000_000_000
	nsec := ns % 1_000_000_000
	if nsec < 0 {
		sec--
		nsec += 1_000_000_000
	}
	return time.Unix(sec, nsec).UTC()
}

// formatDateNanosEpochRound58 formats signed epoch nanoseconds using ES's default
// strict_date_optional_time_nanos output pattern ("2006-01-02T15:04:05.000000000Z").
func formatDateNanosEpochRound58(ns int64) string {
	return epochNanosToUTCTimeRound58(ns).Format("2006-01-02T15:04:05.000000000Z")
}

// formatDateNanosWithFormatRound58 formats signed epoch nanoseconds according to an ES
// date/date_nanos format specification (for fields / docvalue_fields / bucket keys).
func formatDateNanosWithFormatRound58(ns int64, format string) any {
	eff := strings.TrimSpace(strings.Split(format, "||")[0])
	switch strings.ToLower(eff) {
	case "", "strict_date_optional_time_nanos", "date_optional_time_nanos", "strict_date_time_no_millis":
		return formatDateNanosEpochRound58(ns)
	case "strict_date_optional_time", "date_optional_time":
		return epochNanosToUTCTimeRound58(ns).Format("2006-01-02T15:04:05.000Z")
	case "epoch_nanos":
		return ns
	case "epoch_millis":
		ms := ns / 1_000_000
		if ns < 0 && ns%1_000_000 != 0 {
			ms--
		}
		return ms
	case "epoch_second":
		sec := ns / 1_000_000_000
		if ns < 0 && ns%1_000_000_000 != 0 {
			sec--
		}
		return sec
	default:
		layout := schema.ESDateFormatToGoLayout(eff)
		return epochNanosToUTCTimeRound58(ns).Format(layout)
	}
}

// parseDateNanosValueRound58 parses a string or numeric value into signed epoch
// nanoseconds according to an ES date_nanos mapping format.
func parseDateNanosValueRound58(raw any, format string) (int64, bool) {
	if raw == nil {
		return 0, false
	}
	nowUTC := time.Now().UTC()
	hasEpochMillis := false
	hasEpochSecond := false
	hasEpochNanos := false
	if format != "" {
		for _, tok := range strings.Split(format, "||") {
			switch strings.ToLower(strings.TrimSpace(tok)) {
			case "epoch_millis":
				hasEpochMillis = true
			case "epoch_second":
				hasEpochSecond = true
			case "epoch_nanos":
				hasEpochNanos = true
			}
		}
	}
	scaleInt := func(iv int64) int64 {
		if hasEpochSecond && !hasEpochMillis && !hasEpochNanos {
			if iv <= math.MaxInt64/1_000_000_000 && iv >= math.MinInt64/1_000_000_000 {
				return iv * 1_000_000_000
			}
			return iv
		}
		if (hasEpochMillis && !hasEpochNanos) || format == "" {
			// Bare integers in ES date_nanos default format (strict_date_optional_time_nanos||epoch_millis)
			// represent epoch_millis unless already at nanosecond magnitude (e.g., internal sort values).
			if !hasEpochNanos && iv > -100_000_000_000_000 && iv < 100_000_000_000_000 {
				return iv * 1_000_000
			}
		}
		return iv
	}
	switch v := raw.(type) {
	case int64:
		return scaleInt(v), true
	case int:
		return scaleInt(int64(v)), true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return scaleInt(iv), true
		}
		if ns, ok := schema.ParseESDateWithFormatToEpochNanos(v.String(), format, nowUTC); ok {
			return ns, true
		}
		return 0, false
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		if hasEpochSecond && !hasEpochMillis && !hasEpochNanos {
			return int64(math.Round(v * 1_000_000_000)), true
		}
		if (hasEpochMillis && !hasEpochNanos) || (format == "" && math.Abs(v) < 1e14) {
			return int64(math.Round(v * 1_000_000)), true
		}
		return int64(v), true
	case string:
		return schema.ParseESDateWithFormatToEpochNanos(v, format, nowUTC)
	default:
		return 0, false
	}
}

// searchAsYouTypeSubfieldsRound58 returns the active synthetic subfields for a
// search_as_you_type field binding (respecting max_shingle_size 2..4, default 3).
func searchAsYouTypeSubfieldsRound58(b schema.FieldBinding) []string {
	return b.SearchAsYouTypeSubfields()
}

// isHistogramFieldInSchemaRound58 reports whether field resolves to an ES "histogram"
// field in idxSchema.
func isHistogramFieldInSchemaRound58(idxSchema *schema.IndexSchema, field string) bool {
	if idxSchema == nil || strings.TrimSpace(field) == "" {
		return false
	}
	return idxSchema.ResolveField(field).ESType == "histogram"
}

// extractHistogramBinsFromDocRound58 traverses pathSegs inside a decoded _source document
// and returns all positive-count (value, count) pairs from histogram objects {values, counts}.
func extractHistogramBinsFromDocRound58(doc map[string]any, pathSegs []string) ([]float64, []int64) {
	if doc == nil || len(pathSegs) == 0 {
		return nil, nil
	}
	var vals []float64
	var cnts []int64
	var walk func(curr any, idx int)
	walk = func(curr any, idx int) {
		if curr == nil {
			return
		}
		if idx == len(pathSegs) {
			switch node := curr.(type) {
			case []any:
				for _, elem := range node {
					walk(elem, idx)
				}
			case map[string]any:
				rawVals, okV := node["values"].([]any)
				rawCnts, okC := node["counts"].([]any)
				if !okV || !okC || len(rawVals) != len(rawCnts) {
					return
				}
				for i := range rawVals {
					fv, okF := toFloat(rawVals[i])
					cv, okI := toInt64(rawCnts[i])
					if okF && okI && !math.IsNaN(fv) && !math.IsInf(fv, 0) && cv > 0 {
						vals = append(vals, fv)
						cnts = append(cnts, cv)
					}
				}
			}
			return
		}
		switch node := curr.(type) {
		case map[string]any:
			if next, exists := node[pathSegs[idx]]; exists {
				walk(next, idx+1)
			}
		case []any:
			for _, elem := range node {
				walk(elem, idx)
			}
		}
	}
	walk(doc, 0)
	return vals, cnts
}

// evaluateHistogramAggFromSourcesRound58 evaluates count-weighted metric and histogram
// bucket aggregations directly over _source documents for an ES "histogram" field.
func evaluateHistogramAggFromSourcesRound58(spec esast.AggSpec, field string, sources []json.RawMessage) (map[string]any, bool) {
	trimmedField := strings.TrimSpace(field)
	if trimmedField == "" {
		return nil, false
	}
	segs := strings.Split(trimmedField, ".")
	var pairs []memWeightedVal
	var totalCount int64
	var weightedSum float64
	minVal := math.Inf(1)
	maxVal := math.Inf(-1)

	for _, rawSrc := range sources {
		if len(bytes.TrimSpace(rawSrc)) == 0 {
			continue
		}
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(rawSrc))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil || doc == nil {
			continue
		}
		vs, cs := extractHistogramBinsFromDocRound58(doc, segs)
		for i := range vs {
			v := vs[i]
			c := cs[i]
			if c <= 0 {
				continue
			}
			totalCount += c
			weightedSum += v * float64(c)
			if v < minVal {
				minVal = v
			}
			if v > maxVal {
				maxVal = v
			}
			pairs = append(pairs, memWeightedVal{v: v, w: float64(c)})
		}
	}

	switch {
	case spec.Min != nil:
		if totalCount == 0 {
			return map[string]any{"value": nil}, true
		}
		return map[string]any{"value": minVal}, true
	case spec.Max != nil:
		if totalCount == 0 {
			return map[string]any{"value": nil}, true
		}
		return map[string]any{"value": maxVal}, true
	case spec.Sum != nil:
		return map[string]any{"value": weightedSum}, true
	case spec.Avg != nil:
		if totalCount == 0 {
			return map[string]any{"value": nil}, true
		}
		return map[string]any{"value": weightedSum / float64(totalCount)}, true
	case spec.ValueCount != nil:
		return map[string]any{"value": totalCount}, true
	case spec.Stats != nil:
		if totalCount == 0 {
			return map[string]any{
				"count": int64(0),
				"min":   nil,
				"max":   nil,
				"avg":   nil,
				"sum":   0.0,
			}, true
		}
		return map[string]any{
			"count": totalCount,
			"min":   minVal,
			"max":   maxVal,
			"avg":   weightedSum / float64(totalCount),
			"sum":   weightedSum,
		}, true
	case spec.Percentiles != nil:
		pcts := spec.Percentiles.EffectivePercents()
		valuesMap := make(map[string]any, len(pcts))
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].v < pairs[j].v })
		totalW := float64(totalCount)
		for _, pct := range pcts {
			pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
			if !strings.Contains(pctKey, ".") {
				pctKey += ".0"
			}
			if totalCount == 0 {
				valuesMap[pctKey] = nil
			} else {
				valuesMap[pctKey] = computeWeightedQuantile(pairs, totalW, pct/100.0)
			}
		}
		return map[string]any{"values": valuesMap}, true
	case spec.PercentileRanks != nil:
		valuesMap := make(map[string]any, len(spec.PercentileRanks.Values))
		totalW := float64(totalCount)
		for _, thresh := range spec.PercentileRanks.Values {
			valKey := strconv.FormatFloat(thresh, 'f', -1, 64)
			if !strings.Contains(valKey, ".") {
				valKey += ".0"
			}
			if totalCount == 0 {
				valuesMap[valKey] = nil
				continue
			}
			var leW float64
			for _, p := range pairs {
				if p.v <= thresh {
					leW += p.w
				}
			}
			valuesMap[valKey] = 100.0 * leW / totalW
		}
		return map[string]any{"values": valuesMap}, true
	case spec.Boxplot != nil:
		if totalCount == 0 {
			return map[string]any{
				"min":   nil,
				"max":   nil,
				"q1":    nil,
				"q2":    nil,
				"q3":    nil,
				"lower": nil,
				"upper": nil,
			}, true
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].v < pairs[j].v })
		totalW := float64(totalCount)
		q1 := computeWeightedQuantile(pairs, totalW, 0.25)
		q2 := computeWeightedQuantile(pairs, totalW, 0.50)
		q3 := computeWeightedQuantile(pairs, totalW, 0.75)
		iqr := q3 - q1
		lowerFence := q1 - 1.5*iqr
		upperFence := q3 + 1.5*iqr
		lower := minVal
		for _, p := range pairs {
			if p.v >= lowerFence {
				lower = p.v
				break
			}
		}
		upper := maxVal
		for i := len(pairs) - 1; i >= 0; i-- {
			if pairs[i].v <= upperFence {
				upper = pairs[i].v
				break
			}
		}
		return map[string]any{
			"min":   minVal,
			"max":   maxVal,
			"q1":    q1,
			"q2":    q2,
			"q3":    q3,
			"lower": lower,
			"upper": upper,
		}, true
	case spec.Histogram != nil:
		interval := spec.Histogram.Interval
		if interval <= 0 {
			return nil, false
		}
		offset := spec.Histogram.Offset
		bucketCounts := make(map[float64]int64)
		for _, p := range pairs {
			bk := math.Round((math.Floor((p.v-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
			bucketCounts[bk] += int64(math.Round(p.w))
		}
		keys := make([]float64, 0, len(bucketCounts))
		for k := range bucketCounts {
			keys = append(keys, k)
		}
		sort.Float64s(keys)
		minDocCount := int64(0)
		if spec.Histogram.MinDocCount != nil {
			minDocCount = int64(*spec.Histogram.MinDocCount)
		}
		if minDocCount == 0 && len(keys) >= 2 {
			var filled []float64
			for cur := keys[0]; cur <= keys[len(keys)-1]+1e-9; cur = math.Round((cur+interval)*1e12) / 1e12 {
				filled = append(filled, cur)
			}
			keys = filled
		}
		buckets := make([]map[string]any, 0, len(keys))
		for _, k := range keys {
			dc := bucketCounts[k]
			if dc < minDocCount {
				continue
			}
			buckets = append(buckets, map[string]any{
				"key":       k,
				"doc_count": dc,
			})
		}
		return map[string]any{"buckets": buckets}, true
	default:
		return nil, false
	}
}

func parseStrictESBoolParamRound58(paramName, raw string) (bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "true") {
		return true, nil
	}
	if strings.EqualFold(trimmed, "false") {
		return false, nil
	}
	return false, fmt.Errorf("illegal_argument_exception: Failed to parse value [%s] for [%s] as only [true] or [false] are allowed", raw, paramName)
}

// applyAndValidateURISearchParamsRound58 applies and strictly validates URI search
// query parameters (size, from, terminate_after, batched_reduce_size, min_score,
// track_total_hits, booleans, default_operator, sort) onto req.
func applyAndValidateURISearchParamsRound58(r *http.Request, req *esast.SearchRequest) error {
	if r == nil || req == nil {
		return nil
	}
	q := r.URL.Query()

	var awPtr, lnPtr *bool
	if q.Has("analyze_wildcard") {
		aw, err := parseStrictESBoolParamRound58("analyze_wildcard", q.Get("analyze_wildcard"))
		if err != nil {
			return err
		}
		awPtr = &aw
	}
	if q.Has("lenient") {
		ln, err := parseStrictESBoolParamRound58("lenient", q.Get("lenient"))
		if err != nil {
			return err
		}
		lnPtr = &ln
	}
	if defOp := strings.TrimSpace(q.Get("default_operator")); defOp != "" {
		if !strings.EqualFold(defOp, "AND") && !strings.EqualFold(defOp, "OR") {
			return fmt.Errorf("illegal_argument_exception: Unsupported defaultOperator [%s], can only be [OR] or [AND]", defOp)
		}
	}

	if qStr := q.Get("q"); qStr != "" && req.Query == nil {
		qs := &esast.QueryStringQuery{
			Query:            qStr,
			DefaultField:     q.Get("df"),
			DefaultOperator:  q.Get("default_operator"),
			QuoteFieldSuffix: q.Get("quote_field_suffix"),
			AnalyzeWildcard:  awPtr,
			Lenient:          lnPtr,
		}
		req.Query = &esast.Query{
			QueryString: qs,
		}
	}

	if q.Has("version") {
		v, err := parseStrictESBoolParamRound58("version", q.Get("version"))
		if err != nil {
			return err
		}
		req.Version = v
	}
	if q.Has("seq_no_primary_term") {
		sn, err := parseStrictESBoolParamRound58("seq_no_primary_term", q.Get("seq_no_primary_term"))
		if err != nil {
			return err
		}
		req.SeqNoPrimaryTerm = sn
	}
	if q.Has("explain") {
		ex, err := parseStrictESBoolParamRound58("explain", q.Get("explain"))
		if err != nil {
			return err
		}
		req.Explain = ex
	}
	if q.Has("track_scores") {
		ts, err := parseStrictESBoolParamRound58("track_scores", q.Get("track_scores"))
		if err != nil {
			return err
		}
		if req.TrackScores == nil {
			req.TrackScores = &ts
		}
	}

	if q.Has("min_score") {
		msStr := strings.TrimSpace(q.Get("min_score"))
		ms, err := strconv.ParseFloat(msStr, 64)
		if err != nil || math.IsNaN(ms) || math.IsInf(ms, 0) {
			return fmt.Errorf("illegal_argument_exception: Failed to parse float parameter [min_score] with value [%s]", q.Get("min_score"))
		}
		if req.MinScore == nil {
			req.MinScore = &ms
		}
	}

	if q.Has("size") {
		sizeStr := strings.TrimSpace(q.Get("size"))
		sz, err := strconv.Atoi(sizeStr)
		if err != nil {
			return fmt.Errorf("illegal_argument_exception: Failed to parse int parameter [size] with value [%s]", q.Get("size"))
		}
		if sz < 0 {
			return fmt.Errorf("illegal_argument_exception: [size] must be greater than or equal to 0, got [%d]", sz)
		}
		req.Size = &sz
	}

	if q.Has("from") {
		fromStr := strings.TrimSpace(q.Get("from"))
		fr, err := strconv.Atoi(fromStr)
		if err != nil {
			return fmt.Errorf("illegal_argument_exception: Failed to parse int parameter [from] with value [%s]", q.Get("from"))
		}
		if fr < 0 {
			return fmt.Errorf("illegal_argument_exception: [from] must be greater than or equal to 0, got [%d]", fr)
		}
		req.From = &fr
	}

	if q.Has("terminate_after") {
		taStr := strings.TrimSpace(q.Get("terminate_after"))
		ta, err := strconv.Atoi(taStr)
		if err != nil {
			return fmt.Errorf("illegal_argument_exception: Failed to parse int parameter [terminate_after] with value [%s]", q.Get("terminate_after"))
		}
		if ta <= 0 {
			return fmt.Errorf("illegal_argument_exception: [terminate_after] must be greater than 0, got [%d]", ta)
		}
		if req.TerminateAfter == nil {
			req.TerminateAfter = &ta
		}
	}

	if q.Has("batched_reduce_size") {
		brsStr := strings.TrimSpace(q.Get("batched_reduce_size"))
		brs, err := strconv.Atoi(brsStr)
		if err != nil {
			return fmt.Errorf("illegal_argument_exception: Failed to parse int parameter [batched_reduce_size] with value [%s]", q.Get("batched_reduce_size"))
		}
		if brs <= 0 {
			return fmt.Errorf("illegal_argument_exception: [batched_reduce_size] must be greater than 0, got [%d]", brs)
		}
		if req.BatchedReduceSize == nil {
			req.BatchedReduceSize = &brs
		}
	}

	if q.Has("track_total_hits") {
		tth := strings.TrimSpace(q.Get("track_total_hits"))
		var parsedTTH any
		if tth == "" || strings.EqualFold(tth, "true") {
			parsedTTH = true
		} else if strings.EqualFold(tth, "false") {
			parsedTTH = false
		} else {
			n, err := strconv.ParseInt(tth, 10, 64)
			if err != nil || n < -1 {
				return fmt.Errorf("illegal_argument_exception: Failed to parse value [%s] for [track_total_hits]", q.Get("track_total_hits"))
			}
			parsedTTH = n
		}
		if req.TrackTotalHits == nil {
			req.TrackTotalHits = parsedTTH
		}
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
					if !strings.EqualFold(order, "asc") && !strings.EqualFold(order, "desc") {
						return fmt.Errorf("illegal_argument_exception: No enum constant org.elasticsearch.search.sort.SortOrder.%s", order)
					}
				}
				req.Sort = append(req.Sort, esast.SortSpec{
					Entry: esast.SortEntry{Field: field, Order: strings.ToLower(order)},
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
	return nil
}
