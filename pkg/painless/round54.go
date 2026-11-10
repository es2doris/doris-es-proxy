package painless

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func formatJavaFloatingToStringPainless(fv float64, _ bool) string {
	if math.IsNaN(fv) {
		return "NaN"
	}
	if math.IsInf(fv, 1) {
		return "Infinity"
	}
	if math.IsInf(fv, -1) {
		return "-Infinity"
	}
	s := strconv.FormatFloat(fv, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

func formatDurationISO8601Painless(d time.Duration) string {
	if d == 0 {
		return "PT0S"
	}
	neg := d < 0
	if neg {
		d = -d
	}
	var b strings.Builder
	b.WriteString("PT")
	if neg {
		b.WriteByte('-')
	}
	hours := int64(d / time.Hour)
	rem := d % time.Hour
	mins := int64(rem / time.Minute)
	rem %= time.Minute
	secs := int64(rem / time.Second)
	nanos := int64(rem % time.Second)
	if hours > 0 {
		b.WriteString(strconv.FormatInt(hours, 10))
		b.WriteByte('H')
	}
	if mins > 0 {
		b.WriteString(strconv.FormatInt(mins, 10))
		b.WriteByte('M')
	}
	if secs > 0 || nanos > 0 || (hours == 0 && mins == 0) {
		b.WriteString(strconv.FormatInt(secs, 10))
		if nanos > 0 {
			frac := strings.TrimRight(fmt.Sprintf("%09d", nanos), "0")
			b.WriteByte('.')
			b.WriteString(frac)
		}
		b.WriteByte('S')
	}
	return b.String()
}

func parseLocalTimeComponentsPainless(s string) (int, int, int, int, bool) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, 0, 0, 0, false
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return 0, 0, 0, 0, false
	}
	sec := 0
	nano := 0
	if len(parts) == 3 {
		secPart := parts[2]
		if dotIdx := strings.IndexByte(secPart, '.'); dotIdx >= 0 {
			frac := secPart[dotIdx+1:]
			secPart = secPart[:dotIdx]
			if len(frac) == 0 || len(frac) > 9 {
				return 0, 0, 0, 0, false
			}
			for len(frac) < 9 {
				frac += "0"
			}
			nVal, errN := strconv.Atoi(frac)
			if errN != nil {
				return 0, 0, 0, 0, false
			}
			nano = nVal
		}
		if len(secPart) != 2 {
			return 0, 0, 0, 0, false
		}
		sVal, errS := strconv.Atoi(secPart)
		if errS != nil {
			return 0, 0, 0, 0, false
		}
		sec = sVal
	}
	return h, m, sec, nano, true
}

// ============================================================================
// F20: java.util.Optional, OptionalInt, OptionalLong, OptionalDouble
// ============================================================================

type painlessOptional struct {
	kind    string // "Optional", "OptionalInt", "OptionalLong", "OptionalDouble"
	present bool
	val     any
}

func newPainlessOptional(kind string, present bool, val any) *painlessOptional {
	if kind == "" {
		kind = "Optional"
	}
	if !present {
		return &painlessOptional{kind: kind, present: false, val: nil}
	}
	return &painlessOptional{kind: kind, present: true, val: val}
}

func coerceOptionalPrimitivePainless(kind string, val any) (any, error) {
	if val == nil || val == painlessEmptyOptional {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: kind + ".of(null)"}
	}
	if opt, ok := val.(*painlessOptional); ok {
		if !opt.present {
			return nil, &painlessExceptionError{exType: "NullPointerException", message: kind + ".of(null)"}
		}
		val = opt.val
	}
	switch kind {
	case "OptionalInt":
		if iv, ok := toInt64Painless(val); ok {
			return int64(int32(iv)), nil // #nosec G115 -- intentional 32-bit int coercion for OptionalInt
		}
		if fv, ok := toFloat64(val); ok {
			return int64(int32(fv)), nil // #nosec G115 -- intentional 32-bit int coercion for OptionalInt
		}
		return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to int", val)}
	case "OptionalLong":
		if iv, ok := toInt64Painless(val); ok {
			return iv, nil
		}
		if fv, ok := toFloat64(val); ok {
			return int64(fv), nil
		}
		return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to long", val)}
	case "OptionalDouble":
		if fv, ok := toFloat64(val); ok {
			return fv, nil
		}
		return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to double", val)}
	default:
		return val, nil
	}
}

func (o *painlessOptional) String() string {
	if o == nil || !o.present {
		k := "Optional"
		if o != nil && o.kind != "" {
			k = o.kind
		}
		return k + ".empty"
	}
	if o.kind == "OptionalDouble" {
		if fv, ok := toFloat64(o.val); ok {
			return fmt.Sprintf("OptionalDouble[%s]", formatJavaFloatingToStringPainless(fv, false))
		}
	}
	return fmt.Sprintf("%s[%v]", o.kind, o.val)
}

func (o *painlessOptional) equals(other any) bool {
	if o == nil {
		return other == nil
	}
	o2, ok := other.(*painlessOptional)
	if !ok || o2 == nil {
		if !o.present && other == painlessEmptyOptional {
			return o.kind == "Optional"
		}
		return false
	}
	if o.kind != o2.kind || o.present != o2.present {
		return false
	}
	if !o.present {
		return true
	}
	return painlessValuesEqual(o.val, o2.val)
}

func (o *painlessOptional) hashCode() int64 {
	if o == nil || !o.present {
		return 0
	}
	return computeJavaHashCodePainless(o.val)
}

func computeJavaHashCodePainless(v any) int64 {
	if v == nil || v == painlessEmptyOptional {
		return 0
	}
	switch tv := v.(type) {
	case *painlessOptional:
		return tv.hashCode()
	case *painlessOffsetTime:
		return tv.hashCode()
	case *painlessClock:
		return tv.hashCode()
	case *painlessURI:
		return tv.hashCode()
	case *painlessURL:
		return tv.hashCode()
	case bool:
		if tv {
			return 1231
		}
		return 1237
	case int:
		return int64(int32(tv)) // #nosec G115 -- Java Integer.hashCode
	case int32:
		return int64(tv)
	case int64:
		return int64(int32(tv ^ (tv >> 32))) // #nosec G115 -- Java Long.hashCode
	case float64:
		bits := math.Float64bits(tv)
		return int64(int32(bits ^ (bits >> 32))) // #nosec G115 -- Java Double.hashCode
	case string:
		var h int32
		for _, r := range tv {
			h = 31*h + r
		}
		return int64(h)
	default:
		var h int32
		for _, r := range fmt.Sprintf("%v", v) {
			h = 31*h + r
		}
		return int64(h)
	}
}

// ============================================================================
// F21: IntSummaryStatistics, LongSummaryStatistics, DoubleSummaryStatistics
// ============================================================================

func newSummaryStatisticsMapPainless(statType string, hasArgs bool, count int64, minVal, maxVal, sumVal float64) (map[string]any, error) {
	if count < 0 {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "Negative count value",
		}
	}
	if !hasArgs || count == 0 {
		switch statType {
		case "IntSummaryStatistics":
			return map[string]any{
				"__type":  "IntSummaryStatistics",
				"count":   int64(0),
				"sum":     int64(0),
				"min":     int64(math.MaxInt32),
				"max":     int64(math.MinInt32),
				"average": float64(0),
			}, nil
		case "LongSummaryStatistics":
			return map[string]any{
				"__type":  "LongSummaryStatistics",
				"count":   int64(0),
				"sum":     int64(0),
				"min":     int64(math.MaxInt64),
				"max":     int64(math.MinInt64),
				"average": float64(0),
			}, nil
		default:
			return map[string]any{
				"__type":  "DoubleSummaryStatistics",
				"count":   int64(0),
				"sum":     float64(0),
				"min":     math.Inf(1),
				"max":     math.Inf(-1),
				"average": float64(0),
			}, nil
		}
	}
	if minVal > maxVal {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "Minimum greater than maximum",
		}
	}
	if statType == "DoubleSummaryStatistics" {
		nanCount := 0
		if math.IsNaN(minVal) {
			nanCount++
		}
		if math.IsNaN(maxVal) {
			nanCount++
		}
		if math.IsNaN(sumVal) {
			nanCount++
		}
		if nanCount > 0 && nanCount < 3 {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "Some, not all, of the minimum, maximum, or sum is NaN",
			}
		}
		if nanCount == 3 {
			return map[string]any{
				"__type":  "DoubleSummaryStatistics",
				"count":   count,
				"sum":     math.NaN(),
				"min":     math.NaN(),
				"max":     math.NaN(),
				"average": math.NaN(),
			}, nil
		}
	}
	avg := sumVal / float64(count)
	switch statType {
	case "IntSummaryStatistics":
		return map[string]any{
			"__type":  "IntSummaryStatistics",
			"count":   count,
			"sum":     int64(sumVal),
			"min":     int64(int32(minVal)), // #nosec G115 -- IntSummaryStatistics min is int32
			"max":     int64(int32(maxVal)), // #nosec G115 -- IntSummaryStatistics max is int32
			"average": avg,
		}, nil
	case "LongSummaryStatistics":
		return map[string]any{
			"__type":  "LongSummaryStatistics",
			"count":   count,
			"sum":     int64(sumVal),
			"min":     int64(minVal),
			"max":     int64(maxVal),
			"average": avg,
		}, nil
	default:
		return map[string]any{
			"__type":  "DoubleSummaryStatistics",
			"count":   count,
			"sum":     sumVal,
			"min":     minVal,
			"max":     maxVal,
			"average": avg,
		}, nil
	}
}

func isSummaryStatisticsMapPainless(m map[string]any) (string, bool) {
	if m == nil {
		return "", false
	}
	if t, ok := m["__type"].(string); ok {
		switch t {
		case "IntSummaryStatistics", "LongSummaryStatistics", "DoubleSummaryStatistics":
			return t, true
		}
	}
	return "", false
}

func toFloat64AllowNonFinitePainless(v any) (float64, bool) {
	if f, ok := v.(float64); ok {
		return f, true
	}
	return toFloat64(v)
}

func summaryStatisticsAcceptPainless(m map[string]any, val any) error {
	statType, ok := isSummaryStatisticsMapPainless(m)
	if !ok {
		return nil
	}
	fv, fOk := toFloat64AllowNonFinitePainless(val)
	if !fOk {
		return &painlessExceptionError{exType: "IllegalArgumentException", message: "SummaryStatistics.accept requires numeric argument"}
	}
	count, _ := toInt64Painless(m["count"])
	newCount := count + 1
	m["count"] = newCount
	if statType == "DoubleSummaryStatistics" {
		sum, _ := toFloat64AllowNonFinitePainless(m["sum"])
		minV, _ := toFloat64AllowNonFinitePainless(m["min"])
		maxV, _ := toFloat64AllowNonFinitePainless(m["max"])
		newSum := sum + fv
		if math.IsNaN(fv) || math.IsNaN(sum) || math.IsNaN(newSum) || (count > 0 && (math.IsNaN(minV) || math.IsNaN(maxV))) {
			m["sum"] = math.NaN()
			m["min"] = math.NaN()
			m["max"] = math.NaN()
			m["average"] = math.NaN()
			return nil
		}
		if count == 0 || fv < minV {
			minV = fv
		}
		if count == 0 || fv > maxV {
			maxV = fv
		}
		m["sum"] = newSum
		m["min"] = minV
		m["max"] = maxV
		m["average"] = newSum / float64(newCount)
		return nil
	}
	iv, _ := toInt64Painless(val)
	if statType == "IntSummaryStatistics" {
		iv = int64(int32(iv)) // #nosec G115 -- IntSummaryStatistics accepts int32
	}
	sum, _ := toInt64Painless(m["sum"])
	minV, _ := toInt64Painless(m["min"])
	maxV, _ := toInt64Painless(m["max"])
	newSum := sum + iv
	if count == 0 || iv < minV {
		minV = iv
	}
	if count == 0 || iv > maxV {
		maxV = iv
	}
	m["sum"] = newSum
	m["min"] = minV
	m["max"] = maxV
	m["average"] = float64(newSum) / float64(newCount)
	return nil
}

func summaryStatisticsCombinePainless(m map[string]any, other any) error {
	statType, ok := isSummaryStatisticsMapPainless(m)
	if !ok {
		return nil
	}
	if other == nil {
		return &painlessExceptionError{exType: "NullPointerException", message: "Cannot combine null SummaryStatistics"}
	}
	om, okO := other.(map[string]any)
	if !okO {
		return &painlessExceptionError{exType: "ClassCastException", message: "Expected SummaryStatistics"}
	}
	oCount, _ := toInt64Painless(om["count"])
	if oCount == 0 {
		return nil
	}
	count, _ := toInt64Painless(m["count"])
	newCount := count + oCount
	m["count"] = newCount
	if statType == "DoubleSummaryStatistics" {
		sum, _ := toFloat64AllowNonFinitePainless(m["sum"])
		oSum, _ := toFloat64AllowNonFinitePainless(om["sum"])
		minV, _ := toFloat64AllowNonFinitePainless(m["min"])
		oMin, _ := toFloat64AllowNonFinitePainless(om["min"])
		maxV, _ := toFloat64AllowNonFinitePainless(m["max"])
		oMax, _ := toFloat64AllowNonFinitePainless(om["max"])
		newSum := sum + oSum
		if math.IsNaN(sum) || math.IsNaN(oSum) || math.IsNaN(newSum) || math.IsNaN(oMin) || math.IsNaN(oMax) || (count > 0 && (math.IsNaN(minV) || math.IsNaN(maxV))) {
			m["sum"] = math.NaN()
			m["min"] = math.NaN()
			m["max"] = math.NaN()
			m["average"] = math.NaN()
			return nil
		}
		if count == 0 || oMin < minV {
			minV = oMin
		}
		if count == 0 || oMax > maxV {
			maxV = oMax
		}
		m["sum"] = newSum
		m["min"] = minV
		m["max"] = maxV
		m["average"] = newSum / float64(newCount)
		return nil
	}
	sum, _ := toInt64Painless(m["sum"])
	oSum, _ := toInt64Painless(om["sum"])
	minV, _ := toInt64Painless(m["min"])
	oMin, _ := toInt64Painless(om["min"])
	maxV, _ := toInt64Painless(m["max"])
	oMax, _ := toInt64Painless(om["max"])
	newSum := sum + oSum
	if count == 0 || oMin < minV {
		minV = oMin
	}
	if count == 0 || oMax > maxV {
		maxV = oMax
	}
	m["sum"] = newSum
	m["min"] = minV
	m["max"] = maxV
	m["average"] = float64(newSum) / float64(newCount)
	return nil
}

func formatSummaryStatisticsToStringPainless(m map[string]any) string {
	statType, ok := isSummaryStatisticsMapPainless(m)
	if !ok {
		return fmt.Sprintf("%v", m)
	}
	count, _ := toInt64Painless(m["count"])
	avg, _ := toFloat64AllowNonFinitePainless(m["average"])
	avgStr := fmt.Sprintf("%.6f", avg)
	if statType == "DoubleSummaryStatistics" {
		sum, _ := toFloat64AllowNonFinitePainless(m["sum"])
		minV, _ := toFloat64AllowNonFinitePainless(m["min"])
		maxV, _ := toFloat64AllowNonFinitePainless(m["max"])
		return fmt.Sprintf("%s{count=%d, sum=%f, min=%f, average=%s, max=%f}",
			statType, count, sum, minV, avgStr, maxV)
	}
	sum, _ := toInt64Painless(m["sum"])
	minV, _ := toInt64Painless(m["min"])
	maxV, _ := toInt64Painless(m["max"])
	return fmt.Sprintf("%s{count=%d, sum=%d, min=%d, average=%s, max=%d}",
		statType, count, sum, minV, avgStr, maxV)
}

func computeSummaryStatsWithKindPainless(items []any, fnExpr string, statType string, sourceMap, params map[string]any, depth int) (map[string]any, error) {
	if statType == "" {
		statType = "IntSummaryStatistics"
	}
	stats, _ := newSummaryStatisticsMapPainless(statType, false, 0, 0, 0, 0)
	if fnExpr != "" {
		fnExpr = normalizeMethodReferenceToLambdaPainless(fnExpr, 1)
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx > 0 {
			pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
			if len(pNames) > 0 {
				pName := pNames[0]
				body := fnExpr[arrowIdx+2:]
				prev, hadPrev := params[pName]
				for _, it := range items {
					params[pName] = it
					mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
					if err != nil {
						if hadPrev {
							params[pName] = prev
						} else {
							delete(params, pName)
						}
						return nil, err
					}
					if err := summaryStatisticsAcceptPainless(stats, mv); err != nil {
						if hadPrev {
							params[pName] = prev
						} else {
							delete(params, pName)
						}
						return nil, err
					}
				}
				if hadPrev {
					params[pName] = prev
				} else {
					delete(params, pName)
				}
			}
		}
		return stats, nil
	}
	for _, it := range items {
		if err := summaryStatisticsAcceptPainless(stats, it); err != nil {
			return nil, err
		}
	}
	return stats, nil
}

// ============================================================================
// F23: java.time.ZoneOffset, ZoneId, Clock, OffsetTime
// ============================================================================

func parseZoneOffsetSecondsPainless(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" {
		return 0, false
	}
	u := strings.ToUpper(s)
	if u == "Z" || u == "UTC" || u == "GMT" || u == "UT" {
		return 0, true
	}
	for _, pfx := range []string{"UTC", "GMT", "UT"} {
		if strings.HasPrefix(u, pfx) && len(s) > len(pfx) && (s[len(pfx)] == '+' || s[len(pfx)] == '-') {
			s = s[len(pfx):]
			break
		}
	}
	if s[0] != '+' && s[0] != '-' {
		if loc, err := time.LoadLocation(s); err == nil {
			_, off := time.Date(2020, 1, 1, 0, 0, 0, 0, loc).Zone()
			return off, true
		}
		return 0, false
	}
	sign := 1
	if s[0] == '-' {
		sign = -1
	}
	rest := s[1:]
	var hh, mm, ss int
	var err error
	if strings.Contains(rest, ":") {
		parts := strings.Split(rest, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return 0, false
		}
		hh, err = strconv.Atoi(parts[0])
		if err != nil {
			return 0, false
		}
		mm, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, false
		}
		if len(parts) == 3 {
			ss, err = strconv.Atoi(parts[2])
			if err != nil {
				return 0, false
			}
		}
	} else {
		switch len(rest) {
		case 1, 2:
			hh, err = strconv.Atoi(rest)
		case 4:
			hh, err = strconv.Atoi(rest[:2])
			if err == nil {
				mm, err = strconv.Atoi(rest[2:4])
			}
		case 6:
			hh, err = strconv.Atoi(rest[:2])
			if err == nil {
				mm, err = strconv.Atoi(rest[2:4])
			}
			if err == nil {
				ss, err = strconv.Atoi(rest[4:6])
			}
		default:
			return 0, false
		}
		if err != nil {
			return 0, false
		}
	}
	if hh < 0 || hh > 18 || mm < 0 || mm > 59 || ss < 0 || ss > 59 {
		return 0, false
	}
	total := sign * (hh*3600 + mm*60 + ss)
	if total < -64800 || total > 64800 {
		return 0, false
	}
	return total, true
}

func formatZoneOffsetSecondsPainless(totalSeconds int) string {
	if totalSeconds == 0 {
		return "Z"
	}
	sign := "+"
	absSec := totalSeconds
	if absSec < 0 {
		sign = "-"
		absSec = -absSec
	}
	hh := absSec / 3600
	mm := (absSec % 3600) / 60
	ss := absSec % 60
	if ss != 0 {
		return fmt.Sprintf("%s%02d:%02d:%02d", sign, hh, mm, ss)
	}
	return fmt.Sprintf("%s%02d:%02d", sign, hh, mm)
}

func validateAndCreateZoneOffsetHMSSpainless(hours, minutes, seconds int) (string, error) {
	if hours < -18 || hours > 18 {
		return "", &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Zone offset hours not in valid range: value %d is not in the range -18 to 18", hours)}
	}
	if hours > 0 {
		if minutes < 0 || seconds < 0 {
			return "", &painlessExceptionError{exType: "DateTimeException", message: "Zone offset minutes and seconds must be positive because hours is positive"}
		}
	} else if hours < 0 {
		if minutes > 0 || seconds > 0 {
			return "", &painlessExceptionError{exType: "DateTimeException", message: "Zone offset minutes and seconds must be negative because hours is negative"}
		}
	} else if (minutes > 0 && seconds < 0) || (minutes < 0 && seconds > 0) {
		return "", &painlessExceptionError{exType: "DateTimeException", message: "Zone offset minutes and seconds must have the same sign"}
	}
	if minutes < -59 || minutes > 59 {
		return "", &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Zone offset minutes not in valid range: %d", minutes)}
	}
	if seconds < -59 || seconds > 59 {
		return "", &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Zone offset seconds not in valid range: %d", seconds)}
	}
	total := hours*3600 + minutes*60 + seconds
	if total < -64800 || total > 64800 {
		return "", &painlessExceptionError{exType: "DateTimeException", message: "Zone offset not in valid range: -18:00 to +18:00"}
	}
	return formatZoneOffsetSecondsPainless(total), nil
}

type painlessClock struct {
	kind      string // "SystemClock", "FixedClock", "OffsetClock", "TickClock"
	zone      string
	fixedTime time.Time
	hasFixed  bool
	offsetDur time.Duration
	tickNanos int64
	baseNowMs int64
}

func (c *painlessClock) currentTime(budgetNowMs int64) time.Time {
	if c == nil {
		return time.UnixMilli(budgetNowMs).UTC()
	}
	var tm time.Time
	if c.hasFixed {
		tm = c.fixedTime
	} else {
		ms := c.baseNowMs
		if ms == 0 {
			ms = budgetNowMs
		}
		if ms == 0 {
			ms = time.Now().UnixMilli()
		}
		tm = time.UnixMilli(ms).UTC()
	}
	if c.offsetDur != 0 {
		tm = tm.Add(c.offsetDur)
	}
	if c.tickNanos > 1 {
		epochNanos := tm.UnixNano()
		floored := epochNanos - (epochNanos % c.tickNanos)
		if epochNanos < 0 && epochNanos%c.tickNanos != 0 {
			floored -= c.tickNanos
		}
		tm = time.Unix(0, floored).UTC()
	}
	loc := parseZoneLocationPainless(c.zone)
	return tm.In(loc)
}

func (c *painlessClock) String() string {
	if c == nil {
		return "SystemClock[Z]"
	}
	z := c.zone
	if z == "" {
		z = "Z"
	}
	switch c.kind {
	case "FixedClock":
		return fmt.Sprintf("FixedClock[%s,%s]", c.fixedTime.UTC().Format(time.RFC3339Nano), z)
	case "OffsetClock":
		return fmt.Sprintf("OffsetClock[SystemClock[%s],%s]", z, formatDurationISO8601Painless(c.offsetDur))
	case "TickClock":
		return fmt.Sprintf("TickClock[SystemClock[%s],%s]", z, formatDurationISO8601Painless(time.Duration(c.tickNanos)))
	default:
		return fmt.Sprintf("SystemClock[%s]", z)
	}
}

func (c *painlessClock) equals(other any) bool {
	o, ok := other.(*painlessClock)
	if !ok || c == nil || o == nil {
		return false
	}
	return c.kind == o.kind && c.zone == o.zone && c.hasFixed == o.hasFixed &&
		(!c.hasFixed || c.fixedTime.Equal(o.fixedTime)) &&
		c.offsetDur == o.offsetDur && c.tickNanos == o.tickNanos
}

func (c *painlessClock) hashCode() int64 {
	if c == nil {
		return 0
	}
	return computeJavaHashCodePainless(c.String())
}

// painlessOffsetTime represents a java.time.OffsetTime in Painless.
type painlessOffsetTime struct {
	hour          int
	minute        int
	second        int
	nano          int
	offsetSeconds int
}

func newPainlessOffsetTime(hour, minute, second, nano, offsetSeconds int) (*painlessOffsetTime, error) {
	if hour < 0 || hour > 23 {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid value for HourOfDay (valid values 0 - 23): %d", hour)}
	}
	if minute < 0 || minute > 59 {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid value for MinuteOfHour (valid values 0 - 59): %d", minute)}
	}
	if second < 0 || second > 59 {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid value for SecondOfMinute (valid values 0 - 59): %d", second)}
	}
	if nano < 0 || nano > 999_999_999 {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid value for NanoOfSecond (valid values 0 - 999999999): %d", nano)}
	}
	if offsetSeconds < -64800 || offsetSeconds > 64800 {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Zone offset not in valid range: %d", offsetSeconds)}
	}
	return &painlessOffsetTime{
		hour:          hour,
		minute:        minute,
		second:        second,
		nano:          nano,
		offsetSeconds: offsetSeconds,
	}, nil
}

func parsePainlessOffsetTime(v any) (*painlessOffsetTime, bool) {
	if ot, ok := v.(*painlessOffsetTime); ok && ot != nil {
		return ot, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	var timePart, offPart string
	if strings.HasSuffix(s, "Z") || strings.HasSuffix(s, "z") {
		timePart = s[:len(s)-1]
		offPart = "Z"
	} else if idx := strings.LastIndexAny(s, "+-"); idx > 0 {
		timePart = s[:idx]
		offPart = s[idx:]
	} else {
		return nil, false
	}
	h, m, sec, nano, okT := parseLocalTimeComponentsPainless(timePart)
	if !okT {
		return nil, false
	}
	offSec, okO := parseZoneOffsetSecondsPainless(offPart)
	if !okO {
		return nil, false
	}
	ot, err := newPainlessOffsetTime(h, m, sec, nano, offSec)
	if err != nil {
		return nil, false
	}
	return ot, true
}

func (ot *painlessOffsetTime) toEpochNanoOnZeroDay() int64 {
	localNanos := int64(ot.hour*3600+ot.minute*60+ot.second)*1_000_000_000 + int64(ot.nano)
	return localNanos - int64(ot.offsetSeconds)*1_000_000_000
}

func (ot *painlessOffsetTime) addNanos(deltaNanos int64) *painlessOffsetTime {
	const nanosPerDay = 24 * 3600 * 1_000_000_000
	curNanos := int64(ot.hour*3600+ot.minute*60+ot.second)*1_000_000_000 + int64(ot.nano)
	next := (curNanos + (deltaNanos % nanosPerDay) + nanosPerDay) % nanosPerDay
	secOfDay := int(next / 1_000_000_000)
	nano := int(next % 1_000_000_000)
	return &painlessOffsetTime{
		hour:          secOfDay / 3600,
		minute:        (secOfDay % 3600) / 60,
		second:        secOfDay % 60,
		nano:          nano,
		offsetSeconds: ot.offsetSeconds,
	}
}

func (ot *painlessOffsetTime) String() string {
	if ot == nil {
		return "00:00Z"
	}
	return formatLocalTimePainless(ot.hour, ot.minute, ot.second, ot.nano) + formatZoneOffsetSecondsPainless(ot.offsetSeconds)
}

func (ot *painlessOffsetTime) equals(other any) bool {
	o, ok := parsePainlessOffsetTime(other)
	if !ok || ot == nil || o == nil {
		return false
	}
	return ot.hour == o.hour && ot.minute == o.minute && ot.second == o.second && ot.nano == o.nano && ot.offsetSeconds == o.offsetSeconds
}

func (ot *painlessOffsetTime) compareTo(other *painlessOffsetTime) int {
	if ot == nil || other == nil {
		return 0
	}
	if ot.offsetSeconds == other.offsetSeconds {
		n1 := int64(ot.hour*3600+ot.minute*60+ot.second)*1_000_000_000 + int64(ot.nano)
		n2 := int64(other.hour*3600+other.minute*60+other.second)*1_000_000_000 + int64(other.nano)
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
		return 0
	}
	e1 := ot.toEpochNanoOnZeroDay()
	e2 := other.toEpochNanoOnZeroDay()
	if e1 < e2 {
		return -1
	}
	if e1 > e2 {
		return 1
	}
	n1 := int64(ot.hour*3600+ot.minute*60+ot.second)*1_000_000_000 + int64(ot.nano)
	n2 := int64(other.hour*3600+other.minute*60+other.second)*1_000_000_000 + int64(other.nano)
	if n1 < n2 {
		return -1
	}
	if n1 > n2 {
		return 1
	}
	return 0
}

func (ot *painlessOffsetTime) hashCode() int64 {
	if ot == nil {
		return 0
	}
	nod := int64(ot.hour*3600+ot.minute*60+ot.second)*1_000_000_000 + int64(ot.nano)
	return int64(int32(nod^(nod>>32))) ^ int64(int32(ot.offsetSeconds)) // #nosec G115 -- Java OffsetTime.hashCode
}

// painlessValueRange represents java.time.temporal.ValueRange in Painless.
type painlessValueRange struct {
	minSmallest int64
	minLargest  int64
	maxSmallest int64
	maxLargest  int64
}

func newFixedValueRangePainless(minV, maxV int64) *painlessValueRange {
	return &painlessValueRange{
		minSmallest: minV,
		minLargest:  minV,
		maxSmallest: maxV,
		maxLargest:  maxV,
	}
}

func (vr *painlessValueRange) isFixed() bool {
	return vr != nil && vr.minSmallest == vr.minLargest && vr.maxSmallest == vr.maxLargest
}

func (vr *painlessValueRange) isIntValue() bool {
	return vr != nil && vr.minSmallest >= math.MinInt32 && vr.maxLargest <= math.MaxInt32
}

func (vr *painlessValueRange) isValidValue(v int64) bool {
	return vr != nil && v >= vr.minSmallest && v <= vr.maxLargest
}

func (vr *painlessValueRange) isValidIntValue(v int64) bool {
	return vr.isIntValue() && vr.isValidValue(v)
}

func (vr *painlessValueRange) String() string {
	if vr == nil {
		return "0 - 0"
	}
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "%d", vr.minSmallest)
	if vr.minSmallest != vr.minLargest {
		_, _ = fmt.Fprintf(&sb, "/%d", vr.minLargest)
	}
	sb.WriteString(" - ")
	_, _ = fmt.Fprintf(&sb, "%d", vr.maxSmallest)
	if vr.maxSmallest != vr.maxLargest {
		_, _ = fmt.Fprintf(&sb, "/%d", vr.maxLargest)
	}
	return sb.String()
}

func (vr *painlessValueRange) equals(other any) bool {
	o, ok := other.(*painlessValueRange)
	if !ok || vr == nil || o == nil {
		return false
	}
	return vr.minSmallest == o.minSmallest && vr.minLargest == o.minLargest &&
		vr.maxSmallest == o.maxSmallest && vr.maxLargest == o.maxLargest
}

func (vr *painlessValueRange) hashCode() int64 {
	if vr == nil {
		return 0
	}
	return computeJavaHashCodePainless(vr.String())
}

func evalChronoFieldRangePainless(cf painlessChronoField) (*painlessValueRange, error) {
	field := strings.ToUpper(string(cf))
	switch field {
	case "NANO_OF_SECOND":
		return newFixedValueRangePainless(0, 999_999_999), nil
	case "NANO_OF_DAY":
		return newFixedValueRangePainless(0, 86400*1_000_000_000-1), nil
	case "MICRO_OF_SECOND":
		return newFixedValueRangePainless(0, 999_999), nil
	case "MICRO_OF_DAY":
		return newFixedValueRangePainless(0, 86400*1_000_000-1), nil
	case "MILLI_OF_SECOND":
		return newFixedValueRangePainless(0, 999), nil
	case "MILLI_OF_DAY":
		return newFixedValueRangePainless(0, 86400*1_000-1), nil
	case "SECOND_OF_MINUTE":
		return newFixedValueRangePainless(0, 59), nil
	case "SECOND_OF_DAY":
		return newFixedValueRangePainless(0, 86400-1), nil
	case "MINUTE_OF_HOUR":
		return newFixedValueRangePainless(0, 59), nil
	case "MINUTE_OF_DAY":
		return newFixedValueRangePainless(0, 24*60-1), nil
	case "HOUR_OF_AMPM":
		return newFixedValueRangePainless(0, 11), nil
	case "CLOCK_HOUR_OF_AMPM":
		return newFixedValueRangePainless(1, 12), nil
	case "HOUR_OF_DAY":
		return newFixedValueRangePainless(0, 23), nil
	case "CLOCK_HOUR_OF_DAY":
		return newFixedValueRangePainless(1, 24), nil
	case "AMPM_OF_DAY":
		return newFixedValueRangePainless(0, 1), nil
	case "DAY_OF_WEEK", "ALIGNED_DAY_OF_WEEK_IN_MONTH", "ALIGNED_DAY_OF_WEEK_IN_YEAR":
		return newFixedValueRangePainless(1, 7), nil
	case "DAY_OF_MONTH":
		return &painlessValueRange{minSmallest: 1, minLargest: 1, maxSmallest: 28, maxLargest: 31}, nil
	case "DAY_OF_YEAR":
		return &painlessValueRange{minSmallest: 1, minLargest: 1, maxSmallest: 365, maxLargest: 366}, nil
	case "EPOCH_DAY":
		return newFixedValueRangePainless(-365243219162, 365241780471), nil
	case "ALIGNED_WEEK_OF_MONTH":
		return &painlessValueRange{minSmallest: 1, minLargest: 1, maxSmallest: 4, maxLargest: 5}, nil
	case "ALIGNED_WEEK_OF_YEAR":
		return newFixedValueRangePainless(1, 53), nil
	case "MONTH_OF_YEAR":
		return newFixedValueRangePainless(1, 12), nil
	case "PROLEPTIC_MONTH":
		return newFixedValueRangePainless(-11999999988, 11999999999), nil
	case "YEAR_OF_ERA":
		return &painlessValueRange{minSmallest: 1, minLargest: 1, maxSmallest: 999_999_999, maxLargest: 1_000_000_000}, nil
	case "YEAR":
		return newFixedValueRangePainless(-999_999_999, 999_999_999), nil
	case "ERA":
		return newFixedValueRangePainless(0, 1), nil
	case "INSTANT_SECONDS":
		return newFixedValueRangePainless(math.MinInt64, math.MaxInt64), nil
	case "OFFSET_SECONDS":
		return newFixedValueRangePainless(-18*3600, 18*3600), nil
	default:
		return nil, &painlessExceptionError{
			exType:  "UnsupportedTemporalTypeException",
			message: "Unsupported field: " + field,
		}
	}
}

func evalTemporalRangePainless(recVal any, cf painlessChronoField) (*painlessValueRange, error) {
	field := strings.ToUpper(string(cf))
	if !evalIsSupportedChronoFieldPainless(recVal, cf) {
		return nil, &painlessExceptionError{
			exType:  "UnsupportedTemporalTypeException",
			message: "Unsupported field: " + field,
		}
	}
	base, err := evalChronoFieldRangePainless(cf)
	if err != nil {
		return nil, err
	}
	switch field {
	case "DAY_OF_MONTH":
		if md, ok := recVal.(painlessMonthDay); ok {
			maxD := int64(31)
			switch md.month {
			case 2:
				return &painlessValueRange{minSmallest: 1, minLargest: 1, maxSmallest: 28, maxLargest: 29}, nil
			case 4, 6, 9, 11:
				maxD = 30
			}
			return newFixedValueRangePainless(1, maxD), nil
		}
		if s, ok := recVal.(string); ok {
			if tm, okT := parsePainlessDateTime(s); okT {
				return newFixedValueRangePainless(1, int64(daysInMonthPainless(tm.Year(), tm.Month()))), nil
			}
		}
	case "DAY_OF_YEAR":
		if yr, ok := recVal.(painlessYear); ok {
			if yr.isLeap() {
				return newFixedValueRangePainless(1, 366), nil
			}
			return newFixedValueRangePainless(1, 365), nil
		}
		if s, ok := recVal.(string); ok {
			if tm, okT := parsePainlessDateTime(s); okT {
				if isLeapYearPainless(tm.Year()) {
					return newFixedValueRangePainless(1, 366), nil
				}
				return newFixedValueRangePainless(1, 365), nil
			}
		}
	case "ALIGNED_WEEK_OF_MONTH":
		if s, ok := recVal.(string); ok {
			if tm, okT := parsePainlessDateTime(s); okT {
				if tm.Month() == time.February && !isLeapYearPainless(tm.Year()) {
					return newFixedValueRangePainless(1, 4), nil
				}
				return newFixedValueRangePainless(1, 5), nil
			}
		}
	case "YEAR_OF_ERA":
		if yr, ok := recVal.(painlessYear); ok {
			if yr.year <= 0 {
				return newFixedValueRangePainless(1, 1_000_000_000), nil
			}
			return newFixedValueRangePainless(1, 999_999_999), nil
		}
		if s, ok := recVal.(string); ok {
			if tm, okT := parsePainlessDateTime(s); okT {
				if tm.Year() <= 0 {
					return newFixedValueRangePainless(1, 1_000_000_000), nil
				}
				return newFixedValueRangePainless(1, 999_999_999), nil
			}
		}
	}
	return base, nil
}

// ============================================================================
// F24: Pattern.asPredicate, Pattern.asMatchPredicate, painlessPredicate
// ============================================================================

type painlessPredicate struct {
	fn func(val any, sourceMap, params map[string]any, depth int) (bool, error)
}

func (p *painlessPredicate) test(val any, sourceMap, params map[string]any, depth int) (bool, error) {
	if p == nil || p.fn == nil {
		return false, nil
	}
	return p.fn(val, sourceMap, params, depth)
}

func (p *painlessPredicate) String() string {
	return "Predicate"
}

func extractPatternRegexpPainless(recVal any) (*regexp.Regexp, string, error) {
	switch tv := recVal.(type) {
	case *painlessPattern:
		if tv != nil && tv.re != nil {
			return tv.re, tv.raw, nil
		}
	case *regexp.Regexp:
		if tv != nil {
			return tv, tv.String(), nil
		}
	case string:
		patStr := tv
		if isRawRegexLiteralPainless(patStr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
			patStr = strings.ReplaceAll(patStr[1:len(patStr)-1], `\/`, `/`)
		}
		re, err := compilePainlessRegexp(patStr)
		return re, patStr, err
	}
	return nil, "", fmt.Errorf("not a Pattern")
}

// ============================================================================
// F25: User-Defined Classes Inheritance, super, static, toString/equals/hashCode
// ============================================================================

func (cls *painlessUserClass) isInstanceOf(targetType string) bool {
	for cur := cls; cur != nil; cur = cur.parent {
		if cur.name == targetType {
			return true
		}
	}
	return false
}

func (cls *painlessUserClass) allInstanceFields() []painlessUserField {
	if cls == nil {
		return nil
	}
	var out []painlessUserField
	if cls.parent != nil {
		out = append(out, cls.parent.allInstanceFields()...)
	}
	out = append(out, cls.fields...)
	return out
}

func (cls *painlessUserClass) findMethodWithOwner(name string) ([]*painlessUserFunc, *painlessUserClass) {
	for cur := cls; cur != nil; cur = cur.parent {
		if overloads := cur.methods[name]; len(overloads) > 0 {
			return overloads, cur
		}
	}
	return nil, nil
}

func (cls *painlessUserClass) findMethod(name string) []*painlessUserFunc {
	overloads, _ := cls.findMethodWithOwner(name)
	return overloads
}

func (cls *painlessUserClass) findStaticMethodWithOwner(name string) ([]*painlessUserFunc, *painlessUserClass) {
	for cur := cls; cur != nil; cur = cur.parent {
		if cur.staticMethods != nil {
			if overloads := cur.staticMethods[name]; len(overloads) > 0 {
				return overloads, cur
			}
		}
	}
	return nil, nil
}

func (cls *painlessUserClass) getStaticField(name string) (any, bool) {
	for cur := cls; cur != nil; cur = cur.parent {
		if cur.staticValues != nil {
			if v, ok := cur.staticValues[name]; ok {
				return v, true
			}
		}
	}
	return nil, false
}

func (cls *painlessUserClass) setStaticField(name string, val any) bool {
	for cur := cls; cur != nil; cur = cur.parent {
		if cur.staticValues != nil {
			if _, ok := cur.staticValues[name]; ok {
				cur.staticValues[name] = val
				return true
			}
		}
	}
	return false
}

func parseUserClassDeclRound54(stmt string) (*painlessUserClass, bool) {
	t := strings.TrimSpace(stmt)
	if !strings.HasPrefix(t, "class ") && !strings.HasPrefix(t, "class\t") && !strings.HasPrefix(t, "class\n") {
		return nil, false
	}
	rest := strings.TrimSpace(t[len("class"):])
	openBrace := strings.IndexByte(rest, '{')
	if openBrace <= 0 {
		return nil, false
	}
	hdrPart := strings.TrimSpace(rest[:openBrace])
	var className, parentName string
	if extIdx := strings.Index(hdrPart, " extends "); extIdx > 0 {
		className = strings.TrimSpace(hdrPart[:extIdx])
		parentName = strings.TrimSpace(hdrPart[extIdx+len(" extends "):])
		if !reIdentOnly.MatchString(parentName) {
			return nil, false
		}
	} else {
		className = hdrPart
	}
	if !reIdentOnly.MatchString(className) || isPainlessReservedKeyword(className) {
		return nil, false
	}
	bodyPart := strings.TrimSpace(rest[openBrace:])
	if !strings.HasPrefix(bodyPart, "{") || findMatchingDelimiter(bodyPart, 0, '{', '}') != len(bodyPart)-1 {
		return nil, false
	}
	classBody := strings.TrimSpace(bodyPart[1 : len(bodyPart)-1])
	cls := &painlessUserClass{
		name:          className,
		parentName:    parentName,
		methods:       make(map[string][]*painlessUserFunc),
		staticMethods: make(map[string][]*painlessUserFunc),
		staticValues:  make(map[string]any),
	}
	memberStmts := splitTopLevelStatements(classBody)
	for _, mStmt := range memberStmts {
		mStmt = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(mStmt), ";"))
		if mStmt == "" {
			continue
		}
		isStatic := false
		for {
			trimmed := false
			for _, mod := range []string{"public ", "private ", "protected ", "final ", "static "} {
				if strings.HasPrefix(mStmt, mod) {
					if mod == "static " {
						isStatic = true
					}
					mStmt = strings.TrimSpace(mStmt[len(mod):])
					trimmed = true
				}
			}
			if !trimmed {
				break
			}
		}
		// Check constructor: <ClassName>(...) { ... }
		if !isStatic {
			if openP := strings.IndexByte(mStmt, '('); openP > 0 {
				hdr := strings.TrimSpace(mStmt[:openP])
				if hdr == className {
					closeP := findMatchingDelimiter(mStmt, openP, '(', ')')
					if closeP > openP {
						afterP := strings.TrimSpace(mStmt[closeP+1:])
						if strings.HasPrefix(afterP, "{") && findMatchingDelimiter(afterP, 0, '{', '}') == len(afterP)-1 {
							ctor := &painlessUserFunc{
								name:       className,
								returnType: className,
								paramNames: parseParamListNamesPainless(mStmt[openP+1 : closeP]),
								body:       strings.TrimSpace(afterP[1 : len(afterP)-1]),
							}
							cls.constructors = append(cls.constructors, ctor)
							continue
						}
					}
				}
			}
		}
		if fnDecl, ok := parseUserFuncDecl(mStmt); ok {
			if isStatic {
				cls.staticMethods[fnDecl.name] = append(cls.staticMethods[fnDecl.name], fnDecl)
			} else {
				cls.methods[fnDecl.name] = append(cls.methods[fnDecl.name], fnDecl)
			}
			continue
		}
		// Parse field declaration(s)
		parts := splitTopLevelCommaPainless(mStmt)
		var sharedType string
		for idx, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			var declPart, initExpr string
			if eqIdx := findTopLevelAssignOpStartPainless(part); eqIdx > 0 && part[eqIdx] == '=' {
				declPart = strings.TrimSpace(part[:eqIdx])
				initExpr = strings.TrimSpace(part[eqIdx+1:])
			} else {
				declPart = part
			}
			var fieldName string
			if idx == 0 {
				lastSpace := strings.LastIndexAny(declPart, " \t\n\r>]")
				if lastSpace > 0 {
					if declPart[lastSpace] == '>' || declPart[lastSpace] == ']' {
						sharedType = strings.TrimSpace(declPart[:lastSpace+1])
					} else {
						sharedType = strings.TrimSpace(declPart[:lastSpace])
					}
					fieldName = strings.TrimSpace(declPart[lastSpace+1:])
				}
			} else if reIdentOnly.MatchString(declPart) && sharedType != "" {
				fieldName = declPart
			}
			if fieldName != "" && reIdentOnly.MatchString(fieldName) {
				fld := painlessUserField{
					name:     fieldName,
					typeName: sharedType,
					initExpr: initExpr,
				}
				if isStatic {
					cls.staticFields = append(cls.staticFields, fld)
				} else {
					cls.fields = append(cls.fields, fld)
				}
			}
		}
	}
	return cls, true
}

func registerUserClassRound54(budget *evalBudget, cls *painlessUserClass, sourceMap, params map[string]any) {
	if budget == nil || cls == nil {
		return
	}
	if budget.userClasses == nil {
		budget.userClasses = make(map[string]*painlessUserClass)
	}
	if cls.parentName != "" {
		cls.parent = budget.userClasses[cls.parentName]
	}
	if cls.staticValues == nil {
		cls.staticValues = make(map[string]any)
	}
	budget.userClasses[cls.name] = cls
	for _, sf := range cls.staticFields {
		if sf.initExpr != "" {
			if val, err := evalRHSExprDepth(sourceMap, sf.initExpr, params, 0); err == nil {
				cls.staticValues[sf.name] = val
				continue
			}
		}
		switch sf.typeName {
		case "int", "long", "short", "byte":
			cls.staticValues[sf.name] = int64(0)
		case "double", "float":
			cls.staticValues[sf.name] = float64(0)
		case "boolean":
			cls.staticValues[sf.name] = false
		default:
			cls.staticValues[sf.name] = nil
		}
	}
}

func runUserClassConstructorChainPainless(uo *painlessUserObject, cls *painlessUserClass, argVals []any, sourceMap, params map[string]any, depth int) error {
	if uo == nil || cls == nil {
		return nil
	}
	var matchedCtor *painlessUserFunc
	for _, ctor := range cls.constructors {
		if len(ctor.paramNames) == len(argVals) {
			matchedCtor = ctor
			break
		}
	}
	body := ""
	if matchedCtor != nil {
		body = matchedCtor.body
	}
	// Check if first statement in constructor body is `this(...)` or `super(...)`
	calledSuper := false
	stmts := splitTopLevelStatements(body)
	if len(stmts) > 0 {
		first := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmts[0]), ";"))
		if strings.HasPrefix(first, "this(") && strings.HasSuffix(first, ")") && findMatchingDelimiter(first, 4, '(', ')') == len(first)-1 {
			ctorScope := make(map[string]any, len(params)+8)
			for k, v := range params {
				ctorScope[k] = v
			}
			ctorScope["this"] = uo
			ctorScope["__current_class"] = cls
			if matchedCtor != nil {
				for i, pName := range matchedCtor.paramNames {
					if i < len(argVals) {
						ctorScope[pName] = argVals[i]
					}
				}
			}
			thisArgStr := strings.TrimSpace(first[5 : len(first)-1])
			var thisArgs []any
			if thisArgStr != "" {
				for _, ra := range splitTopLevelCommaPainless(thisArgStr) {
					av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(ra), ctorScope, depth+1)
					if err != nil {
						return err
					}
					thisArgs = append(thisArgs, av)
				}
			}
			if err := runUserClassConstructorChainPainless(uo, cls, thisArgs, sourceMap, params, depth+1); err != nil {
				return err
			}
			calledSuper = true
			body = strings.Join(stmts[1:], "; ")
		} else if strings.HasPrefix(first, "super(") && strings.HasSuffix(first, ")") && findMatchingDelimiter(first, 5, '(', ')') == len(first)-1 {
			if cls.parent != nil {
				ctorScope := make(map[string]any, len(params)+8)
				for k, v := range params {
					ctorScope[k] = v
				}
				ctorScope["this"] = uo
				ctorScope["__current_class"] = cls
				if matchedCtor != nil {
					for i, pName := range matchedCtor.paramNames {
						if i < len(argVals) {
							ctorScope[pName] = argVals[i]
						}
					}
				}
				superArgStr := strings.TrimSpace(first[6 : len(first)-1])
				var superArgs []any
				if superArgStr != "" {
					for _, ra := range splitTopLevelCommaPainless(superArgStr) {
						av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(ra), ctorScope, depth+1)
						if err != nil {
							return err
						}
						superArgs = append(superArgs, av)
					}
				}
				if err := runUserClassConstructorChainPainless(uo, cls.parent, superArgs, sourceMap, params, depth+1); err != nil {
					return err
				}
			}
			calledSuper = true
			body = strings.Join(stmts[1:], "; ")
		}
	}
	if !calledSuper && cls.parent != nil {
		if err := runUserClassConstructorChainPainless(uo, cls.parent, nil, sourceMap, params, depth+1); err != nil {
			return err
		}
	}
	if matchedCtor != nil && strings.TrimSpace(body) != "" {
		budget := getOrInitEvalBudget(params)
		ctorScope := make(map[string]any, len(params)+len(matchedCtor.paramNames)+4)
		for k, v := range params {
			ctorScope[k] = v
		}
		ctorScope["this"] = uo
		ctorScope["__current_class"] = cls
		methodParams := make(map[string]bool, len(matchedCtor.paramNames))
		for i, pName := range matchedCtor.paramNames {
			if i < len(argVals) {
				ctorScope[pName] = argVals[i]
			}
			methodParams[pName] = true
		}
		ctorScope["__method_params"] = methodParams
		ctorScope["__script_locals"] = make(map[string]bool)
		ctxOp := ""
		if err := execBlock(sourceMap, body, ctorScope, &ctxOp, budget); err != nil && !errors.Is(err, errPainlessReturn) {
			return err
		}
	}
	return nil
}

func evalUserClassMethodOnClassPainless(uo *painlessUserObject, targetCls *painlessUserClass, methodName, argStr string, isStatic bool, sourceMap, params map[string]any, depth int) (any, error) {
	if targetCls == nil {
		return nil, nil
	}
	var argVals []any
	if strings.TrimSpace(argStr) != "" {
		rawArgs := splitTopLevelCommaPainless(argStr)
		argVals = make([]any, 0, len(rawArgs))
		for _, ra := range rawArgs {
			av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(ra), params, depth+1)
			if err != nil {
				return nil, err
			}
			argVals = append(argVals, av)
		}
	}
	return evalUserClassMethodWithArgsPainless(uo, targetCls, methodName, argVals, isStatic, sourceMap, params, depth)
}

func evalUserClassMethodWithArgsPainless(uo *painlessUserObject, targetCls *painlessUserClass, methodName string, argVals []any, isStatic bool, sourceMap, params map[string]any, depth int) (any, error) {
	if targetCls == nil {
		return nil, nil
	}
	var overloads []*painlessUserFunc
	var ownerCls *painlessUserClass
	if isStatic {
		overloads, ownerCls = targetCls.findStaticMethodWithOwner(methodName)
	} else {
		overloads, ownerCls = targetCls.findMethodWithOwner(methodName)
		if len(overloads) == 0 {
			overloads, ownerCls = targetCls.findStaticMethodWithOwner(methodName)
		}
	}
	var fn *painlessUserFunc
	if len(overloads) > 0 {
		for _, cand := range overloads {
			if len(cand.paramNames) == len(argVals) {
				fn = cand
				break
			}
		}
		if fn == nil {
			fn = overloads[0]
		}
	}
	if fn == nil {
		return nil, nil
	}
	budget := getOrInitEvalBudget(params)
	if err := budget.step(); err != nil {
		return nil, err
	}
	mScope := make(map[string]any, len(params)+len(fn.paramNames)+4)
	for k, v := range params {
		if k == "_return_val" || k == "_last_expr_val" {
			continue
		}
		mScope[k] = v
	}
	if uo != nil {
		mScope["this"] = uo
	} else {
		delete(mScope, "this")
	}
	mScope["__current_class"] = ownerCls
	methodParams := make(map[string]bool, len(fn.paramNames))
	for i, pName := range fn.paramNames {
		if i < len(argVals) {
			mScope[pName] = argVals[i]
		}
		methodParams[pName] = true
	}
	mScope["__method_params"] = methodParams
	mScope["__script_locals"] = make(map[string]bool)
	ctxOp := ""
	err := execBlock(sourceMap, fn.body, mScope, &ctxOp, budget)
	if err != nil && !errors.Is(err, errPainlessReturn) {
		return nil, err
	}
	if fn.returnType == "void" {
		return nil, nil
	}
	if retVal, hasRet := mScope["_return_val"]; hasRet {
		return retVal, nil
	}
	return mScope["_last_expr_val"], nil
}

func evalValueHashCodePainless(v any, sourceMap, params map[string]any, depth int) int64 {
	if v == nil || v == painlessEmptyOptional {
		return 0
	}
	switch tv := v.(type) {
	case *painlessOptional:
		return tv.hashCode()
	case *painlessOffsetTime:
		return tv.hashCode()
	case *painlessClock:
		return tv.hashCode()
	case *painlessURI:
		return tv.hashCode()
	case *painlessURL:
		return tv.hashCode()
	case *painlessUserObject:
		if tv != nil && tv.class != nil && tv.class.findMethod("hashCode") != nil {
			if res, err := evalUserClassMethodWithArgsPainless(tv, tv.class, "hashCode", nil, false, sourceMap, params, depth+1); err == nil {
				if iv, ok := toInt64Painless(res); ok {
					return iv
				}
			}
		}
	}
	return computeJavaHashCodePainless(v)
}

// ============================================================================
// F26: java.util.UUID Version-1 & Signed compareTo, java.net.URI & java.net.URL
// ============================================================================

func parseUUIDBitsPainless(s string) (msb uint64, lsb uint64, ok bool) {
	norm, valid := parseAndFormatUUIDPainless(s)
	if !valid {
		return 0, 0, false
	}
	parts := strings.Split(norm, "-")
	p0, _ := strconv.ParseUint(parts[0], 16, 64)
	p1, _ := strconv.ParseUint(parts[1], 16, 64)
	p2, _ := strconv.ParseUint(parts[2], 16, 64)
	p3, _ := strconv.ParseUint(parts[3], 16, 64)
	p4, _ := strconv.ParseUint(parts[4], 16, 64)
	msb = (p0 << 32) | (p1 << 16) | p2
	lsb = (p3 << 48) | p4
	return msb, lsb, true
}

func compareUUIDSignedPainless(s1, s2 string) (int64, bool) {
	msb1, lsb1, ok1 := parseUUIDBitsPainless(s1)
	msb2, lsb2, ok2 := parseUUIDBitsPainless(s2)
	if !ok1 || !ok2 {
		return 0, false
	}
	sm1 := int64(msb1) // #nosec G115 -- Java UUID.compareTo compares signed 64-bit MSB
	sm2 := int64(msb2) // #nosec G115 -- Java UUID.compareTo compares signed 64-bit MSB
	if sm1 < sm2 {
		return -1, true
	}
	if sm1 > sm2 {
		return 1, true
	}
	sl1 := int64(lsb1) // #nosec G115 -- Java UUID.compareTo compares signed 64-bit LSB
	sl2 := int64(lsb2) // #nosec G115 -- Java UUID.compareTo compares signed 64-bit LSB
	if sl1 < sl2 {
		return -1, true
	}
	if sl1 > sl2 {
		return 1, true
	}
	return 0, true
}

// painlessURI represents a java.net.URI in Painless.
type painlessURI struct {
	u            *url.URL
	raw          string
	opaque       bool
	ssp          string
	hasAuthority bool
}

func isHexBytePainless(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func quoteURIComponentPainless(s string, extraDisallow string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '%' {
			if i+2 < len(s) && isHexBytePainless(s[i+1]) && isHexBytePainless(s[i+2]) {
				sb.WriteByte(b)
				continue
			}
			sb.WriteString("%25")
			continue
		}
		if b <= 0x20 || b >= 0x7f || strings.IndexByte("<>\"`{}\\^|", b) >= 0 || (extraDisallow != "" && strings.IndexByte(extraDisallow, b) >= 0) {
			_, _ = fmt.Fprintf(&sb, "%%%02X", b)
		} else {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

func newPainlessURIFromString(raw string) (*painlessURI, error) {
	if strings.ContainsAny(raw, " \t\n\r<>\"`{}\\^|") {
		return nil, &painlessExceptionError{exType: "URISyntaxException", message: fmt.Sprintf("Illegal character in URI: %s", raw)}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &painlessExceptionError{exType: "URISyntaxException", message: err.Error()}
	}
	opaque := u.Scheme != "" && u.Opaque != ""
	ssp := u.Opaque
	if !opaque {
		afterScheme := raw
		if u.Scheme != "" {
			if idx := strings.IndexByte(raw, ':'); idx >= 0 {
				afterScheme = raw[idx+1:]
			}
		}
		if hashIdx := strings.IndexByte(afterScheme, '#'); hashIdx >= 0 {
			afterScheme = afterScheme[:hashIdx]
		}
		ssp = afterScheme
	}
	return &painlessURI{
		u:            u,
		raw:          raw,
		opaque:       opaque,
		ssp:          ssp,
		hasAuthority: !opaque && strings.HasPrefix(ssp, "//"),
	}, nil
}

func (uri *painlessURI) rawAuthority() (string, bool) {
	if uri == nil || uri.u == nil || uri.opaque {
		return "", false
	}
	if uri.u.Host == "" && uri.u.User == nil && !uri.hasAuthority {
		return "", false
	}
	if strings.HasPrefix(uri.ssp, "//") {
		rest := uri.ssp[2:]
		end := len(rest)
		if idx := strings.IndexAny(rest, "/?"); idx >= 0 {
			end = idx
		}
		return rest[:end], true
	}
	if uri.u.User != nil {
		return uri.u.User.String() + "@" + uri.u.Host, true
	}
	return uri.u.Host, true
}

func (uri *painlessURI) compareTo(o *painlessURI) int64 {
	if uri == nil || o == nil {
		return 0
	}
	cmpOptStr := func(a string, aDef bool, b string, bDef bool, ignoreCase bool) int64 {
		if !aDef && !bDef {
			return 0
		}
		if !aDef {
			return -1
		}
		if !bDef {
			return 1
		}
		if ignoreCase {
			a = strings.ToLower(a)
			b = strings.ToLower(b)
		}
		return int64(strings.Compare(a, b))
	}
	if c := cmpOptStr(uri.u.Scheme, uri.u.Scheme != "", o.u.Scheme, o.u.Scheme != "", true); c != 0 {
		return c
	}
	uFrag, uHasFrag := "", false
	if uri.u.Fragment != "" || strings.Contains(uri.raw, "#") {
		uFrag = uri.u.EscapedFragment()
		uHasFrag = true
	}
	oFrag, oHasFrag := "", false
	if o.u.Fragment != "" || strings.Contains(o.raw, "#") {
		oFrag = o.u.EscapedFragment()
		oHasFrag = true
	}
	if uri.opaque || o.opaque {
		if c := int64(strings.Compare(uri.ssp, o.ssp)); c != 0 {
			return c
		}
		return cmpOptStr(uFrag, uHasFrag, oFrag, oHasFrag, false)
	}
	h1 := uri.getHost()
	h2 := o.getHost()
	if h1 != nil && h2 != nil {
		u1, u1Def := "", uri.u.User != nil
		if u1Def {
			u1 = uri.u.User.String()
		}
		u2, u2Def := "", o.u.User != nil
		if u2Def {
			u2 = o.u.User.String()
		}
		if c := cmpOptStr(u1, u1Def, u2, u2Def, false); c != 0 {
			return c
		}
		if c := cmpOptStr(fmt.Sprintf("%v", h1), true, fmt.Sprintf("%v", h2), true, true); c != 0 {
			return c
		}
		if pDiff := uri.getPort() - o.getPort(); pDiff != 0 {
			return pDiff
		}
	} else {
		a1, a1Def := uri.rawAuthority()
		a2, a2Def := o.rawAuthority()
		if c := cmpOptStr(a1, a1Def, a2, a2Def, false); c != 0 {
			return c
		}
	}
	if c := cmpOptStr(uri.u.EscapedPath(), true, o.u.EscapedPath(), true, false); c != 0 {
		return c
	}
	q1Def := uri.u.RawQuery != "" || uri.u.ForceQuery
	q2Def := o.u.RawQuery != "" || o.u.ForceQuery
	if c := cmpOptStr(uri.u.RawQuery, q1Def, o.u.RawQuery, q2Def, false); c != 0 {
		return c
	}
	return cmpOptStr(uFrag, uHasFrag, oFrag, oHasFrag, false)
}

func (uri *painlessURI) String() string {
	if uri == nil {
		return ""
	}
	return uri.raw
}

func (uri *painlessURI) toASCIIString() string {
	if uri == nil || uri.u == nil {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < len(uri.raw); i++ {
		b := uri.raw[i]
		if b >= 0x80 {
			_, _ = fmt.Fprintf(&sb, "%%%02X", b)
		} else {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

func (uri *painlessURI) getPort() int64 {
	if uri == nil || uri.u == nil || uri.opaque {
		return -1
	}
	h := uri.u.Host
	if colonIdx := strings.LastIndexByte(h, ':'); colonIdx >= 0 {
		if closeBr := strings.LastIndexByte(h, ']'); closeBr < colonIdx {
			pStr := h[colonIdx+1:]
			if pStr == "" {
				return -1
			}
			if p, err := strconv.ParseInt(pStr, 10, 64); err == nil {
				return p
			}
		}
	}
	return -1
}

func (uri *painlessURI) getHost() any {
	if uri == nil || uri.u == nil || uri.opaque {
		return nil
	}
	h := uri.u.Hostname()
	if h == "" {
		return nil
	}
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

func (uri *painlessURI) normalize() *painlessURI {
	if uri == nil || uri.u == nil || uri.opaque || uri.u.Path == "" {
		return uri
	}
	cleanPath := path.Clean(uri.u.Path)
	if cleanPath == "." {
		cleanPath = ""
	} else if strings.HasSuffix(uri.u.Path, "/") && cleanPath != "/" {
		cleanPath += "/"
	}
	if !strings.HasPrefix(uri.u.Path, "/") {
		cleanPath = strings.TrimPrefix(cleanPath, "/")
	}
	cp := *uri.u
	cp.Path = cleanPath
	cp.RawPath = ""
	res, err := newPainlessURIFromString(cp.String())
	if err != nil {
		return uri
	}
	return res
}

func (uri *painlessURI) resolve(other *painlessURI) *painlessURI {
	if uri == nil || other == nil {
		return other
	}
	if uri.opaque || other.u.Scheme != "" {
		return other
	}
	resolved := uri.u.ResolveReference(other.u)
	res, err := newPainlessURIFromString(resolved.String())
	if err != nil {
		return other
	}
	return res
}

func (uri *painlessURI) relativize(other *painlessURI) *painlessURI {
	if uri == nil || other == nil || uri.opaque || other.opaque {
		return other
	}
	if !strings.EqualFold(uri.u.Scheme, other.u.Scheme) || uri.u.Host != other.u.Host {
		return other
	}
	basePath := path.Clean(uri.u.Path)
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	targetPath := other.u.Path
	if !strings.HasPrefix(targetPath, basePath) {
		return other
	}
	relPath := strings.TrimPrefix(targetPath, basePath)
	var sb strings.Builder
	sb.WriteString(relPath)
	if other.u.RawQuery != "" {
		sb.WriteByte('?')
		sb.WriteString(other.u.RawQuery)
	}
	if other.u.Fragment != "" {
		sb.WriteByte('#')
		sb.WriteString(other.u.Fragment)
	}
	res, err := newPainlessURIFromString(sb.String())
	if err != nil {
		return other
	}
	return res
}

func (uri *painlessURI) equals(other any) bool {
	o, ok := other.(*painlessURI)
	if !ok || uri == nil || o == nil {
		return false
	}
	return strings.EqualFold(uri.u.Scheme, o.u.Scheme) && uri.ssp == o.ssp && uri.u.Fragment == o.u.Fragment
}

func (uri *painlessURI) hashCode() int64 {
	if uri == nil {
		return 0
	}
	return computeJavaHashCodePainless(strings.ToLower(uri.u.Scheme) + ":" + uri.ssp + "#" + uri.u.Fragment)
}

// painlessURL represents a java.net.URL in Painless.
type painlessURL struct {
	u   *url.URL
	raw string
}

func newPainlessURLFromString(raw string) (*painlessURL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return nil, &painlessExceptionError{exType: "MalformedURLException", message: fmt.Sprintf("no protocol: %s", raw)}
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "ftp", "file", "jar", "mailto":
	default:
		return nil, &painlessExceptionError{exType: "MalformedURLException", message: fmt.Sprintf("unknown protocol: %s", scheme)}
	}
	return &painlessURL{u: u, raw: raw}, nil
}

func (u *painlessURL) String() string {
	if u == nil {
		return ""
	}
	return u.raw
}

func (u *painlessURL) getDefaultPort() int64 {
	if u == nil || u.u == nil {
		return -1
	}
	switch strings.ToLower(u.u.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	case "ftp":
		return 21
	default:
		return -1
	}
}

func (u *painlessURL) getPort() int64 {
	if u == nil || u.u == nil {
		return -1
	}
	uri := &painlessURI{u: u.u, raw: u.raw}
	return uri.getPort()
}

func (u *painlessURL) getFile() string {
	if u == nil || u.u == nil {
		return ""
	}
	if u.u.RawQuery != "" {
		return u.u.Path + "?" + u.u.RawQuery
	}
	return u.u.Path
}

func (u *painlessURL) equals(other any) bool {
	o, ok := other.(*painlessURL)
	if !ok || u == nil || o == nil {
		return false
	}
	return strings.EqualFold(u.u.Scheme, o.u.Scheme) && strings.EqualFold(u.u.Host, o.u.Host) &&
		u.getFile() == o.getFile() && u.u.Fragment == o.u.Fragment
}

func (u *painlessURL) hashCode() int64 {
	if u == nil {
		return 0
	}
	return computeJavaHashCodePainless(strings.ToLower(u.u.Scheme) + "://" + strings.ToLower(u.u.Host) + u.getFile())
}

// ============================================================================
// Round 54 Dispatchers Hooked into eval.go
// ============================================================================

func evalRound54ZeroArgMethodPainless(mSuffix, recExpr string, recVal any, sourceMap, params map[string]any, depth int) (any, bool, error) {
	// Check user object overrides for toString() and hashCode()
	if uo, isUO := recVal.(*painlessUserObject); isUO && uo != nil && uo.class != nil {
		switch mSuffix {
		case ".toString()":
			if uo.class.findMethod("toString") != nil {
				res, err := evalUserClassMethodOnClassPainless(uo, uo.class, "toString", "", false, sourceMap, params, depth+1)
				return res, true, err
			}
			return uo.String(), true, nil
		case ".hashCode()":
			if uo.class.findMethod("hashCode") != nil {
				res, err := evalUserClassMethodOnClassPainless(uo, uo.class, "hashCode", "", false, sourceMap, params, depth+1)
				return res, true, err
			}
			return computeJavaHashCodePainless(uo), true, nil
		}
	}

	// F20: Optional zero-arg methods
	if opt, isOpt := recVal.(*painlessOptional); isOpt && opt != nil {
		switch mSuffix {
		case ".isPresent()":
			return opt.present, true, nil
		case ".isEmpty()":
			return !opt.present, true, nil
		case ".get()", ".orElseThrow()":
			if !opt.present {
				return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
			}
			return opt.val, true, nil
		case ".getAsInt()":
			if !opt.present {
				return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
			}
			v, err := coerceOptionalPrimitivePainless("OptionalInt", opt.val)
			return v, true, err
		case ".getAsLong()":
			if !opt.present {
				return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
			}
			v, err := coerceOptionalPrimitivePainless("OptionalLong", opt.val)
			return v, true, err
		case ".getAsDouble()":
			if !opt.present {
				return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
			}
			v, err := coerceOptionalPrimitivePainless("OptionalDouble", opt.val)
			return v, true, err
		case ".stream()":
			if !opt.present {
				return []any{}, true, nil
			}
			return []any{opt.val}, true, nil
		case ".toString()":
			return opt.String(), true, nil
		case ".hashCode()":
			return opt.hashCode(), true, nil
		}
	}

	// F21: SummaryStatistics toString()
	if m, isMap := recVal.(map[string]any); isMap {
		if _, isStats := isSummaryStatisticsMapPainless(m); isStats && mSuffix == ".toString()" {
			return formatSummaryStatisticsToStringPainless(m), true, nil
		}
	}

	// F23: Clock zero-arg methods
	if clk, isClk := recVal.(*painlessClock); isClk && clk != nil {
		budget := getOrInitEvalBudget(params)
		nowMs := int64(0)
		if budget != nil {
			nowMs = budget.nowMillis
		}
		tm := clk.currentTime(nowMs)
		switch mSuffix {
		case ".instant()":
			return tm.UTC().Format(time.RFC3339Nano), true, nil
		case ".millis()":
			return tm.UnixMilli(), true, nil
		case ".getZone()":
			if clk.zone == "" {
				return "Z", true, nil
			}
			return clk.zone, true, nil
		case ".toString()":
			return clk.String(), true, nil
		case ".hashCode()":
			return clk.hashCode(), true, nil
		}
	}

	// F20: ValueRange and ChronoField.range() zero-arg methods
	if vr, isVR := recVal.(*painlessValueRange); isVR && vr != nil {
		switch mSuffix {
		case ".getMinimum()":
			return vr.minSmallest, true, nil
		case ".getLargestMinimum()":
			return vr.minLargest, true, nil
		case ".getSmallestMaximum()":
			return vr.maxSmallest, true, nil
		case ".getMaximum()":
			return vr.maxLargest, true, nil
		case ".isFixed()":
			return vr.isFixed(), true, nil
		case ".isIntValue()":
			return vr.isIntValue(), true, nil
		case ".toString()":
			return vr.String(), true, nil
		case ".hashCode()":
			return vr.hashCode(), true, nil
		}
	}
	if mSuffix == ".range()" {
		if field, ok := parseChronoFieldArgPainless(recVal); ok {
			vr, err := evalChronoFieldRangePainless(field)
			return vr, true, err
		}
	}

	// F23: OffsetTime zero-arg methods
	if ot, isOT := recVal.(*painlessOffsetTime); isOT && ot != nil {
		switch mSuffix {
		case ".getHour()":
			return int64(ot.hour), true, nil
		case ".getMinute()":
			return int64(ot.minute), true, nil
		case ".getSecond()":
			return int64(ot.second), true, nil
		case ".getNano()":
			return int64(ot.nano), true, nil
		case ".getOffset()":
			return formatZoneOffsetSecondsPainless(ot.offsetSeconds), true, nil
		case ".toLocalTime()":
			return formatLocalTimePainless(ot.hour, ot.minute, ot.second, ot.nano), true, nil
		case ".toString()":
			return ot.String(), true, nil
		case ".hashCode()":
			return ot.hashCode(), true, nil
		}
	}

	// F23: ZoneId / ZoneOffset zero-arg methods
	switch mSuffix {
	case ".getId()":
		if s, ok := recVal.(string); ok {
			return s, true, nil
		}
	case ".getTotalSeconds()":
		if offSec, ok := parseZoneOffsetSecondsPainless(recVal); ok {
			return int64(offSec), true, nil
		}
	case ".normalized()":
		if _, isPeriod := parsePainlessPeriod(recVal); !isPeriod {
			if offSec, ok := parseZoneOffsetSecondsPainless(recVal); ok {
				return formatZoneOffsetSecondsPainless(offSec), true, nil
			}
		}
	case ".getRules()":
		if s, ok := recVal.(string); ok {
			return map[string]any{"id": s, "fixedOffset": true}, true, nil
		}
	case ".getOffset()":
		if tm, ok := parsePainlessDateTime(recVal); ok {
			_, off := tm.Zone()
			return formatZoneOffsetSecondsPainless(off), true, nil
		}
	case ".getZone()":
		if s, ok := recVal.(string); ok {
			if lb := strings.IndexByte(s, '['); lb > 0 && strings.HasSuffix(s, "]") {
				return s[lb+1 : len(s)-1], true, nil
			}
		}
		if tm, ok := parsePainlessDateTime(recVal); ok {
			name, off := tm.Zone()
			if name != "" && name != "UTC" {
				return name, true, nil
			}
			return formatZoneOffsetSecondsPainless(off), true, nil
		}
	}

	// F24: Pattern & Matcher zero-arg methods
	switch mSuffix {
	case ".asPredicate()":
		re, _, err := extractPatternRegexpPainless(recVal)
		if err != nil || re == nil {
			return nil, true, err
		}
		return &painlessPredicate{
			fn: func(val any, _, _ map[string]any, _ int) (bool, error) {
				if val == nil {
					return false, nil
				}
				return re.MatchString(fmt.Sprintf("%v", val)), nil
			},
		}, true, nil
	case ".asMatchPredicate()":
		_, patStr, err := extractPatternRegexpPainless(recVal)
		if err != nil {
			return nil, true, err
		}
		fullRe, errC := compilePainlessRegexp("^(?:" + patStr + ")$")
		if errC != nil {
			return nil, true, errC
		}
		return &painlessPredicate{
			fn: func(val any, _, _ map[string]any, _ int) (bool, error) {
				if val == nil {
					return false, nil
				}
				return fullRe.MatchString(fmt.Sprintf("%v", val)), nil
			},
		}, true, nil
	case ".negate()":
		if pred, isPred := recVal.(*painlessPredicate); isPred && pred != nil {
			return &painlessPredicate{
				fn: func(val any, sm, pm map[string]any, d int) (bool, error) {
					ok, err := pred.test(val, sm, pm, d)
					return !ok, err
				},
			}, true, nil
		}
	}
	if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil {
		switch mSuffix {
		case ".results()":
			regStart := 0
			regEnd := len(pm.input)
			if pm.hasRegion {
				regStart = pm.regionStart
				regEnd = pm.regionEnd
			}
			if pm.re == nil {
				return []any{}, true, nil
			}
			locs := pm.re.FindAllStringSubmatchIndex(pm.input[regStart:regEnd], -1)
			out := make([]any, 0, len(locs))
			for _, loc := range locs {
				shifted := make([]int, len(loc))
				for i, v := range loc {
					if v >= 0 {
						shifted[i] = v + regStart
					} else {
						shifted[i] = -1
					}
				}
				out = append(out, &painlessMatcher{
					re:                      pm.re,
					pat:                     pm.pat,
					input:                   pm.input,
					curPos:                  shifted[1],
					lastMatch:               shifted,
					hasRegion:               pm.hasRegion,
					regionStart:             pm.regionStart,
					regionEnd:               pm.regionEnd,
					transparentBounds:       pm.transparentBounds,
					anchoringBoundsDisabled: pm.anchoringBoundsDisabled,
				})
			}
			return out, true, nil
		case ".toMatchResult()":
			if len(pm.lastMatch) < 2 || pm.lastMatch[0] < 0 {
				return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "No match found"}
			}
			cpMatch := make([]int, len(pm.lastMatch))
			copy(cpMatch, pm.lastMatch)
			return &painlessMatcher{
				re:                      pm.re,
				pat:                     pm.pat,
				input:                   pm.input,
				curPos:                  pm.curPos,
				lastMatch:               cpMatch,
				hasRegion:               pm.hasRegion,
				regionStart:             pm.regionStart,
				regionEnd:               pm.regionEnd,
				transparentBounds:       pm.transparentBounds,
				anchoringBoundsDisabled: pm.anchoringBoundsDisabled,
				lastSearchHitEnd:        pm.lastSearchHitEnd,
				lastSearchRequireEnd:    pm.lastSearchRequireEnd,
			}, true, nil
		case ".namedGroups()":
			out := make(map[string]any)
			if pm.re != nil {
				for idx, name := range pm.re.SubexpNames() {
					if idx > 0 && name != "" {
						out[name] = int64(idx)
					}
				}
			}
			return out, true, nil
		case ".hasTransparentBounds()":
			return pm.transparentBounds, true, nil
		case ".hasAnchoringBounds()":
			return !pm.anchoringBoundsDisabled, true, nil
		case ".hitEnd()":
			return pm.lastSearchHitEnd, true, nil
		case ".requireEnd()":
			return pm.lastSearchRequireEnd, true, nil
		}
	}

	// F26: UUID version-1 methods
	if mSuffix == ".timestamp()" || mSuffix == ".clockSequence()" || mSuffix == ".node()" {
		if s, ok := recVal.(string); ok {
			if msb, lsb, valid := parseUUIDBitsPainless(s); valid {
				ver := (msb >> 12) & 0x0f
				if ver != 1 {
					return nil, true, &painlessExceptionError{exType: "UnsupportedOperationException", message: "Not a time-based UUID"}
				}
				switch mSuffix {
				case ".timestamp()":
					ts := ((msb & 0x0fff) << 48) | (((msb >> 16) & 0xffff) << 32) | (msb >> 32)
					return int64(ts), true, nil // #nosec G115 -- 60-bit UUID v1 timestamp fits positive int64
				case ".clockSequence()":
					return int64((lsb >> 48) & 0x3fff), true, nil // #nosec G115 -- 14-bit UUID v1 clockSequence
				case ".node()":
					return int64(lsb & 0x0000ffffffffffff), true, nil // #nosec G115 -- 48-bit UUID v1 node fits positive int64
				}
			}
		}
	}

	// F26: java.net.URI zero-arg methods
	if uri, isURI := recVal.(*painlessURI); isURI && uri != nil {
		switch mSuffix {
		case ".getScheme()":
			if uri.u.Scheme == "" {
				return nil, true, nil
			}
			return uri.u.Scheme, true, nil
		case ".getSchemeSpecificPart()":
			if d, err := url.PathUnescape(uri.ssp); err == nil {
				return d, true, nil
			}
			return uri.ssp, true, nil
		case ".getRawSchemeSpecificPart()":
			return uri.ssp, true, nil
		case ".getAuthority()", ".getRawAuthority()":
			rawAuth, okA := uri.rawAuthority()
			if !okA {
				return nil, true, nil
			}
			if mSuffix == ".getAuthority()" {
				if d, err := url.PathUnescape(rawAuth); err == nil {
					return d, true, nil
				}
			}
			return rawAuth, true, nil
		case ".getUserInfo()", ".getRawUserInfo()":
			if uri.opaque || uri.u.User == nil {
				return nil, true, nil
			}
			if mSuffix == ".getUserInfo()" {
				if d, err := url.PathUnescape(uri.u.User.String()); err == nil {
					return d, true, nil
				}
			}
			return uri.u.User.String(), true, nil
		case ".getHost()":
			return uri.getHost(), true, nil
		case ".getPort()":
			return uri.getPort(), true, nil
		case ".getPath()":
			if uri.opaque {
				return nil, true, nil
			}
			return uri.u.Path, true, nil
		case ".getRawPath()":
			if uri.opaque {
				return nil, true, nil
			}
			return uri.u.EscapedPath(), true, nil
		case ".getQuery()":
			if uri.opaque || (uri.u.RawQuery == "" && !uri.u.ForceQuery) {
				return nil, true, nil
			}
			if d, err := url.PathUnescape(uri.u.RawQuery); err == nil {
				return d, true, nil
			}
			return uri.u.RawQuery, true, nil
		case ".getRawQuery()":
			if uri.opaque || (uri.u.RawQuery == "" && !uri.u.ForceQuery) {
				return nil, true, nil
			}
			return uri.u.RawQuery, true, nil
		case ".getFragment()":
			if uri.u.Fragment == "" && !strings.Contains(uri.raw, "#") {
				return nil, true, nil
			}
			return uri.u.Fragment, true, nil
		case ".getRawFragment()":
			if uri.u.Fragment == "" && !strings.Contains(uri.raw, "#") {
				return nil, true, nil
			}
			return uri.u.EscapedFragment(), true, nil
		case ".isAbsolute()":
			return uri.u.Scheme != "", true, nil
		case ".isOpaque()":
			return uri.opaque, true, nil
		case ".normalize()":
			return uri.normalize(), true, nil
		case ".toASCIIString()":
			return uri.toASCIIString(), true, nil
		case ".toURL()":
			if uri.u.Scheme == "" {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "URI is not absolute"}
			}
			uVal, err := newPainlessURLFromString(uri.raw)
			return uVal, true, err
		case ".toString()":
			return uri.String(), true, nil
		case ".hashCode()":
			return uri.hashCode(), true, nil
		}
	}

	// F26: java.net.URL zero-arg methods
	if uVal, isURL := recVal.(*painlessURL); isURL && uVal != nil {
		switch mSuffix {
		case ".getProtocol()":
			return strings.ToLower(uVal.u.Scheme), true, nil
		case ".getHost()":
			return uVal.u.Hostname(), true, nil
		case ".getPort()":
			return uVal.getPort(), true, nil
		case ".getDefaultPort()":
			return uVal.getDefaultPort(), true, nil
		case ".getFile()":
			return uVal.getFile(), true, nil
		case ".getPath()":
			return uVal.u.Path, true, nil
		case ".getQuery()":
			if uVal.u.RawQuery == "" && !uVal.u.ForceQuery {
				return nil, true, nil
			}
			return uVal.u.RawQuery, true, nil
		case ".getAuthority()":
			if uVal.u.User != nil {
				return uVal.u.User.String() + "@" + uVal.u.Host, true, nil
			}
			return uVal.u.Host, true, nil
		case ".getUserInfo()":
			if uVal.u.User == nil {
				return nil, true, nil
			}
			return uVal.u.User.String(), true, nil
		case ".getRef()":
			if uVal.u.Fragment == "" && !strings.Contains(uVal.raw, "#") {
				return nil, true, nil
			}
			return uVal.u.Fragment, true, nil
		case ".toURI()":
			uri, err := newPainlessURIFromString(uVal.raw)
			return uri, true, err
		case ".toExternalForm()", ".toString()":
			return uVal.String(), true, nil
		case ".hashCode()":
			return uVal.hashCode(), true, nil
		}
	}

	if mSuffix == ".hashCode()" {
		return computeJavaHashCodePainless(recVal), true, nil
	}

	return nil, false, nil
}

func evalRound54ParamMethodPreArgPainless(mName, recExpr string, recVal any, argExpr string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	// F25: User object custom equals(other)
	if mName == ".equals(" {
		if uo, isUO := recVal.(*painlessUserObject); isUO && uo != nil && uo.class != nil {
			if uo.class.findMethod("equals") != nil {
				res, err := evalUserClassMethodOnClassPainless(uo, uo.class, "equals", argExpr, false, sourceMap, params, depth+1)
				if b, isB := res.(bool); isB {
					return b, true, err
				}
				return res != nil && res != false, true, err
			}
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return uo == otherVal, true, nil
		}
		if opt, isOpt := recVal.(*painlessOptional); isOpt && opt != nil {
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return opt.equals(otherVal), true, nil
		}
		if ot, isOT := recVal.(*painlessOffsetTime); isOT && ot != nil {
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return ot.equals(otherVal), true, nil
		}
		if clk, isClk := recVal.(*painlessClock); isClk && clk != nil {
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return clk.equals(otherVal), true, nil
		}
		if uri, isURI := recVal.(*painlessURI); isURI && uri != nil {
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return uri.equals(otherVal), true, nil
		}
		if uVal, isURL := recVal.(*painlessURL); isURL && uVal != nil {
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return uVal.equals(otherVal), true, nil
		}
		if vr, isVR := recVal.(*painlessValueRange); isVR && vr != nil {
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			return vr.equals(otherVal), true, nil
		}
	}

	// F20: ValueRange parameterized methods
	if vr, isVR := recVal.(*painlessValueRange); isVR && vr != nil {
		switch mName {
		case ".isValidValue(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			iv, ok := toInt64Painless(v0)
			if !ok {
				return false, true, nil
			}
			return vr.isValidValue(iv), true, nil
		case ".isValidIntValue(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			iv, ok := toInt64Painless(v0)
			if !ok {
				return false, true, nil
			}
			return vr.isValidIntValue(iv), true, nil
		}
	}

	// F20: Optional parameterized methods
	if opt, isOpt := recVal.(*painlessOptional); isOpt && opt != nil {
		switch mName {
		case ".orElse(":
			otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if opt.present {
				return opt.val, true, nil
			}
			if opt.kind != "Optional" {
				coerced, cErr := coerceOptionalPrimitivePainless(opt.kind, otherVal)
				if cErr == nil {
					return coerced, true, nil
				}
			}
			return otherVal, true, nil
		case ".orElseGet(":
			if opt.present {
				return opt.val, true, nil
			}
			normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 0)
			if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
				v, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
				if err != nil {
					return nil, true, err
				}
				if opt.kind != "Optional" {
					coerced, cErr := coerceOptionalPrimitivePainless(opt.kind, v)
					if cErr == nil {
						return coerced, true, nil
					}
				}
				return v, true, nil
			}
			return nil, true, nil
		case ".or(":
			if opt.present {
				return opt, true, nil
			}
			normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 0)
			if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
				v, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
				if err != nil {
					return nil, true, err
				}
				if v == nil {
					return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "Optional.or() supplier returned null"}
				}
				if o2, ok := v.(*painlessOptional); ok {
					return o2, true, nil
				}
				return newPainlessOptional("Optional", true, v), true, nil
			}
			return newPainlessOptional("Optional", false, nil), true, nil
		case ".orElseThrow(":
			if opt.present {
				return opt.val, true, nil
			}
			v, err := evalOptionalOrElseThrowSupplierPainless(argExpr, sourceMap, params, depth+1)
			return v, true, err
		case ".ifPresent(":
			if opt.present {
				normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 1)
				if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
					if len(pNames) > 0 {
						pName := pNames[0]
						prev, hadPrev := params[pName]
						params[pName] = opt.val
						_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
						if hadPrev {
							params[pName] = prev
						} else {
							delete(params, pName)
						}
						return nil, true, err
					}
				}
			}
			return nil, true, nil
		case ".ifPresentOrElse(":
			ieArgs := splitTopLevelCommaPainless(argExpr)
			if opt.present {
				if len(ieArgs) >= 1 {
					normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(ieArgs[0]), 1)
					if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
						if len(pNames) > 0 {
							pName := pNames[0]
							prev, hadPrev := params[pName]
							params[pName] = opt.val
							_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
					}
				}
			} else if len(ieArgs) >= 2 {
				normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(ieArgs[1]), 0)
				if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
					_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
					return nil, true, err
				}
			}
			return nil, true, nil
		case ".filter(":
			if !opt.present {
				return opt, true, nil
			}
			matched, err := evalPredicateArgOnItemPainless(argExpr, opt.val, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if !matched {
				return newPainlessOptional(opt.kind, false, nil), true, nil
			}
			return opt, true, nil
		case ".map(":
			if !opt.present {
				return newPainlessOptional("Optional", false, nil), true, nil
			}
			normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 1)
			if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					prev, hadPrev := params[pName]
					params[pName] = opt.val
					mv, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					if err != nil {
						return nil, true, err
					}
					if mv == nil || mv == painlessEmptyOptional {
						return newPainlessOptional("Optional", false, nil), true, nil
					}
					return newPainlessOptional("Optional", true, mv), true, nil
				}
			}
			return opt, true, nil
		case ".flatMap(":
			if !opt.present {
				return newPainlessOptional("Optional", false, nil), true, nil
			}
			normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 1)
			if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					prev, hadPrev := params[pName]
					params[pName] = opt.val
					mv, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					if err != nil {
						return nil, true, err
					}
					if mv == nil {
						return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "Optional.flatMap() mapper returned null"}
					}
					if o2, ok := mv.(*painlessOptional); ok {
						return o2, true, nil
					}
					if mv == painlessEmptyOptional {
						return newPainlessOptional("Optional", false, nil), true, nil
					}
					return newPainlessOptional("Optional", true, mv), true, nil
				}
			}
			return opt, true, nil
		}
	}

	// F21: SummaryStatistics .accept(v) and .combine(other)
	if m, isMap := recVal.(map[string]any); isMap {
		if _, isStats := isSummaryStatisticsMapPainless(m); isStats {
			switch mName {
			case ".accept(":
				v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				return nil, true, summaryStatisticsAcceptPainless(m, v)
			case ".combine(":
				v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				return nil, true, summaryStatisticsCombinePainless(m, v)
			}
		}
	}

	// F23: Clock.withZone(zone)
	if clk, isClk := recVal.(*painlessClock); isClk && clk != nil && mName == ".withZone(" {
		zVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		if zVal == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "zone"}
		}
		cp := *clk
		cp.zone = fmt.Sprintf("%v", zVal)
		return &cp, true, nil
	}

	// F23: OffsetTime parameterized methods
	if ot, isOT := recVal.(*painlessOffsetTime); isOT && ot != nil {
		args := splitTopLevelCommaPainless(argExpr)
		evalFirstInt := func() (int, error) {
			if len(args) == 0 {
				return 0, nil
			}
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return 0, err
			}
			iv, _ := toInt64Painless(v)
			return int(iv), nil
		}
		switch mName {
		case ".withHour(":
			h, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			res, err := newPainlessOffsetTime(h, ot.minute, ot.second, ot.nano, ot.offsetSeconds)
			return res, true, err
		case ".withMinute(":
			m, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			res, err := newPainlessOffsetTime(ot.hour, m, ot.second, ot.nano, ot.offsetSeconds)
			return res, true, err
		case ".withSecond(":
			s, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			res, err := newPainlessOffsetTime(ot.hour, ot.minute, s, ot.nano, ot.offsetSeconds)
			return res, true, err
		case ".withNano(":
			n, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			res, err := newPainlessOffsetTime(ot.hour, ot.minute, ot.second, n, ot.offsetSeconds)
			return res, true, err
		case ".withOffsetSameLocal(":
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			offSec, ok := parseZoneOffsetSecondsPainless(v)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid ZoneOffset: %v", v)}
			}
			res, err := newPainlessOffsetTime(ot.hour, ot.minute, ot.second, ot.nano, offSec)
			return res, true, err
		case ".withOffsetSameInstant(":
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			offSec, ok := parseZoneOffsetSecondsPainless(v)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid ZoneOffset: %v", v)}
			}
			diffSec := offSec - ot.offsetSeconds
			shifted := ot.addNanos(int64(diffSec) * 1_000_000_000)
			shifted.offsetSeconds = offSec
			return shifted, true, nil
		case ".plusHours(", ".minusHours(":
			h, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			if mName == ".minusHours(" {
				h = -h
			}
			return ot.addNanos(int64(h) * 3600 * 1_000_000_000), true, nil
		case ".plusMinutes(", ".minusMinutes(":
			m, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			if mName == ".minusMinutes(" {
				m = -m
			}
			return ot.addNanos(int64(m) * 60 * 1_000_000_000), true, nil
		case ".plusSeconds(", ".minusSeconds(":
			s, err := evalFirstInt()
			if err != nil {
				return nil, true, err
			}
			if mName == ".minusSeconds(" {
				s = -s
			}
			return ot.addNanos(int64(s) * 1_000_000_000), true, nil
		case ".plusNanos(", ".minusNanos(":
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			ns, _ := toInt64Painless(v)
			if mName == ".minusNanos(" {
				ns = -ns
			}
			return ot.addNanos(ns), true, nil
		case ".plus(", ".minus(":
			sign := int64(1)
			if mName == ".minus(" {
				sign = -1
			}
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if dur, ok := parsePainlessDuration(v0); ok && len(args) == 1 {
				return ot.addNanos(sign * dur.Nanoseconds()), true, nil
			}
			if len(args) >= 2 {
				uVal, errU := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if errU != nil {
					return nil, true, errU
				}
				amt, _ := toInt64Painless(v0)
				uStr := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", uVal))), "CHRONOUNIT.")
				switch uStr {
				case "HOURS":
					return ot.addNanos(sign * amt * 3600 * 1_000_000_000), true, nil
				case "MINUTES":
					return ot.addNanos(sign * amt * 60 * 1_000_000_000), true, nil
				case "SECONDS":
					return ot.addNanos(sign * amt * 1_000_000_000), true, nil
				case "MILLIS":
					return ot.addNanos(sign * amt * 1_000_000), true, nil
				case "MICROS":
					return ot.addNanos(sign * amt * 1_000), true, nil
				case "NANOS":
					return ot.addNanos(sign * amt), true, nil
				case "HALF_DAYS":
					return ot.addNanos(sign * amt * 12 * 3600 * 1_000_000_000), true, nil
				default:
					return nil, true, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported unit: " + uStr}
				}
			}
		case ".truncatedTo(":
			uVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			uStr := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", uVal))), "CHRONOUNIT.")
			switch uStr {
			case "DAYS":
				return &painlessOffsetTime{offsetSeconds: ot.offsetSeconds}, true, nil
			case "HALF_DAYS":
				return &painlessOffsetTime{hour: (ot.hour / 12) * 12, offsetSeconds: ot.offsetSeconds}, true, nil
			case "HOURS":
				return &painlessOffsetTime{hour: ot.hour, offsetSeconds: ot.offsetSeconds}, true, nil
			case "MINUTES":
				return &painlessOffsetTime{hour: ot.hour, minute: ot.minute, offsetSeconds: ot.offsetSeconds}, true, nil
			case "SECONDS":
				return &painlessOffsetTime{hour: ot.hour, minute: ot.minute, second: ot.second, offsetSeconds: ot.offsetSeconds}, true, nil
			case "MILLIS":
				return &painlessOffsetTime{hour: ot.hour, minute: ot.minute, second: ot.second, nano: (ot.nano / 1_000_000) * 1_000_000, offsetSeconds: ot.offsetSeconds}, true, nil
			case "MICROS":
				return &painlessOffsetTime{hour: ot.hour, minute: ot.minute, second: ot.second, nano: (ot.nano / 1_000) * 1_000, offsetSeconds: ot.offsetSeconds}, true, nil
			case "NANOS":
				return ot, true, nil
			default:
				return nil, true, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported unit for truncation: " + uStr}
			}
		case ".atDate(":
			dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			tm, ok := parsePainlessDateTime(dVal)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid LocalDate: %v", dVal)}
			}
			return fmt.Sprintf("%04d-%02d-%02dT%s", tm.Year(), int(tm.Month()), tm.Day(), ot.String()), true, nil
		case ".toEpochSecond(":
			dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			tm, ok := parsePainlessDateTime(dVal)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid LocalDate: %v", dVal)}
			}
			epochDay := time.Date(tm.Year(), tm.Month(), tm.Day(), 0, 0, 0, 0, time.UTC).Unix() / 86400
			secOfDay := int64(ot.hour*3600 + ot.minute*60 + ot.second)
			return epochDay*86400 + secOfDay - int64(ot.offsetSeconds), true, nil
		case ".isBefore(", ".isAfter(", ".isEqual(", ".compareTo(":
			oVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			oOT, ok := parsePainlessOffsetTime(oVal)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid OffsetTime: %v", oVal)}
			}
			switch mName {
			case ".isBefore(":
				return ot.toEpochNanoOnZeroDay() < oOT.toEpochNanoOnZeroDay(), true, nil
			case ".isAfter(":
				return ot.toEpochNanoOnZeroDay() > oOT.toEpochNanoOnZeroDay(), true, nil
			case ".isEqual(":
				return ot.toEpochNanoOnZeroDay() == oOT.toEpochNanoOnZeroDay(), true, nil
			case ".compareTo(":
				return int64(ot.compareTo(oOT)), true, nil
			}
		}
	}

	// F24: Pattern.splitAsStream(input) & Predicate methods
	if mName == ".splitAsStream(" {
		re, _, err := extractPatternRegexpPainless(recVal)
		if err != nil || re == nil {
			return []any{}, true, err
		}
		v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
		if err0 != nil {
			return nil, true, err0
		}
		if v0 == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "input is null"}
		}
		s := fmt.Sprintf("%v", v0)
		if s == "" {
			return []any{}, true, nil
		}
		parts := re.Split(s, -1)
		for len(parts) > 0 && parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
		out := make([]any, len(parts))
		for i, p := range parts {
			out[i] = p
		}
		return out, true, nil
	}
	if pred, isPred := recVal.(*painlessPredicate); isPred && pred != nil {
		switch mName {
		case ".test(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return false, true, err
			}
			res, errT := pred.test(v0, sourceMap, params, depth+1)
			return res, true, errT
		case ".and(":
			return &painlessPredicate{
				fn: func(val any, sm, pm map[string]any, d int) (bool, error) {
					ok1, err1 := pred.test(val, sm, pm, d)
					if err1 != nil || !ok1 {
						return false, err1
					}
					return evalPredicateArgOnItemPainless(argExpr, val, sm, pm, d+1)
				},
			}, true, nil
		case ".or(":
			return &painlessPredicate{
				fn: func(val any, sm, pm map[string]any, d int) (bool, error) {
					ok1, err1 := pred.test(val, sm, pm, d)
					if err1 != nil || ok1 {
						return ok1, err1
					}
					return evalPredicateArgOnItemPainless(argExpr, val, sm, pm, d+1)
				},
			}, true, nil
		}
	}

	// F24: Matcher parameterized methods (.usePattern, .useTransparentBounds, .useAnchoringBounds, method-ref .replaceAll/.replaceFirst)
	if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil {
		switch mName {
		case ".usePattern(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if v0 == nil {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Pattern cannot be null"}
			}
			newRe, patRaw, errP := extractPatternRegexpPainless(v0)
			if errP != nil || newRe == nil {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Invalid Pattern"}
			}
			pm.re = newRe
			if pp, ok := v0.(*painlessPattern); ok && pp != nil {
				pm.pat = pp
			} else {
				pm.pat = &painlessPattern{re: newRe, raw: patRaw}
			}
			pm.lastMatch = nil
			return pm, true, nil
		case ".useTransparentBounds(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			b, _ := v0.(bool)
			pm.transparentBounds = b
			return pm, true, nil
		case ".useAnchoringBounds(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			b, _ := v0.(bool)
			pm.anchoringBoundsDisabled = !b
			return pm, true, nil
		}
	}

	// F26: UUID signed compareTo
	if mName == ".compareTo(" {
		if s1, ok := recVal.(string); ok {
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err == nil {
				if s2, ok2 := v0.(string); ok2 {
					if cmp, isUUID := compareUUIDSignedPainless(s1, s2); isUUID {
						return cmp, true, nil
					}
				}
			}
		}
		if uri, isURI := recVal.(*painlessURI); isURI && uri != nil {
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			o, ok := v0.(*painlessURI)
			if !ok || o == nil {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "Cannot compare URI to non-URI"}
			}
			return uri.compareTo(o), true, nil
		}
	}

	// F26: URI.resolve and URI.relativize
	if uri, isURI := recVal.(*painlessURI); isURI && uri != nil {
		switch mName {
		case ".resolve(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if v0 == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "URI.resolve(null)"}
			}
			var otherURI *painlessURI
			if o, ok := v0.(*painlessURI); ok {
				otherURI = o
			} else {
				var uErr error
				otherURI, uErr = newPainlessURIFromString(fmt.Sprintf("%v", v0))
				if uErr != nil {
					return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: uErr.Error()}
				}
			}
			return uri.resolve(otherURI), true, nil
		case ".relativize(":
			v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			o, ok := v0.(*painlessURI)
			if !ok || o == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "URI.relativize(null)"}
			}
			return uri.relativize(o), true, nil
		}
	}

	return nil, false, nil
}

func evalPredicateArgOnItemPainless(predExpr string, item any, sourceMap, params map[string]any, depth int) (bool, error) {
	predExpr = strings.TrimSpace(predExpr)
	normArg := normalizeMethodReferenceToLambdaPainless(predExpr, 1)
	if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
		pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
		if len(pNames) > 0 {
			pName := pNames[0]
			prev, hadPrev := params[pName]
			params[pName] = item
			matched, err := evalPainlessPredicateLambda(normArg[arrowIdx+2:], sourceMap, params, depth+1)
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
			return matched, err
		}
	}
	v, err := evalRHSExprDepth(sourceMap, predExpr, params, depth+1)
	if err != nil {
		return false, err
	}
	if pred, ok := v.(*painlessPredicate); ok && pred != nil {
		return pred.test(item, sourceMap, params, depth+1)
	}
	return false, nil
}

func evalRound54ConstructorPainless(clsName, argStr string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	cArgs := splitTopLevelCommaPainless(argStr)
	evalArg := func(i int) (any, error) {
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[i]), params, depth+1)
	}
	switch clsName {
	case "IntSummaryStatistics", "LongSummaryStatistics", "DoubleSummaryStatistics":
		if len(cArgs) == 0 {
			stats, err := newSummaryStatisticsMapPainless(clsName, false, 0, 0, 0, 0)
			return stats, true, err
		}
		if len(cArgs) >= 4 {
			v0, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			v1, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			v2, err2 := evalArg(2)
			if err2 != nil {
				return nil, true, err2
			}
			v3, err3 := evalArg(3)
			if err3 != nil {
				return nil, true, err3
			}
			cnt, _ := toInt64Painless(v0)
			minF, _ := toFloat64AllowNonFinitePainless(v1)
			maxF, _ := toFloat64AllowNonFinitePainless(v2)
			sumF, _ := toFloat64AllowNonFinitePainless(v3)
			stats, err := newSummaryStatisticsMapPainless(clsName, true, cnt, minF, maxF, sumF)
			return stats, true, err
		}
		return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Invalid SummaryStatistics constructor arguments"}
	case "URI":
		switch len(cArgs) {
		case 1:
			v0, err := evalArg(0)
			if err != nil {
				return nil, true, err
			}
			if v0 == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "URI(null)"}
			}
			uri, uErr := newPainlessURIFromString(fmt.Sprintf("%v", v0))
			return uri, true, uErr
		case 3:
			// URI(scheme, ssp, fragment)
			sVal, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			sspVal, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			fragVal, err2 := evalArg(2)
			if err2 != nil {
				return nil, true, err2
			}
			var sb strings.Builder
			if sVal != nil {
				_, _ = fmt.Fprintf(&sb, "%v", sVal)
				sb.WriteByte(':')
			}
			if sspVal != nil {
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", sspVal), "#"))
			}
			if fragVal != nil {
				sb.WriteByte('#')
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", fragVal), ""))
			}
			uri, uErr := newPainlessURIFromString(sb.String())
			return uri, true, uErr
		case 4:
			// URI(scheme, host, path, fragment)
			sVal, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			hVal, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			pVal, err2 := evalArg(2)
			if err2 != nil {
				return nil, true, err2
			}
			fVal, err3 := evalArg(3)
			if err3 != nil {
				return nil, true, err3
			}
			if pVal != nil {
				pStr := fmt.Sprintf("%v", pVal)
				if pStr != "" && !strings.HasPrefix(pStr, "/") && hVal != nil && fmt.Sprintf("%v", hVal) != "" {
					return nil, true, &painlessExceptionError{exType: "URISyntaxException", message: fmt.Sprintf("Relative path in absolute URI: %s", pStr)}
				}
			}
			var sb strings.Builder
			if sVal != nil {
				_, _ = fmt.Fprintf(&sb, "%v:", sVal)
			}
			if hVal != nil {
				_, _ = fmt.Fprintf(&sb, "//%v", hVal)
			}
			if pVal != nil {
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", pVal), "?#"))
			}
			if fVal != nil {
				sb.WriteByte('#')
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", fVal), ""))
			}
			uri, uErr := newPainlessURIFromString(sb.String())
			return uri, true, uErr
		case 5:
			// URI(scheme, authority, path, query, fragment)
			sVal, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			aVal, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			pVal, err2 := evalArg(2)
			if err2 != nil {
				return nil, true, err2
			}
			qVal, err3 := evalArg(3)
			if err3 != nil {
				return nil, true, err3
			}
			fVal, err4 := evalArg(4)
			if err4 != nil {
				return nil, true, err4
			}
			if pVal != nil {
				pStr := fmt.Sprintf("%v", pVal)
				if pStr != "" && !strings.HasPrefix(pStr, "/") && aVal != nil && fmt.Sprintf("%v", aVal) != "" {
					return nil, true, &painlessExceptionError{exType: "URISyntaxException", message: fmt.Sprintf("Relative path in absolute URI: %s", pStr)}
				}
			}
			var sb strings.Builder
			if sVal != nil {
				_, _ = fmt.Fprintf(&sb, "%v:", sVal)
			}
			if aVal != nil {
				sb.WriteString("//")
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", aVal), "/?#"))
			}
			if pVal != nil {
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", pVal), "?#"))
			}
			if qVal != nil {
				sb.WriteByte('?')
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", qVal), "#"))
			}
			if fVal != nil {
				sb.WriteByte('#')
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", fVal), ""))
			}
			uri, uErr := newPainlessURIFromString(sb.String())
			return uri, true, uErr
		case 7:
			// URI(scheme, userInfo, host, port, path, query, fragment)
			sVal, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			uVal, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			hVal, err2 := evalArg(2)
			if err2 != nil {
				return nil, true, err2
			}
			portVal, err3 := evalArg(3)
			if err3 != nil {
				return nil, true, err3
			}
			pVal, err4 := evalArg(4)
			if err4 != nil {
				return nil, true, err4
			}
			qVal, err5 := evalArg(5)
			if err5 != nil {
				return nil, true, err5
			}
			fVal, err6 := evalArg(6)
			if err6 != nil {
				return nil, true, err6
			}
			if pVal != nil {
				pStr := fmt.Sprintf("%v", pVal)
				if pStr != "" && !strings.HasPrefix(pStr, "/") && hVal != nil && fmt.Sprintf("%v", hVal) != "" {
					return nil, true, &painlessExceptionError{exType: "URISyntaxException", message: fmt.Sprintf("Relative path in absolute URI: %s", pStr)}
				}
			}
			var sb strings.Builder
			if sVal != nil {
				_, _ = fmt.Fprintf(&sb, "%v:", sVal)
			}
			if hVal != nil {
				sb.WriteString("//")
				if uVal != nil {
					sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", uVal), "@/?#"))
					sb.WriteByte('@')
				}
				_, _ = fmt.Fprintf(&sb, "%v", hVal)
				if port, ok := toInt64Painless(portVal); ok && port >= 0 {
					_, _ = fmt.Fprintf(&sb, ":%d", port)
				}
			}
			if pVal != nil {
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", pVal), "?#"))
			}
			if qVal != nil {
				sb.WriteByte('?')
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", qVal), "#"))
			}
			if fVal != nil {
				sb.WriteByte('#')
				sb.WriteString(quoteURIComponentPainless(fmt.Sprintf("%v", fVal), ""))
			}
			uri, uErr := newPainlessURIFromString(sb.String())
			return uri, true, uErr
		}
	case "URL":
		switch len(cArgs) {
		case 1:
			v0, err := evalArg(0)
			if err != nil {
				return nil, true, err
			}
			if v0 == nil {
				return nil, true, &painlessExceptionError{exType: "MalformedURLException", message: "null"}
			}
			uObj, uErr := newPainlessURLFromString(fmt.Sprintf("%v", v0))
			return uObj, true, uErr
		case 2:
			v0, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			v1, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			if base, ok := v0.(*painlessURL); ok && base != nil {
				ref, rErr := url.Parse(fmt.Sprintf("%v", v1))
				if rErr != nil {
					return nil, true, &painlessExceptionError{exType: "MalformedURLException", message: rErr.Error()}
				}
				resolved := base.u.ResolveReference(ref)
				uObj, uErr := newPainlessURLFromString(resolved.String())
				return uObj, true, uErr
			}
			uObj, uErr := newPainlessURLFromString(fmt.Sprintf("%v", v1))
			return uObj, true, uErr
		case 3:
			// URL(protocol, host, file)
			pVal, _ := evalArg(0)
			hVal, _ := evalArg(1)
			fVal, _ := evalArg(2)
			fileStr := fmt.Sprintf("%v", fVal)
			if fileStr != "" && !strings.HasPrefix(fileStr, "/") {
				fileStr = "/" + fileStr
			}
			uObj, uErr := newPainlessURLFromString(fmt.Sprintf("%v://%v%s", pVal, hVal, fileStr))
			return uObj, true, uErr
		case 4:
			// URL(protocol, host, port, file)
			pVal, _ := evalArg(0)
			hVal, _ := evalArg(1)
			portVal, _ := evalArg(2)
			fVal, _ := evalArg(3)
			fileStr := fmt.Sprintf("%v", fVal)
			if fileStr != "" && !strings.HasPrefix(fileStr, "/") {
				fileStr = "/" + fileStr
			}
			port, _ := toInt64Painless(portVal)
			if port >= 0 {
				uObj, uErr := newPainlessURLFromString(fmt.Sprintf("%v://%v:%d%s", pVal, hVal, port, fileStr))
				return uObj, true, uErr
			}
			uObj, uErr := newPainlessURLFromString(fmt.Sprintf("%v://%v%s", pVal, hVal, fileStr))
			return uObj, true, uErr
		}
	}
	return nil, false, nil
}

func evalRound54StaticCallPainless(fnName string, args []string, argStr string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	evalArg := func(i int) (any, error) {
		if i >= len(args) {
			return nil, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(args[i]), params, depth+1)
	}
	evalIntArg := func(i int) (int, error) {
		v, err := evalArg(i)
		if err != nil {
			return 0, err
		}
		iv, _ := toInt64Painless(v)
		return int(iv), nil
	}

	// F20: Optional / OptionalInt / OptionalLong / OptionalDouble factories
	switch fnName {
	case "Optional.of", "Optional.ofNullable", "OptionalInt.of", "OptionalLong.of", "OptionalDouble.of":
		kind := strings.Split(fnName, ".")[0]
		if len(args) == 0 {
			return newPainlessOptional(kind, false, nil), true, nil
		}
		v, err := evalArg(0)
		if err != nil {
			return nil, true, err
		}
		if v == nil || v == painlessEmptyOptional {
			if fnName == "Optional.ofNullable" {
				return newPainlessOptional("Optional", false, nil), true, nil
			}
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: fnName + "(null)"}
		}
		if opt, isOpt := v.(*painlessOptional); isOpt && !opt.present && fnName == "Optional.ofNullable" {
			return newPainlessOptional("Optional", false, nil), true, nil
		}
		if kind != "Optional" {
			coerced, cErr := coerceOptionalPrimitivePainless(kind, v)
			if cErr != nil {
				return nil, true, cErr
			}
			return newPainlessOptional(kind, true, coerced), true, nil
		}
		return newPainlessOptional("Optional", true, v), true, nil
	case "Optional.empty", "OptionalInt.empty", "OptionalLong.empty", "OptionalDouble.empty":
		kind := strings.Split(fnName, ".")[0]
		return newPainlessOptional(kind, false, nil), true, nil
	}

	// F22: Objects.* and Collections.* static methods
	switch fnName {
	case "Objects.compare":
		if len(args) < 3 {
			return int64(0), true, nil
		}
		a, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		b, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		if painlessValuesEqual(a, b) {
			return int64(0), true, nil
		}
		c, errC := evalPainlessComparatorPair(strings.TrimSpace(args[2]), a, b, sourceMap, params, depth+1)
		return int64(c), true, errC
	case "Objects.requireNonNullElseGet":
		if len(args) < 2 {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "supplier"}
		}
		v0, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		if v0 != nil && v0 != painlessEmptyOptional {
			return v0, true, nil
		}
		supExpr := strings.TrimSpace(args[1])
		if supExpr == "null" {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "supplier"}
		}
		normSup := normalizeMethodReferenceToLambdaPainless(supExpr, 0)
		if arrowIdx := findNextUnquotedSubstr(normSup, "->", 0); arrowIdx >= 0 {
			res, err := evalPainlessLambdaBody(normSup[arrowIdx+2:], sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if res == nil || res == painlessEmptyOptional {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "supplier.get()"}
			}
			return res, true, nil
		}
		return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "supplier"}
	case "Objects.checkIndex":
		idx, err0 := evalIntArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		length, err1 := evalIntArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		if length <= 0 || idx < 0 || idx >= length {
			return nil, true, &painlessExceptionError{
				exType:  "IndexOutOfBoundsException",
				message: fmt.Sprintf("Index %d out of bounds for length %d", idx, length),
			}
		}
		return int64(idx), true, nil
	case "Objects.checkFromToIndex":
		fromIdx, err0 := evalIntArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		toIdx, err1 := evalIntArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		length, err2 := evalIntArg(2)
		if err2 != nil {
			return nil, true, err2
		}
		if fromIdx < 0 || fromIdx > toIdx || toIdx > length || length < 0 {
			return nil, true, &painlessExceptionError{
				exType:  "IndexOutOfBoundsException",
				message: fmt.Sprintf("Range [%d, %d) out of bounds for length %d", fromIdx, toIdx, length),
			}
		}
		return int64(fromIdx), true, nil
	case "Objects.checkFromIndexSize":
		fromIdx, err0 := evalIntArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		size, err1 := evalIntArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		length, err2 := evalIntArg(2)
		if err2 != nil {
			return nil, true, err2
		}
		if length < 0 || fromIdx < 0 || size < 0 || int64(fromIdx)+int64(size) > int64(length) {
			return nil, true, &painlessExceptionError{
				exType:  "IndexOutOfBoundsException",
				message: fmt.Sprintf("Range [%d, %d + %d) out of bounds for length %d", fromIdx, fromIdx, size, length),
			}
		}
		return int64(fromIdx), true, nil
	case "Objects.toIdentityString":
		v0, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		if v0 == nil || v0 == painlessEmptyOptional {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "Objects.toIdentityString(null)"}
		}
		cls := painlessClassForValuePainless(v0)
		hc := uint32(computeJavaHashCodePainless(v0)) // #nosec G115 -- 32-bit identity hash hex formatting
		return fmt.Sprintf("%s@%x", cls.fullName, hc), true, nil
	case "Objects.hashCode":
		if len(args) == 0 {
			return int64(0), true, nil
		}
		v0, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		return evalValueHashCodePainless(v0, sourceMap, params, depth+1), true, nil
	case "Objects.hash":
		var h int32 = 1
		for i := range args {
			vi, errI := evalArg(i)
			if errI != nil {
				return nil, true, errI
			}
			vh := int32(evalValueHashCodePainless(vi, sourceMap, params, depth+1)) // #nosec G115 -- 32-bit Java hashCode
			h = 31*h + vh
		}
		return int64(h), true, nil
	case "Collections.indexOfSubList", "Collections.lastIndexOfSubList":
		if len(args) < 2 {
			return int64(-1), true, nil
		}
		v0, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		v1, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		src, ok0 := v0.([]any)
		tgt, ok1 := v1.([]any)
		if !ok0 || !ok1 {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "List is null"}
		}
		if len(tgt) > len(src) {
			return int64(-1), true, nil
		}
		if len(tgt) == 0 {
			if fnName == "Collections.lastIndexOfSubList" {
				return int64(len(src)), true, nil
			}
			return int64(0), true, nil
		}
		limit := len(src) - len(tgt)
		if fnName == "Collections.lastIndexOfSubList" {
			for i := limit; i >= 0; i-- {
				match := true
				for j := 0; j < len(tgt); j++ {
					if !painlessValuesEqual(src[i+j], tgt[j]) {
						match = false
						break
					}
				}
				if match {
					return int64(i), true, nil
				}
			}
			return int64(-1), true, nil
		}
		for i := 0; i <= limit; i++ {
			match := true
			for j := 0; j < len(tgt); j++ {
				if !painlessValuesEqual(src[i+j], tgt[j]) {
					match = false
					break
				}
			}
			if match {
				return int64(i), true, nil
			}
		}
		return int64(-1), true, nil
	case "Collections.addAll":
		if len(args) < 1 {
			return false, true, nil
		}
		targetExpr := strings.TrimSpace(args[0])
		recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, targetExpr, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		slice, ok := recVal.([]any)
		if !ok {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "Collection is null"}
		}
		if len(args) == 1 {
			return false, true, nil
		}
		changed := false
		for i := 1; i < len(args); i++ {
			ev, errE := evalArg(i)
			if errE != nil {
				return nil, true, errE
			}
			if i == 1 && len(args) == 2 {
				if arr, isArr := ev.([]any); isArr {
					if len(arr) > 0 {
						slice = append(slice, arr...)
						changed = true
					}
					break
				}
			}
			slice = append(slice, ev)
			changed = true
		}
		if writeBack != nil {
			writeBack(slice)
		} else if reIdentOnly.MatchString(targetExpr) && params != nil {
			params[targetExpr] = slice
			syncLocalVarAlias(sourceMap, params, targetExpr)
		}
		return changed, true, nil
	case "Collections.copy":
		if len(args) < 2 {
			return nil, true, nil
		}
		destVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		srcVal, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		dest, okD := destVal.([]any)
		src, okS := srcVal.([]any)
		if !okD || !okS {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "List is null"}
		}
		if len(src) > len(dest) {
			return nil, true, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: "Source does not fit in dest"}
		}
		copy(dest, src)
		return nil, true, nil
	case "Collections.unmodifiableList", "Collections.unmodifiableSet", "Collections.unmodifiableMap", "Collections.unmodifiableCollection",
		"Collections.synchronizedList", "Collections.synchronizedSet", "Collections.synchronizedMap", "Collections.synchronizedCollection",
		"Collections.checkedList", "Collections.checkedSet", "Collections.checkedMap", "Collections.checkedCollection":
		if len(args) >= 1 {
			v0, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			if v0 == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: fnName + "(null)"}
			}
			return v0, true, nil
		}
		return nil, true, nil
	}

	// F23: ZoneOffset, ZoneId, Clock, OffsetTime static methods
	switch fnName {
	case "ZoneOffset.ofHours":
		h, err := evalIntArg(0)
		if err != nil {
			return nil, true, err
		}
		res, errZ := validateAndCreateZoneOffsetHMSSpainless(h, 0, 0)
		return res, true, errZ
	case "ZoneOffset.ofHoursMinutes":
		h, err0 := evalIntArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		m, err1 := evalIntArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		res, errZ := validateAndCreateZoneOffsetHMSSpainless(h, m, 0)
		return res, true, errZ
	case "ZoneOffset.ofHoursMinutesSeconds":
		h, err0 := evalIntArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		m, err1 := evalIntArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		s, err2 := evalIntArg(2)
		if err2 != nil {
			return nil, true, err2
		}
		res, errZ := validateAndCreateZoneOffsetHMSSpainless(h, m, s)
		return res, true, errZ
	case "ZoneOffset.ofTotalSeconds":
		tot, err0 := evalIntArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		if tot < -64800 || tot > 64800 {
			return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Total seconds not in valid range -64800 to 64800: %d", tot)}
		}
		return formatZoneOffsetSecondsPainless(tot), true, nil
	case "ZoneId.systemDefault":
		return "UTC", true, nil
	case "ZoneId.getAvailableZoneIds":
		return []any{
			"UTC", "Z", "GMT", "America/New_York", "America/Chicago",
			"America/Denver", "America/Los_Angeles", "Europe/London",
			"Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney",
		}, true, nil
	case "ZoneId.ofOffset":
		if len(args) < 2 {
			return "Z", true, nil
		}
		pVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		oVal, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		if pVal == nil || oVal == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "prefix or offset is null"}
		}
		pfx := fmt.Sprintf("%v", pVal)
		switch pfx {
		case "", "UTC", "GMT", "UT":
		default:
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "prefix should be GMT, UTC or UT, is: " + pfx}
		}
		offSec, ok := parseZoneOffsetSecondsPainless(oVal)
		if !ok {
			return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid ZoneOffset: %v", oVal)}
		}
		if offSec == 0 {
			if pfx == "" {
				return "Z", true, nil
			}
			return pfx, true, nil
		}
		return pfx + formatZoneOffsetSecondsPainless(offSec), true, nil
	case "Clock.systemUTC":
		budget := getOrInitEvalBudget(params)
		nowMs := int64(0)
		if budget != nil {
			nowMs = budget.nowMillis
		}
		return &painlessClock{kind: "SystemClock", zone: "Z", baseNowMs: nowMs}, true, nil
	case "Clock.systemDefaultZone":
		budget := getOrInitEvalBudget(params)
		nowMs := int64(0)
		if budget != nil {
			nowMs = budget.nowMillis
		}
		return &painlessClock{kind: "SystemClock", zone: "UTC", baseNowMs: nowMs}, true, nil
	case "Clock.system":
		zVal, err := evalArg(0)
		if err != nil {
			return nil, true, err
		}
		if zVal == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "zone"}
		}
		budget := getOrInitEvalBudget(params)
		nowMs := int64(0)
		if budget != nil {
			nowMs = budget.nowMillis
		}
		return &painlessClock{kind: "SystemClock", zone: fmt.Sprintf("%v", zVal), baseNowMs: nowMs}, true, nil
	case "Clock.fixed":
		iVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		zVal, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		if iVal == nil || zVal == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "instant or zone is null"}
		}
		tm, ok := parsePainlessDateTime(iVal)
		if !ok {
			return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid Instant: %v", iVal)}
		}
		return &painlessClock{kind: "FixedClock", zone: fmt.Sprintf("%v", zVal), fixedTime: tm.UTC(), hasFixed: true}, true, nil
	case "Clock.offset":
		cVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		dVal, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		baseClk, okC := cVal.(*painlessClock)
		dur, okD := parsePainlessDuration(dVal)
		if !okC || baseClk == nil || !okD {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "baseClock or offsetDuration is null"}
		}
		cp := *baseClk
		cp.kind = "OffsetClock"
		cp.offsetDur += dur
		return &cp, true, nil
	case "Clock.tickSeconds", "Clock.tickMinutes", "Clock.tickMillis":
		zVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		if zVal == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "zone"}
		}
		tickNanos := int64(time.Second)
		switch fnName {
		case "Clock.tickMinutes":
			tickNanos = int64(time.Minute)
		case "Clock.tickMillis":
			tickNanos = int64(time.Millisecond)
		}
		budget := getOrInitEvalBudget(params)
		nowMs := int64(0)
		if budget != nil {
			nowMs = budget.nowMillis
		}
		return &painlessClock{kind: "TickClock", zone: fmt.Sprintf("%v", zVal), tickNanos: tickNanos, baseNowMs: nowMs}, true, nil
	case "Clock.tick":
		cVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		dVal, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		baseClk, okC := cVal.(*painlessClock)
		dur, okD := parsePainlessDuration(dVal)
		if !okC || baseClk == nil || !okD {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "baseClock or tickDuration is null"}
		}
		if dur <= 0 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Tick duration must be positive"}
		}
		cp := *baseClk
		cp.kind = "TickClock"
		cp.tickNanos = dur.Nanoseconds()
		return &cp, true, nil
	case "OffsetTime.of":
		if len(args) == 2 {
			ltVal, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			offVal, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			h, m, s, n, okT := parseLocalTimeComponentsPainless(fmt.Sprintf("%v", ltVal))
			if !okT {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid LocalTime: %v", ltVal)}
			}
			offSec, okO := parseZoneOffsetSecondsPainless(offVal)
			if !okO {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid ZoneOffset: %v", offVal)}
			}
			res, err := newPainlessOffsetTime(h, m, s, n, offSec)
			return res, true, err
		}
		if len(args) >= 5 {
			h, err0 := evalIntArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			m, err1 := evalIntArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			s, err2 := evalIntArg(2)
			if err2 != nil {
				return nil, true, err2
			}
			n, err3 := evalIntArg(3)
			if err3 != nil {
				return nil, true, err3
			}
			offVal, err4 := evalArg(4)
			if err4 != nil {
				return nil, true, err4
			}
			offSec, okO := parseZoneOffsetSecondsPainless(offVal)
			if !okO {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid ZoneOffset: %v", offVal)}
			}
			res, err := newPainlessOffsetTime(h, m, s, n, offSec)
			return res, true, err
		}
		return nil, true, &painlessExceptionError{exType: "DateTimeException", message: "Invalid OffsetTime.of arguments"}
	case "OffsetTime.parse":
		v0, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		if v0 == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "text"}
		}
		if len(args) >= 2 {
			fVal, err1 := evalArg(1)
			if err1 != nil {
				return nil, true, err1
			}
			if tm, ok := parseDateTimeWithFormatterPainless(v0, fVal); ok {
				_, offSec := tm.Zone()
				res, err := newPainlessOffsetTime(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), offSec)
				return res, true, err
			}
		}
		ot, ok := parsePainlessOffsetTime(v0)
		if !ok {
			return nil, true, &painlessExceptionError{exType: "DateTimeParseException", message: fmt.Sprintf("Text %q could not be parsed as OffsetTime", fmt.Sprintf("%v", v0))}
		}
		return ot, true, nil
	case "OffsetTime.now":
		budget := getOrInitEvalBudget(params)
		nowMs := int64(0)
		if budget != nil {
			nowMs = budget.nowMillis
		}
		tm := time.UnixMilli(nowMs).UTC()
		if len(args) >= 1 && strings.TrimSpace(args[0]) != "" {
			v0, err0 := evalArg(0)
			if err0 != nil {
				return nil, true, err0
			}
			if clk, isClk := v0.(*painlessClock); isClk && clk != nil {
				tm = clk.currentTime(nowMs)
			} else if v0 != nil {
				loc := parseZoneLocationPainless(fmt.Sprintf("%v", v0))
				tm = tm.In(loc)
			}
		}
		_, offSec := tm.Zone()
		res, err := newPainlessOffsetTime(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), offSec)
		return res, true, err
	case "OffsetTime.ofInstant":
		iVal, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		zVal, err1 := evalArg(1)
		if err1 != nil {
			return nil, true, err1
		}
		tm, ok := parsePainlessDateTime(iVal)
		if !ok || zVal == nil {
			return nil, true, &painlessExceptionError{exType: "DateTimeException", message: "Invalid Instant or ZoneId"}
		}
		loc := parseZoneLocationPainless(fmt.Sprintf("%v", zVal))
		tm = tm.In(loc)
		_, offSec := tm.Zone()
		res, err := newPainlessOffsetTime(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), offSec)
		return res, true, err
	}

	// F26: URI.create
	if fnName == "URI.create" {
		v0, err0 := evalArg(0)
		if err0 != nil {
			return nil, true, err0
		}
		if v0 == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "URI.create(null)"}
		}
		uri, uErr := newPainlessURIFromString(fmt.Sprintf("%v", v0))
		if uErr != nil {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: uErr.Error()}
		}
		return uri, true, nil
	}

	// F25: super.method(...) or ClassName.staticMethod(...)
	if strings.HasPrefix(fnName, "super.") {
		mName := strings.TrimPrefix(fnName, "super.")
		if uo, isUO := params["this"].(*painlessUserObject); isUO && uo != nil && uo.class != nil {
			curCls := uo.class
			if cc, ok := params["__current_class"].(*painlessUserClass); ok && cc != nil {
				curCls = cc
			}
			if curCls.parent != nil {
				res, err := evalUserClassMethodOnClassPainless(uo, curCls.parent, mName, argStr, false, sourceMap, params, depth+1)
				return res, true, err
			}
		}
	}
	budget := getOrInitEvalBudget(params)
	if dotIdx := strings.IndexByte(fnName, '.'); dotIdx > 0 && budget != nil && len(budget.userClasses) > 0 {
		clsName := fnName[:dotIdx]
		mName := fnName[dotIdx+1:]
		if uCls := budget.userClasses[clsName]; uCls != nil {
			res, err := evalUserClassMethodOnClassPainless(nil, uCls, mName, argStr, true, sourceMap, params, depth+1)
			return res, true, err
		}
	}
	if dotIdx := strings.IndexByte(fnName, '.'); dotIdx < 0 && params != nil {
		if thisObj, isUO := params["this"].(*painlessUserObject); isUO && thisObj != nil && thisObj.class != nil {
			if thisObj.class.findMethod(fnName) != nil {
				res, err := evalUserClassMethodOnClassPainless(thisObj, thisObj.class, fnName, argStr, false, sourceMap, params, depth+1)
				return res, true, err
			}
		}
		if curCls, ok := params["__current_class"].(*painlessUserClass); ok && curCls != nil {
			if overloads, _ := curCls.findStaticMethodWithOwner(fnName); len(overloads) > 0 {
				res, err := evalUserClassMethodOnClassPainless(nil, curCls, fnName, argStr, true, sourceMap, params, depth+1)
				return res, true, err
			}
		}
	}

	return nil, false, nil
}

func execRound54StatementCallPainless(sourceMap map[string]any, stmt string, params map[string]any, budget *evalBudget) (bool, error) {
	if isTopLevelAssignmentStmt(stmt) || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return(") {
		return false, nil
	}
	for _, sPfx := range []string{"Collections.addAll(", "Collections.copy(", "java.util.Collections.addAll(", "java.util.Collections.copy("} {
		if strings.HasPrefix(stmt, sPfx) && strings.HasSuffix(stmt, ")") && findMatchingDelimiter(stmt, len(sPfx)-1, '(', ')') == len(stmt)-1 {
			val, _, err := evalStaticCallPainless(sourceMap, stmt, params, 0)
			if err != nil {
				return true, err
			}
			params["_last_expr_val"] = val
			return true, nil
		}
	}
	for _, mName := range []string{".accept(", ".combine("} {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(stmt, mName); ok {
			recVal, err := evalRHSExpr(sourceMap, recExpr, params)
			if err != nil {
				return true, err
			}
			if m, isMap := recVal.(map[string]any); isMap {
				if _, isStats := isSummaryStatisticsMapPainless(m); isStats {
					_, _, errM := evalRound54ParamMethodPreArgPainless(mName, recExpr, recVal, argExpr, sourceMap, params, 0)
					params["_last_expr_val"] = nil
					return true, errM
				}
			}
		}
	}
	return false, nil
}
