package painless

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func errUnsupportedOpPainless() error {
	return &painlessExceptionError{
		exType:  "UnsupportedOperationException",
		message: "UnsupportedOperationException",
	}
}

// ============================================================================
// F20: IEEE-754 NaN / ±Infinity Helpers
// ============================================================================

// toFloat64RawPainless converts numeric values to float64 while preserving
// IEEE-754 NaN, +Infinity, -Infinity, and -0.0. Unlike toFloat64, it does not
// coerce nil or strings and does not reject non-finite floats.
func toFloat64RawPainless(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	case int16:
		return float64(val), true
	case int8:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint64:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint16:
		return float64(val), true
	case uint8:
		return float64(val), true
	case json.Number:
		parsed, err := val.Float64()
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	case *painlessBigDecimal:
		if val == nil {
			return 0, false
		}
		return val.float64Value(), true
	case *painlessBigInteger:
		if val == nil {
			return 0, false
		}
		return val.float64Value(), true
	case *big.Int:
		if val == nil {
			return 0, false
		}
		f, _ := new(big.Float).SetInt(val).Float64()
		return f, true
	default:
		return 0, false
	}
}

func toFloat64WithRawPainless(v any) (float64, bool) {
	if f, ok := toFloat64RawPainless(v); ok {
		return f, true
	}
	if v == nil {
		return 0, false
	}
	return toFloat64(v)
}

func isRawFloatingValPainless(v any) (float64, bool) {
	switch tv := v.(type) {
	case float64:
		return tv, true
	case float32:
		return float64(tv), true
	default:
		return 0, false
	}
}

func isFloatingNaNPainless(v any) bool {
	f, ok := isRawFloatingValPainless(v)
	return ok && math.IsNaN(f)
}

func isNonFiniteFloatingPainless(v any) bool {
	f, ok := isRawFloatingValPainless(v)
	return ok && (math.IsNaN(f) || math.IsInf(f, 0))
}

// formatJavaFloatingPainless formats a float64 using Java NaN/Infinity tokens
// while preserving finite formatting compatibility with existing Painless tests.
func formatJavaFloatingPainless(f float64, bits int) string {
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	if bits == 32 && math.Abs(f) > math.MaxFloat32 {
		if f < 0 {
			return "-Infinity"
		}
		return "Infinity"
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// formatValueForStringPainless formats any Painless value for String.valueOf,
// Objects.toString, .toString(), and string '+' concatenation.
func formatValueForStringPainless(v any) string {
	if v == nil || v == painlessEmptyOptional {
		return "null"
	}
	switch tv := v.(type) {
	case string:
		return tv
	case float64:
		if math.IsNaN(tv) {
			return "NaN"
		}
		if math.IsInf(tv, 1) {
			return "Infinity"
		}
		if math.IsInf(tv, -1) {
			return "-Infinity"
		}
		return fmt.Sprintf("%v", tv)
	case float32:
		fv := float64(tv)
		if math.IsNaN(fv) {
			return "NaN"
		}
		if math.IsInf(fv, 1) {
			return "Infinity"
		}
		if math.IsInf(fv, -1) {
			return "-Infinity"
		}
		return fmt.Sprintf("%v", tv)
	case time.Duration:
		return formatDurationISO8601Painless(tv)
	case map[string]any:
		if _, isStats := isSummaryStatisticsMapPainless(tv); isStats {
			return formatSummaryStatisticsToStringPainless(tv)
		}
		if excType, hasExc := tv["__exc_type"].(string); hasExc && excType != "" {
			msg, _ := tv["message"].(string)
			if msg != "" {
				return excType + ": " + msg
			}
			return excType
		}
		return fmt.Sprintf("%v", tv)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// compareJavaDoubleTotalOrderPainless implements Java Double.compare / Float.compare
// total ordering: -Infinity < -0.0 < +0.0 < +Infinity < NaN (and NaN == NaN -> 0).
func compareJavaDoubleTotalOrderPainless(a, b float64) int {
	if math.IsNaN(a) {
		if math.IsNaN(b) {
			return 0
		}
		return 1
	}
	if math.IsNaN(b) {
		return -1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	// Equal in IEEE-754 (<=> finite equal, matching ±Inf, or ±0.0).
	sa := math.Signbit(a)
	sb := math.Signbit(b)
	if sa == sb {
		return 0
	}
	if sa {
		return -1
	}
	return 1
}

func javaFloatingMaxPainless(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	if a == 0 && b == 0 && math.Signbit(a) != math.Signbit(b) {
		return math.Copysign(0, 1)
	}
	if a >= b {
		return a
	}
	return b
}

func javaFloatingMinPainless(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	if a == 0 && b == 0 && math.Signbit(a) != math.Signbit(b) {
		return math.Copysign(0, -1)
	}
	if a <= b {
		return a
	}
	return b
}

func trimJavaASCIIControlSpacePainless(s string) string {
	start := 0
	for start < len(s) && s[start] <= 0x20 {
		start++
	}
	end := len(s)
	for end > start && s[end-1] <= 0x20 {
		end--
	}
	return s[start:end]
}

// parseJavaFloatingPainless implements Double.parseDouble/valueOf and Float.parseFloat/valueOf.
func parseJavaFloatingPainless(v any, bits int, isValueOf bool) (float64, error) {
	if v == nil || v == painlessEmptyOptional {
		return 0, &painlessExceptionError{
			exType:  "NullPointerException",
			message: "Cannot invoke \"String.trim()\" because \"in\" is null",
		}
	}
	if isValueOf {
		if f, ok := toFloat64RawPainless(v); ok {
			if bits == 32 && !math.IsNaN(f) && !math.IsInf(f, 0) && math.Abs(f) > math.MaxFloat32 {
				return math.Copysign(math.Inf(1), f), nil
			}
			return f, nil
		}
	} else {
		// In Painless dynamic calls, numeric arguments passed to parseDouble/parseFloat
		// only occurred if non-string; check string strictly first.
		if _, isStr := v.(string); !isStr {
			if f, ok := toFloat64RawPainless(v); ok {
				if bits == 32 && !math.IsNaN(f) && !math.IsInf(f, 0) && math.Abs(f) > math.MaxFloat32 {
					return math.Copysign(math.Inf(1), f), nil
				}
				return f, nil
			}
		}
	}
	s, ok := v.(string)
	if !ok {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", fmt.Sprintf("%v", v)),
		}
	}
	trimmed := trimJavaASCIIControlSpacePainless(s)
	if trimmed == "" || strings.ContainsRune(trimmed, '_') {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	switch trimmed {
	case "NaN", "+NaN", "-NaN":
		return math.NaN(), nil
	case "Infinity", "+Infinity":
		return math.Inf(1), nil
	case "-Infinity":
		return math.Inf(-1), nil
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "nan") || strings.Contains(lower, "inf") {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	clean := trimmed
	if len(clean) > 1 {
		last := clean[len(clean)-1]
		if last == 'f' || last == 'F' || last == 'd' || last == 'D' {
			isHex := strings.HasPrefix(lower, "0x") || strings.HasPrefix(lower, "+0x") || strings.HasPrefix(lower, "-0x")
			if !isHex || strings.ContainsAny(clean[:len(clean)-1], "pP") {
				clean = clean[:len(clean)-1]
			}
		}
	}
	fv, pErr := strconv.ParseFloat(clean, 64)
	if pErr != nil && !errors.Is(pErr, strconv.ErrRange) {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	if math.IsNaN(fv) {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	if bits == 32 && !math.IsInf(fv, 0) {
		if math.Abs(fv) > math.MaxFloat32 {
			return math.Copysign(math.Inf(1), fv), nil
		}
		if fv != 0 && math.Abs(fv) < float64(math.SmallestNonzeroFloat32)/2 {
			return math.Copysign(0, fv), nil
		}
	}
	return fv, nil
}

// ============================================================================
// F21: Integral Wrapper Parsing & Decoding Helpers
// ============================================================================

func isStrictJavaRadixDigitsPainless(s string, allowSign bool, allowNegative bool) bool {
	if len(s) == 0 {
		return false
	}
	idx := 0
	if allowSign && (s[0] == '+' || s[0] == '-') {
		if s[0] == '-' && !allowNegative {
			return false
		}
		idx++
		if idx >= len(s) {
			return false
		}
	}
	for i := idx; i < len(s); i++ {
		c := s[i]
		isDigit := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isDigit {
			return false
		}
	}
	return true
}

func extractStrictRadixArgPainless(rVal any) (int, error) {
	if rVal == nil || rVal == painlessEmptyOptional {
		return 0, &painlessExceptionError{exType: "NullPointerException", message: "radix is null"}
	}
	var radix int64
	var ok bool
	if iv, okI := toInt64Painless(rVal); okI {
		radix, ok = iv, true
	} else if fv, okF := toFloat64RawPainless(rVal); okF && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) {
		radix, ok = int64(fv), true
	}
	if !ok || radix < 2 || radix > 36 {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("radix %v less than Character.MIN_RADIX or greater than Character.MAX_RADIX", rVal),
		}
	}
	return int(radix), nil
}

func parseJavaSignedIntegralPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (int64, error) {
	if len(args) == 0 {
		return 0, &painlessExceptionError{exType: "NumberFormatException", message: "missing argument"}
	}
	v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err != nil {
		return 0, err
	}
	bitSize := 64
	switch fnName {
	case "Integer.parseInt", "Integer.valueOf":
		bitSize = 32
	case "Short.parseShort", "Short.valueOf":
		bitSize = 16
	case "Byte.parseByte", "Byte.valueOf":
		bitSize = 8
	}
	isValueOf := strings.HasSuffix(fnName, ".valueOf")
	if isValueOf && len(args) == 1 && v != nil {
		wrapInt := func(iv int64) int64 {
			switch bitSize {
			case 32:
				return int64(int32(iv)) // #nosec G115 -- intentional Java 32-bit boxing wrap
			case 16:
				return int64(int16(iv)) // #nosec G115 -- intentional Java 16-bit boxing wrap
			case 8:
				return int64(int8(iv)) // #nosec G115 -- intentional Java 8-bit boxing wrap
			default:
				return iv
			}
		}
		switch tv := v.(type) {
		case int:
			return wrapInt(int64(tv)), nil
		case int64:
			return wrapInt(tv), nil
		case int32:
			return wrapInt(int64(tv)), nil
		case int16:
			return wrapInt(int64(tv)), nil
		case int8:
			return wrapInt(int64(tv)), nil
		case float64:
			if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
				return wrapInt(int64(tv)), nil
			}
		case float32:
			fv := float64(tv)
			if !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return wrapInt(int64(fv)), nil
			}
		case json.Number:
			if iv, pErr := tv.Int64(); pErr == nil {
				return wrapInt(iv), nil
			}
			if fv, fErr := tv.Float64(); fErr == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return wrapInt(int64(fv)), nil
			}
		}
	}

	radix := 10
	if len(args) >= 2 {
		rVal, rErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if rErr != nil {
			return 0, rErr
		}
		parsedRadix, radErr := extractStrictRadixArgPainless(rVal)
		if radErr != nil {
			return 0, radErr
		}
		radix = parsedRadix
	}

	if v == nil || v == painlessEmptyOptional {
		return 0, &painlessExceptionError{exType: "NumberFormatException", message: "Cannot parse null string"}
	}
	s, ok := v.(string)
	if !ok || !isStrictJavaRadixDigitsPainless(s, true, true) {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", fmt.Sprintf("%v", v)),
		}
	}
	iv, pErr := strconv.ParseInt(s, radix, bitSize)
	if pErr != nil {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	return iv, nil
}

func parseJavaUnsignedIntegralPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (int64, error) {
	if len(args) == 0 {
		return 0, &painlessExceptionError{exType: "NumberFormatException", message: "missing argument"}
	}
	v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err != nil {
		return 0, err
	}
	radix := 10
	if len(args) >= 2 {
		rVal, rErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if rErr != nil {
			return 0, rErr
		}
		parsedRadix, radErr := extractStrictRadixArgPainless(rVal)
		if radErr != nil {
			return 0, radErr
		}
		radix = parsedRadix
	}
	if v == nil || v == painlessEmptyOptional {
		return 0, &painlessExceptionError{exType: "NumberFormatException", message: "Cannot parse null string"}
	}
	s, ok := v.(string)
	if !ok || !isStrictJavaRadixDigitsPainless(s, true, false) {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", fmt.Sprintf("%v", v)),
		}
	}
	clean := s
	if clean[0] == '+' {
		clean = clean[1:]
	}
	bitSize := 64
	if fnName == "Integer.parseUnsignedInt" {
		bitSize = 32
	}
	uv, pErr := strconv.ParseUint(clean, radix, bitSize)
	if pErr != nil {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	if bitSize == 32 {
		return int64(int32(uint32(uv))), nil // #nosec G115 -- intentional Java 32-bit signed reinterpretation of unsigned int
	}
	return int64(uv), nil // #nosec G115 -- intentional Java 64-bit signed reinterpretation of unsigned long
}

func decodeJavaIntegralPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (int64, error) {
	if len(args) == 0 {
		return 0, &painlessExceptionError{exType: "NullPointerException", message: "nm is null"}
	}
	v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err != nil {
		return 0, err
	}
	if v == nil || v == painlessEmptyOptional {
		return 0, &painlessExceptionError{
			exType:  "NullPointerException",
			message: "Cannot invoke \"String.length()\" because \"nm\" is null",
		}
	}
	s, ok := v.(string)
	if !ok || len(s) == 0 {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: "Zero length string",
		}
	}
	for _, r := range s {
		if r == '_' || r <= 0x20 || unicode.IsSpace(r) {
			return 0, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", s),
			}
		}
	}
	neg := false
	rest := s
	switch rest[0] {
	case '-':
		neg = true
		rest = rest[1:]
	case '+':
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	base := 10
	digits := rest
	if strings.HasPrefix(rest, "0x") || strings.HasPrefix(rest, "0X") {
		base = 16
		digits = rest[2:]
	} else if strings.HasPrefix(rest, "#") {
		base = 16
		digits = rest[1:]
	} else if rest[0] == '0' && len(rest) > 1 {
		base = 8
		digits = rest[1:]
	}
	if !isStrictJavaRadixDigitsPainless(digits, false, false) {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	bi, okBI := new(big.Int).SetString(digits, base)
	if !okBI {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	if neg {
		bi.Neg(bi)
	}
	if !bi.IsInt64() {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("For input string: %q", s),
		}
	}
	iv := bi.Int64()
	var minVal, maxVal int64
	switch fnName {
	case "Byte.decode":
		minVal, maxVal = math.MinInt8, math.MaxInt8
	case "Short.decode":
		minVal, maxVal = math.MinInt16, math.MaxInt16
	case "Integer.decode":
		minVal, maxVal = math.MinInt32, math.MaxInt32
	default:
		minVal, maxVal = math.MinInt64, math.MaxInt64
	}
	if iv < minVal || iv > maxVal {
		return 0, &painlessExceptionError{
			exType:  "NumberFormatException",
			message: fmt.Sprintf("Value %d out of range from input %s", iv, s),
		}
	}
	return iv, nil
}

// ============================================================================
// F22: BigDecimal.toString() JSR-13 Canonical Scientific Notation
// ============================================================================

func formatBigDecimalJSR13Painless(bd *painlessBigDecimal) string {
	if bd == nil || bd.unscaled == nil {
		return "0"
	}
	neg := bd.unscaled.Sign() < 0
	absVal := new(big.Int).Abs(bd.unscaled)
	digits := absVal.String()
	prec := len(digits)
	adjusted := -bd.scale + (prec - 1)
	if bd.scale >= 0 && adjusted >= -6 {
		return bd.toPlainString()
	}
	if absVal.Sign() == 0 {
		return fmt.Sprintf("0E%+d", -bd.scale)
	}
	mantissa := digits
	if len(digits) > 1 {
		mantissa = digits[:1] + "." + digits[1:]
	}
	prefix := ""
	if neg {
		prefix = "-"
	}
	return fmt.Sprintf("%s%sE%+d", prefix, mantissa, adjusted)
}

// ============================================================================
// F23 & F24: java.time Zone-Less LocalDateTime, ChronoField.with & Strict Parse
// ============================================================================

func extractBracketedZoneIDPainless(s string) (body, zoneID string, hasZone bool) {
	s = strings.TrimSpace(s)
	idx := strings.IndexByte(s, '[')
	if idx > 0 && strings.HasSuffix(s, "]") {
		zid := strings.TrimSpace(s[idx+1 : len(s)-1])
		if zid != "" {
			return strings.TrimSpace(s[:idx]), zid, true
		}
	}
	return s, "", false
}

func formatLocalDateTimeZoneLessPainless(tm time.Time) string {
	if tm.Nanosecond() > 0 {
		return tm.Format("2006-01-02T15:04:05.999999999")
	}
	return tm.Format("2006-01-02T15:04:05")
}

func validateChronoFieldValuePainless(cf painlessChronoField, newVal int64) error {
	vr, err := evalChronoFieldRangePainless(cf)
	if err != nil {
		return err
	}
	if !vr.isValidValue(newVal) {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for %s (valid values %s): %d", cf, vr.String(), newVal),
		}
	}
	return nil
}

func parseStrictJavaTemporalPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, error) {
	if len(args) == 0 {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "text"}
	}
	v, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err0 != nil {
		return nil, err0
	}
	if v == nil || v == painlessEmptyOptional {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "text"}
	}
	var fmtVal any
	hasFmt := len(args) >= 2
	if hasFmt {
		var err1 error
		fmtVal, err1 = evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if err1 != nil {
			return nil, err1
		}
		if fmtVal == nil || fmtVal == painlessEmptyOptional {
			return nil, &painlessExceptionError{exType: "NullPointerException", message: "formatter"}
		}
	}

	rawStr, isStr := v.(string)
	if !isStr {
		rawStr = fmt.Sprintf("%v", v)
	}
	parseErr := func() error {
		return &painlessExceptionError{
			exType:  "DateTimeParseException",
			message: fmt.Sprintf("Text %q could not be parsed for %s", rawStr, fnName),
		}
	}

	// Reject leading/trailing whitespace on unformatted ISO parse calls per java.time.*.parse
	if !hasFmt && strings.TrimSpace(rawStr) != rawStr {
		return nil, parseErr()
	}

	switch fnName {
	case "Duration.parse":
		if _, isDur := v.(time.Duration); isDur {
			return nil, parseErr()
		}
		if rawStr == "" || strings.TrimSpace(rawStr) != rawStr {
			return nil, parseErr()
		}
		dur, ok := parseISO8601DurationStrictPainless(rawStr)
		if !ok {
			return nil, parseErr()
		}
		return dur, nil

	case "Period.parse":
		if _, isPer := v.(painlessPeriod); isPer {
			return nil, parseErr()
		}
		if rawStr == "" || strings.TrimSpace(rawStr) != rawStr {
			return nil, parseErr()
		}
		per, ok := parseISO8601PeriodStrictPainless(rawStr)
		if !ok {
			return nil, parseErr()
		}
		return per, nil

	case "Year.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return painlessYear{year: int64(tm.Year())}, nil
		}
		y, ok := parseStrictISOYearPainless(rawStr)
		if !ok {
			return nil, parseErr()
		}
		return painlessYear{year: y}, nil

	case "YearMonth.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return fmt.Sprintf("%04d-%02d", tm.Year(), int(tm.Month())), nil
		}
		ym, ok := parseStrictISOYearMonthPainless(rawStr)
		if !ok {
			return nil, parseErr()
		}
		return ym, nil

	case "MonthDay.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return painlessMonthDay{month: int(tm.Month()), day: tm.Day()}, nil
		}
		md, ok := parseStrictISOMonthDayPainless(rawStr)
		if !ok {
			return nil, parseErr()
		}
		return md, nil

	case "LocalDate.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return tm.Format("2006-01-02"), nil
		}
		if len(rawStr) != 10 || rawStr[4] != '-' || rawStr[7] != '-' {
			return nil, parseErr()
		}
		tm, err := time.Parse("2006-01-02", rawStr)
		if err != nil {
			return nil, parseErr()
		}
		return tm.Format("2006-01-02"), nil

	case "LocalTime.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), nil
		}
		if strings.Contains(rawStr, "T") || strings.Contains(rawStr, "-") || strings.Contains(rawStr, "+") || strings.HasSuffix(rawStr, "Z") {
			return nil, parseErr()
		}
		h, m, sec, nano, ok := parseLocalTimeComponentsPainless(rawStr)
		if !ok || h < 0 || h > 23 || m < 0 || m > 59 || sec < 0 || sec > 59 || nano < 0 || nano > 999_999_999 {
			return nil, parseErr()
		}
		return formatLocalTimePainless(h, m, sec, nano), nil

	case "LocalDateTime.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return formatLocalDateTimeZoneLessPainless(tm), nil
		}
		// ISO_LOCAL_DATE_TIME requires yyyy-MM-ddTHH:mm[:ss[.SSSSSSSSS]] with NO offset or zone
		tIdx := strings.IndexByte(rawStr, 'T')
		if tIdx != 10 || rawStr[4] != '-' || rawStr[7] != '-' {
			return nil, parseErr()
		}
		datePart := rawStr[:10]
		timePart := rawStr[11:]
		if strings.ContainsAny(timePart, "Zz+-[] ") {
			return nil, parseErr()
		}
		dt, dErr := time.Parse("2006-01-02", datePart)
		if dErr != nil {
			return nil, parseErr()
		}
		h, m, sec, nano, okT := parseLocalTimeComponentsPainless(timePart)
		if !okT || h < 0 || h > 23 || m < 0 || m > 59 || sec < 0 || sec > 59 || nano < 0 || nano > 999_999_999 {
			return nil, parseErr()
		}
		tm := time.Date(dt.Year(), dt.Month(), dt.Day(), h, m, sec, nano, time.UTC)
		return formatLocalDateTimeZoneLessPainless(tm), nil

	case "Instant.parse":
		// ISO_INSTANT requires T and trailing Z (or UTC offset in Java 12+ DateTimeFormatter.ISO_INSTANT)
		if !strings.Contains(rawStr, "T") && !strings.Contains(rawStr, "t") {
			return nil, parseErr()
		}
		if strings.Contains(rawStr, "[") {
			return nil, parseErr()
		}
		tm, err := time.Parse(time.RFC3339Nano, rawStr)
		if err != nil {
			return nil, parseErr()
		}
		return tm.UTC().Format(time.RFC3339Nano), nil

	case "OffsetDateTime.parse":
		if hasFmt {
			tm, ok := parseDateTimeWithFormatterStrictPainless(rawStr, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			return tm.Format(time.RFC3339Nano), nil
		}
		if strings.Contains(rawStr, "[") {
			return nil, parseErr()
		}
		tm, ok := parseStrictOffsetDateTimeStringPainless(rawStr)
		if !ok {
			return nil, parseErr()
		}
		return tm.Format(time.RFC3339Nano), nil

	case "ZonedDateTime.parse":
		if hasFmt {
			body, zid, hasZ := extractBracketedZoneIDPainless(rawStr)
			tm, ok := parseDateTimeWithFormatterStrictPainless(body, fmtVal)
			if !ok {
				return nil, parseErr()
			}
			if hasZ {
				loc, zOk := loadStrictZoneLocationPainless(zid)
				if !zOk {
					return nil, parseErr()
				}
				return tm.In(loc).Format(time.RFC3339Nano) + "[" + zid + "]", nil
			}
			return tm.Format(time.RFC3339Nano), nil
		}
		body, zid, hasZ := extractBracketedZoneIDPainless(rawStr)
		tm, ok := parseStrictOffsetDateTimeStringPainless(body)
		if !ok {
			return nil, parseErr()
		}
		if hasZ {
			loc, zOk := loadStrictZoneLocationPainless(zid)
			if !zOk {
				return nil, parseErr()
			}
			// Preserve instant/wall time with explicit bracketed ZoneId
			return tm.In(loc).Format(time.RFC3339Nano) + "[" + zid + "]", nil
		}
		return tm.Format(time.RFC3339Nano), nil
	}

	return nil, parseErr()
}

func loadStrictZoneLocationPainless(zid string) (*time.Location, bool) {
	zid = strings.TrimSpace(zid)
	if zid == "" {
		return nil, false
	}
	if zid == "Z" || zid == "UTC" || zid == "GMT" || zid == "UT" {
		return time.UTC, true
	}
	if offSec, ok := parseZoneOffsetSecondsPainless(zid); ok {
		return time.FixedZone(zid, offSec), true
	}
	if strings.HasPrefix(zid, "UTC+") || strings.HasPrefix(zid, "UTC-") ||
		strings.HasPrefix(zid, "GMT+") || strings.HasPrefix(zid, "GMT-") {
		if offSec, ok := parseZoneOffsetSecondsPainless(zid[3:]); ok {
			return time.FixedZone(zid, offSec), true
		}
		return nil, false
	}
	loc, err := time.LoadLocation(zid)
	if err != nil {
		return nil, false
	}
	return loc, true
}

func parseStrictOffsetDateTimeStringPainless(s string) (time.Time, bool) {
	if len(s) < 16 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't') {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04Z07:00",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04-0700",
		"2006-01-02T15:04:05.999999999-0700",
	} {
		if tm, err := time.Parse(layout, strings.Replace(s, "t", "T", 1)); err == nil {
			return tm, true
		}
	}
	return time.Time{}, false
}

func parseDateTimeWithFormatterStrictPainless(s string, fmtVal any) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	layout, zLoc := splitFormatterAndZonePainless(fmtVal)
	candidates := []string{
		layout,
		strings.ReplaceAll(layout, "-0700", "Z0700"),
		strings.ReplaceAll(layout, "-0700", "Z07:00"),
		strings.ReplaceAll(layout, "Z0700", "Z07:00"),
		strings.ReplaceAll(layout, "Z07:00", "Z0700"),
		strings.ReplaceAll(layout, "Z07", "Z07:00"),
	}
	switch layout {
	case "2006-01-02T15:04:05":
		candidates = append(candidates, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04")
	case "15:04:05", "15:04:05.999999999":
		candidates = append(candidates, "15:04:05.999999999", "15:04:05", "15:04")
	}
	for _, c := range candidates {
		if zLoc != nil {
			if tm, err := time.ParseInLocation(c, s, zLoc); err == nil {
				return tm, true
			}
		}
		if tm, err := time.Parse(c, s); err == nil {
			if zLoc != nil {
				tm = tm.In(zLoc)
			}
			return tm, true
		}
	}
	return time.Time{}, false
}

func parseStrictISOYearPainless(s string) (int64, bool) {
	if len(s) == 0 {
		return 0, false
	}
	rest := s
	hasSign := false
	if rest[0] == '+' || rest[0] == '-' {
		hasSign = true
		rest = rest[1:]
	}
	if len(rest) < 4 || len(rest) > 10 {
		return 0, false
	}
	// ISO-8601 Year.parse requires '+' or '-' when more than 4 digits, and '+' with 4 digits is rejected unless >4 digits?
	// Actually Java Year.parse: 4 digits without sign ("2024"), or signed >= 4 digits ("-0004", "+10000", "+2024").
	_ = hasSign
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return 0, false
		}
	}
	y, err := strconv.ParseInt(s, 10, 64)
	if err != nil || y < -999_999_999 || y > 999_999_999 {
		return 0, false
	}
	return y, true
}

func parseStrictISOYearMonthPainless(s string) (string, bool) {
	if len(s) < 7 {
		return "", false
	}
	dashIdx := strings.LastIndexByte(s, '-')
	if dashIdx < 4 || dashIdx+3 != len(s) {
		return "", false
	}
	yPart := s[:dashIdx]
	mPart := s[dashIdx+1:]
	y, okY := parseStrictISOYearPainless(yPart)
	if !okY || len(mPart) != 2 || mPart[0] < '0' || mPart[0] > '9' || mPart[1] < '0' || mPart[1] > '9' {
		return "", false
	}
	m, err := strconv.Atoi(mPart)
	if err != nil || m < 1 || m > 12 {
		return "", false
	}
	return fmt.Sprintf("%04d-%02d", y, m), true
}

func parseStrictISOMonthDayPainless(s string) (painlessMonthDay, bool) {
	if len(s) != 7 || !strings.HasPrefix(s, "--") || s[4] != '-' {
		return painlessMonthDay{}, false
	}
	mStr := s[2:4]
	dStr := s[5:7]
	for i := 0; i < 2; i++ {
		if mStr[i] < '0' || mStr[i] > '9' || dStr[i] < '0' || dStr[i] > '9' {
			return painlessMonthDay{}, false
		}
	}
	m, err1 := strconv.Atoi(mStr)
	d, err2 := strconv.Atoi(dStr)
	if err1 != nil || err2 != nil || m < 1 || m > 12 {
		return painlessMonthDay{}, false
	}
	maxD := maxDaysInMonthPainless(m, true)
	if d < 1 || d > maxD {
		return painlessMonthDay{}, false
	}
	return painlessMonthDay{month: m, day: d}, true
}

func parseISO8601DurationStrictPainless(s string) (time.Duration, bool) {
	if len(s) < 4 {
		return 0, false
	}
	upper := strings.ToUpper(s)
	neg := false
	switch upper[0] {
	case '-':
		neg = true
		upper = upper[1:]
	case '+':
		upper = upper[1:]
	}
	if len(upper) < 3 || upper[0] != 'P' {
		return 0, false
	}
	upper = upper[1:]
	inTime := false
	parsedAny := false
	seenD, seenH, seenM, seenS := false, false, false, false
	var total time.Duration

	for len(upper) > 0 {
		if upper[0] == 'T' {
			if inTime {
				return 0, false
			}
			inTime = true
			upper = upper[1:]
			if len(upper) == 0 {
				return 0, false
			}
			continue
		}
		partSign := int64(1)
		switch upper[0] {
		case '-':
			partSign = -1
			upper = upper[1:]
		case '+':
			upper = upper[1:]
		}
		if len(upper) == 0 {
			return 0, false
		}
		i := 0
		dotCount := 0
		for i < len(upper) && ((upper[i] >= '0' && upper[i] <= '9') || upper[i] == '.' || upper[i] == ',') {
			if upper[i] == '.' || upper[i] == ',' {
				dotCount++
				if dotCount > 1 {
					return 0, false
				}
			}
			i++
		}
		if i == 0 || i >= len(upper) {
			return 0, false
		}
		numPart := strings.ReplaceAll(upper[:i], ",", ".")
		unit := upper[i]
		upper = upper[i+1:]

		if dotCount > 0 && unit != 'S' {
			return 0, false
		}
		switch unit {
		case 'D':
			if inTime || seenD {
				return 0, false
			}
			seenD = true
			iv, err := strconv.ParseInt(numPart, 10, 64)
			if err != nil {
				return 0, false
			}
			total += time.Duration(partSign*iv) * 24 * time.Hour
		case 'H':
			if !inTime || seenH || seenM || seenS {
				return 0, false
			}
			seenH = true
			iv, err := strconv.ParseInt(numPart, 10, 64)
			if err != nil {
				return 0, false
			}
			total += time.Duration(partSign*iv) * time.Hour
		case 'M':
			if !inTime || seenM || seenS {
				return 0, false
			}
			seenM = true
			iv, err := strconv.ParseInt(numPart, 10, 64)
			if err != nil {
				return 0, false
			}
			total += time.Duration(partSign*iv) * time.Minute
		case 'S':
			if !inTime || seenS {
				return 0, false
			}
			seenS = true
			secPart := numPart
			fracNanos := int64(0)
			if dotIdx := strings.IndexByte(numPart, '.'); dotIdx >= 0 {
				secPart = numPart[:dotIdx]
				fracStr := numPart[dotIdx+1:]
				if len(secPart) == 0 || len(fracStr) == 0 || len(fracStr) > 9 {
					return 0, false
				}
				for len(fracStr) < 9 {
					fracStr += "0"
				}
				fn, errF := strconv.ParseInt(fracStr, 10, 64)
				if errF != nil {
					return 0, false
				}
				fracNanos = fn
			}
			sv, errS := strconv.ParseInt(secPart, 10, 64)
			if errS != nil {
				return 0, false
			}
			total += time.Duration(partSign) * (time.Duration(sv)*time.Second + time.Duration(fracNanos))
		default:
			return 0, false
		}
		parsedAny = true
	}
	if !parsedAny {
		return 0, false
	}
	if neg {
		total = -total
	}
	return total, true
}

func parseISO8601PeriodStrictPainless(s string) (painlessPeriod, bool) {
	if len(s) < 3 {
		return painlessPeriod{}, false
	}
	upper := strings.ToUpper(s)
	neg := false
	switch upper[0] {
	case '-':
		neg = true
		upper = upper[1:]
	case '+':
		upper = upper[1:]
	}
	if len(upper) < 2 || upper[0] != 'P' {
		return painlessPeriod{}, false
	}
	upper = upper[1:]
	if strings.Contains(upper, "T") {
		return painlessPeriod{}, false
	}
	var p painlessPeriod
	parsedAny := false
	seenY, seenM, seenW, seenD := false, false, false, false
	for len(upper) > 0 {
		partSign := 1
		switch upper[0] {
		case '-':
			partSign = -1
			upper = upper[1:]
		case '+':
			upper = upper[1:]
		}
		if len(upper) == 0 {
			return painlessPeriod{}, false
		}
		i := 0
		for i < len(upper) && upper[i] >= '0' && upper[i] <= '9' {
			i++
		}
		if i == 0 || i >= len(upper) {
			return painlessPeriod{}, false
		}
		iv, err := strconv.Atoi(upper[:i])
		if err != nil {
			return painlessPeriod{}, false
		}
		iv *= partSign
		unit := upper[i]
		upper = upper[i+1:]
		switch unit {
		case 'Y':
			if seenY || seenM || seenW || seenD {
				return painlessPeriod{}, false
			}
			seenY = true
			p.years += iv
		case 'M':
			if seenM || seenW || seenD {
				return painlessPeriod{}, false
			}
			seenM = true
			p.months += iv
		case 'W':
			if seenW || seenD {
				return painlessPeriod{}, false
			}
			seenW = true
			p.days += iv * 7
		case 'D':
			if seenD {
				return painlessPeriod{}, false
			}
			seenD = true
			p.days += iv
		default:
			return painlessPeriod{}, false
		}
		parsedAny = true
	}
	if !parsedAny {
		return painlessPeriod{}, false
	}
	if neg {
		p.years = -p.years
		p.months = -p.months
		p.days = -p.days
	}
	return p, true
}

// ============================================================================
// F25: User-Defined Class Instance Method Dispatch in execSimpleStmt
// ============================================================================

func extractTrailingCallArgsFromStmtPainless(stmt string) (string, bool) {
	stmt = strings.TrimSpace(stmt)
	if !strings.HasSuffix(stmt, ")") {
		return "", false
	}
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(stmt)-1; i++ {
		if stepQuoteState(stmt, i, &inQuotes, &inRegexClass) {
			continue
		}
		if stmt[i] == '(' && findMatchingDelimiter(stmt, i, '(', ')') == len(stmt)-1 {
			return strings.TrimSpace(stmt[i+1 : len(stmt)-1]), true
		}
	}
	return "", false
}

func tryExecUserObjectStmtMethodPainless(targetVal any, methodName, stmt string, sourceMap, params map[string]any) (bool, error) {
	uo, ok := targetVal.(*painlessUserObject)
	if !ok || uo == nil || uo.class == nil {
		return false, nil
	}
	if len(uo.class.findMethod(methodName)) == 0 {
		return false, nil
	}
	argStr, okA := extractTrailingCallArgsFromStmtPainless(stmt)
	if !okA {
		return false, nil
	}
	res, err := evalUserObjectMethodPainless(uo, methodName, argStr, sourceMap, params, 0)
	if err != nil {
		return true, err
	}
	if params != nil {
		params["_last_expr_val"] = res
	}
	return true, nil
}

// ============================================================================
// F26: Unmodifiable Collection / Map Factories & Tracking
// ============================================================================

func allocUnmodSlicePainless(capHint int) []any {
	if capHint < 1 {
		capHint = 1
	}
	return make([]any, 0, capHint)
}

func markUnmodSlicePainless(budget *evalBudget, s []any) []any {
	if cap(s) == 0 {
		s = make([]any, 0, 1)
	}
	if budget != nil {
		ptr := reflect.ValueOf(s).Pointer()
		if ptr != 0 {
			if budget.unmodSlices == nil {
				budget.unmodSlices = make(map[uintptr]bool)
			}
			budget.unmodSlices[ptr] = true
		}
	}
	return s
}

func markUnmodMapPainless(budget *evalBudget, m map[string]any) map[string]any {
	if m == nil {
		m = make(map[string]any)
	}
	if budget != nil {
		ptr := reflect.ValueOf(m).Pointer()
		if ptr != 0 {
			if budget.unmodMaps == nil {
				budget.unmodMaps = make(map[uintptr]bool)
			}
			budget.unmodMaps[ptr] = true
		}
	}
	return m
}

func shallowCopyUnmodSlicePainless(budget *evalBudget, src []any) []any {
	cp := allocUnmodSlicePainless(len(src))
	cp = append(cp, src...)
	return markUnmodSlicePainless(budget, cp)
}

func shallowCopyUnmodMapPainless(budget *evalBudget, src map[string]any) map[string]any {
	cp := make(map[string]any, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return markUnmodMapPainless(budget, cp)
}

func isUnmodContainerPainless(budget *evalBudget, v any) bool {
	if budget == nil || v == nil {
		return false
	}
	switch tv := v.(type) {
	case []any:
		if len(budget.unmodSlices) == 0 {
			return false
		}
		ptr := reflect.ValueOf(tv).Pointer()
		return ptr != 0 && budget.unmodSlices[ptr]
	case map[string]any:
		if len(budget.unmodMaps) == 0 {
			return false
		}
		ptr := reflect.ValueOf(tv).Pointer()
		if ptr != 0 && budget.unmodMaps[ptr] {
			return true
		}
		if pm, ok := tv["__parent_map"].(map[string]any); ok && pm != nil {
			pPtr := reflect.ValueOf(pm).Pointer()
			if pPtr != 0 && budget.unmodMaps[pPtr] {
				return true
			}
		}
		if bm, ok := tv["__backing_map"].(map[string]any); ok && bm != nil {
			bPtr := reflect.ValueOf(bm).Pointer()
			if bPtr != 0 && budget.unmodMaps[bPtr] {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func checkMutableContainerPainless(budget *evalBudget, v any) error {
	if isUnmodContainerPainless(budget, v) {
		return errUnsupportedOpPainless()
	}
	return nil
}

func checkMutableAtPathPainless(budget *evalBudget, root map[string]any, path []string) error {
	if budget == nil || root == nil {
		return nil
	}
	var target any
	if len(path) == 0 {
		target = root
	} else {
		target = resolveParamPath(root, path)
	}
	return checkMutableContainerPainless(budget, target)
}

func checkMutableParentAtPathPainless(budget *evalBudget, root map[string]any, path []string) error {
	if budget == nil || root == nil || len(path) < 2 {
		return nil
	}
	for i := 1; i < len(path); i++ {
		parent := resolveParamPath(root, path[:i])
		if isUnmodContainerPainless(budget, parent) {
			return errUnsupportedOpPainless()
		}
	}
	return nil
}

func isInstantVarDeclOrExprPainless(stmt, rhsExpr string, params map[string]any) bool {
	trimmedStmt := strings.TrimSpace(stmt)
	if strings.HasPrefix(trimmedStmt, "Instant ") || strings.HasPrefix(trimmedStmt, "java.time.Instant ") {
		return true
	}
	tm := reVarTypeDeclPrefix.FindStringSubmatch(stmt)
	if len(tm) >= 2 {
		declType := strings.TrimSpace(tm[1])
		if declType == "Instant" || declType == "java.time.Instant" {
			return true
		}
	}
	return isInstantReceiverExprPainless(rhsExpr, params)
}

func stripBalancedOuterParensPainless(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		inQuote := byte(0)
		escaped := false
		wrapsAll := true
		for i := 0; i < len(s); i++ {
			ch := s[i]
			if escaped {
				escaped = false
				continue
			}
			if inQuote != 0 {
				switch ch {
				case '\\':
					escaped = true
				case inQuote:
					inQuote = 0
				}
				continue
			}
			switch ch {
			case '\'', '"':
				inQuote = ch
				continue
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i < len(s)-1 {
					wrapsAll = false
				}
			}
			if !wrapsAll {
				break
			}
		}
		if !wrapsAll || depth != 0 {
			break
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func isInstantReceiverExprPainless(expr string, params map[string]any) bool {
	s := stripBalancedOuterParensPainless(expr)
	if s == "" {
		return false
	}
	if strings.Contains(s, ".atZone(") || strings.Contains(s, ".atOffset(") || strings.Contains(s, ".toString(") {
		return false
	}
	if strings.HasPrefix(s, "Instant.") || strings.HasPrefix(s, "java.time.Instant.") {
		return true
	}
	if strings.Contains(s, ".toInstant(") || strings.Contains(s, ".instant(") {
		return true
	}
	if params == nil {
		return false
	}
	if reIdentOnly.MatchString(s) {
		return params["__temporal_kind_"+s] == "Instant"
	}
	if dotIdx := strings.IndexByte(s, '.'); dotIdx > 0 {
		baseIdent := strings.TrimSpace(s[:dotIdx])
		if reIdentOnly.MatchString(baseIdent) && params["__temporal_kind_"+baseIdent] == "Instant" {
			return true
		}
	}
	return false
}

func isInstantSupportedChronoFieldPainless(cf painlessChronoField) bool {
	switch strings.ToUpper(strings.TrimSpace(string(cf))) {
	case "NANO_OF_SECOND", "MICRO_OF_SECOND", "MILLI_OF_SECOND", "INSTANT_SECONDS":
		return true
	default:
		return false
	}
}

func tryBuildLambdaPredicateArgPainless(rawArg string, capturedParams map[string]any) (*painlessPredicate, bool) {
	s := strings.TrimSpace(rawArg)
	if s == "" {
		return nil, false
	}
	norm := s
	if strings.Contains(s, "::") {
		norm = normalizeMethodReferenceToLambdaPainless(s, 1)
	}
	arrowIdx := findNextUnquotedSubstr(norm, "->", 0)
	if arrowIdx <= 0 || arrowIdx+2 > len(norm) {
		return nil, false
	}
	pNames := parsePainlessLambdaHeader(norm[:arrowIdx])
	if len(pNames) != 1 {
		return nil, false
	}
	pName := pNames[0]
	body := strings.TrimSpace(norm[arrowIdx+2:])
	if body == "" {
		return nil, false
	}
	captured := make(map[string]any, len(capturedParams))
	for k, v := range capturedParams {
		captured[k] = v
	}
	return &painlessPredicate{
		fn: func(val any, sm, pm map[string]any, d int) (bool, error) {
			scope := make(map[string]any, len(captured)+2)
			for k, v := range captured {
				scope[k] = v
			}
			if pm != nil {
				if b, ok := pm["__eval_budget"]; ok {
					scope["__eval_budget"] = b
				}
			}
			scope[pName] = val
			return evalPainlessPredicateLambda(body, sm, scope, d+1)
		},
	}, true
}
