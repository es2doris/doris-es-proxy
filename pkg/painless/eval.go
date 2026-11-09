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

package painless

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- Painless Digest.md5 compatibility
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- Painless Digest.sha1 compatibility
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	errPainlessReturn   = errors.New("painless_return")
	errPainlessBreak    = errors.New("painless_break")
	errPainlessContinue = errors.New("painless_continue")
	errPainlessYield    = errors.New("painless_yield")
)

type painlessLabeledJumpError struct {
	label   string
	isBreak bool
}

func (e *painlessLabeledJumpError) Error() string {
	if e.isBreak {
		return "painless_labeled_break:" + e.label
	}
	return "painless_labeled_continue:" + e.label
}

type painlessEmptyOptionalType struct{}

func (painlessEmptyOptionalType) String() string {
	return "Optional.empty"
}

var painlessEmptyOptional = painlessEmptyOptionalType{}

func isEmptyOptionalOrNilPainless(v any) bool {
	return v == nil || v == painlessEmptyOptional
}

func unwrapPainlessInternalValue(v any) any {
	if v == painlessEmptyOptional {
		return nil
	}
	switch tv := v.(type) {
	case *painlessBigInteger:
		if tv == nil || tv.val == nil {
			return int64(0)
		}
		if tv.val.IsInt64() {
			return tv.val.Int64()
		}
		return tv.val.String()
	case []any:
		changed := false
		for _, elem := range tv {
			if elem == painlessEmptyOptional {
				changed = true
				break
			}
			if _, isBI := elem.(*painlessBigInteger); isBI {
				changed = true
				break
			}
		}
		if !changed {
			return tv
		}
		out := make([]any, len(tv))
		for i, elem := range tv {
			out[i] = unwrapPainlessInternalValue(elem)
		}
		return out
	}
	return v
}

func unwrapEmptyOptionalPainless(v any) any {
	return unwrapPainlessInternalValue(v)
}

// painlessHexFormat represents a java.util.HexFormat instance in Painless.
type painlessHexFormat struct {
	delimiter string
	prefix    string
	suffix    string
	upperCase bool
}

func (hf painlessHexFormat) String() string {
	uc := "false"
	if hf.upperCase {
		uc = "true"
	}
	return fmt.Sprintf("uppercase: %s, delimiter: %q, prefix: %q, suffix: %q", uc, hf.delimiter, hf.prefix, hf.suffix)
}

// painlessYear represents a java.time.Year value in Painless.
type painlessYear struct {
	year int64
}

func (y painlessYear) String() string {
	return strconv.FormatInt(y.year, 10)
}

func (y painlessYear) getValue() int64 {
	return y.year
}

func (y painlessYear) isLeap() bool {
	return isLeapYearPainless(int(y.year))
}

func (y painlessYear) length() int64 {
	if y.isLeap() {
		return 366
	}
	return 365
}

func (y painlessYear) atDay(day int) string {
	maxDay := int(y.length())
	if day < 1 {
		day = 1
	} else if day > maxDay {
		day = maxDay
	}
	tm := time.Date(int(y.year), 1, day, 0, 0, 0, 0, time.UTC)
	return tm.Format("2006-01-02")
}

func (y painlessYear) atMonth(month int) string {
	if month < 1 {
		month = 1
	} else if month > 12 {
		month = 12
	}
	return fmt.Sprintf("%04d-%02d", y.year, month)
}

func (y painlessYear) atMonthDay(md painlessMonthDay) string {
	maxDay := maxDaysInMonthPainless(md.month, y.isLeap())
	d := md.day
	if d > maxDay {
		d = maxDay
	}
	if d < 1 {
		d = 1
	}
	return fmt.Sprintf("%04d-%02d-%02d", y.year, md.month, d)
}

func isLeapYearPainless(year int) bool {
	return (year%4 == 0 && year%100 != 0) || (year%400 == 0)
}

// painlessMonthDay represents a java.time.MonthDay value in Painless.
type painlessMonthDay struct {
	month int
	day   int
}

func (md painlessMonthDay) String() string {
	return fmt.Sprintf("--%02d-%02d", md.month, md.day)
}

func (md painlessMonthDay) getMonth() string {
	if md.month >= 1 && md.month <= 12 {
		return strings.ToUpper(time.Month(md.month).String())
	}
	return "JANUARY"
}

func (md painlessMonthDay) getMonthValue() int64 {
	return int64(md.month)
}

func (md painlessMonthDay) getDayOfMonth() int64 {
	return int64(md.day)
}

func (md painlessMonthDay) atYear(year int) string {
	maxDay := maxDaysInMonthPainless(md.month, isLeapYearPainless(year))
	d := md.day
	if d > maxDay {
		d = maxDay
	}
	if d < 1 {
		d = 1
	}
	return fmt.Sprintf("%04d-%02d-%02d", year, md.month, d)
}

func (md painlessMonthDay) isValidYear(year int) bool {
	if md.month == 2 && md.day == 29 {
		return isLeapYearPainless(year)
	}
	return md.month >= 1 && md.month <= 12 && md.day >= 1 && md.day <= maxDaysInMonthPainless(md.month, true)
}

func (md painlessMonthDay) withMonth(month int) painlessMonthDay {
	if month < 1 {
		month = 1
	} else if month > 12 {
		month = 12
	}
	maxD := maxDaysInMonthPainless(month, true)
	d := md.day
	if d > maxD {
		d = maxD
	}
	return painlessMonthDay{month: month, day: d}
}

func (md painlessMonthDay) withDayOfMonth(day int) painlessMonthDay {
	maxD := maxDaysInMonthPainless(md.month, true)
	if day < 1 {
		day = 1
	} else if day > maxD {
		day = maxD
	}
	return painlessMonthDay{month: md.month, day: day}
}

func maxDaysInMonthPainless(month int, leapYear bool) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if leapYear {
			return 29
		}
		return 28
	default:
		return 31
	}
}

func parseMonthNumberPainless(v any) (int, bool) {
	if iv, ok := toInt64Painless(v); ok && iv >= 1 && iv <= 12 {
		return int(iv), true
	}
	if s, ok := v.(string); ok {
		s = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(s, "Month.")))
		switch s {
		case "JANUARY":
			return 1, true
		case "FEBRUARY":
			return 2, true
		case "MARCH":
			return 3, true
		case "APRIL":
			return 4, true
		case "MAY":
			return 5, true
		case "JUNE":
			return 6, true
		case "JULY":
			return 7, true
		case "AUGUST":
			return 8, true
		case "SEPTEMBER":
			return 9, true
		case "OCTOBER":
			return 10, true
		case "NOVEMBER":
			return 11, true
		case "DECEMBER":
			return 12, true
		}
	}
	return 0, false
}

// painlessChronoField represents a java.time.temporal.ChronoField constant in Painless.
type painlessChronoField string

func (cf painlessChronoField) String() string {
	return string(cf)
}

func parseChronoFieldArgPainless(argVal any) (painlessChronoField, bool) {
	if cf, ok := argVal.(painlessChronoField); ok {
		return cf, true
	}
	if s, ok := argVal.(string); ok && strings.HasPrefix(s, "ChronoField.") {
		return painlessChronoField(strings.TrimPrefix(s, "ChronoField.")), true
	}
	return "", false
}

func classifyTemporalStringKindPainless(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 7 && s[4] == '-' {
		return "YearMonth"
	}
	if len(s) == 10 && s[4] == '-' && s[7] == '-' {
		return "LocalDate"
	}
	if !strings.Contains(s, "-") && strings.Contains(s, ":") {
		return "LocalTime"
	}
	if strings.HasSuffix(s, "Z") || strings.Contains(s, "+") || (strings.Contains(s, "T") && strings.LastIndexByte(s, '-') > 10) {
		return "ZonedDateTime"
	}
	return "LocalDateTime"
}

func evalIsSupportedChronoFieldPainless(recVal any, cf painlessChronoField) bool {
	field := strings.ToUpper(string(cf))
	switch tv := recVal.(type) {
	case painlessYear:
		switch field {
		case "YEAR", "YEAR_OF_ERA", "ERA":
			return true
		}
		return false
	case painlessMonthDay:
		switch field {
		case "MONTH_OF_YEAR", "DAY_OF_MONTH":
			return true
		}
		return false
	case string:
		if _, ok := parsePainlessDateTime(tv); !ok {
			return false
		}
		kind := classifyTemporalStringKindPainless(tv)
		switch kind {
		case "YearMonth":
			switch field {
			case "YEAR", "YEAR_OF_ERA", "ERA", "MONTH_OF_YEAR", "PROLEPTIC_MONTH":
				return true
			}
			return false
		case "LocalDate":
			switch field {
			case "YEAR", "YEAR_OF_ERA", "ERA", "MONTH_OF_YEAR", "PROLEPTIC_MONTH",
				"DAY_OF_MONTH", "DAY_OF_YEAR", "DAY_OF_WEEK", "EPOCH_DAY",
				"ALIGNED_DAY_OF_WEEK_IN_MONTH", "ALIGNED_DAY_OF_WEEK_IN_YEAR",
				"ALIGNED_WEEK_OF_MONTH", "ALIGNED_WEEK_OF_YEAR":
				return true
			}
			return false
		case "LocalTime":
			switch field {
			case "HOUR_OF_DAY", "CLOCK_HOUR_OF_DAY", "HOUR_OF_AMPM", "CLOCK_HOUR_OF_AMPM", "AMPM_OF_DAY",
				"MINUTE_OF_HOUR", "MINUTE_OF_DAY", "SECOND_OF_MINUTE", "SECOND_OF_DAY",
				"MILLI_OF_SECOND", "MILLI_OF_DAY", "MICRO_OF_SECOND", "MICRO_OF_DAY",
				"NANO_OF_SECOND", "NANO_OF_DAY":
				return true
			}
			return false
		case "LocalDateTime":
			return field != "INSTANT_SECONDS" && field != "OFFSET_SECONDS"
		default:
			return true
		}
	}
	return false
}

func evalGetChronoFieldPainless(recVal any, cf painlessChronoField) (int64, error) {
	field := strings.ToUpper(string(cf))
	if yr, ok := recVal.(painlessYear); ok {
		switch field {
		case "YEAR":
			return yr.year, nil
		case "YEAR_OF_ERA":
			if yr.year >= 1 {
				return yr.year, nil
			}
			return 1 - yr.year, nil
		case "ERA":
			if yr.year >= 1 {
				return 1, nil
			}
			return 0, nil
		default:
			return 0, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported field: " + field}
		}
	}
	if md, ok := recVal.(painlessMonthDay); ok {
		switch field {
		case "MONTH_OF_YEAR":
			return int64(md.month), nil
		case "DAY_OF_MONTH":
			return int64(md.day), nil
		default:
			return 0, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported field: " + field}
		}
	}
	tm, ok := parsePainlessDateTime(recVal)
	if !ok {
		return 0, nil
	}
	if s, isStr := recVal.(string); isStr && !evalIsSupportedChronoFieldPainless(s, cf) {
		return 0, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported field: " + field}
	}
	switch field {
	case "YEAR":
		return int64(tm.Year()), nil
	case "YEAR_OF_ERA":
		if tm.Year() >= 1 {
			return int64(tm.Year()), nil
		}
		return int64(1 - tm.Year()), nil
	case "ERA":
		if tm.Year() >= 1 {
			return 1, nil
		}
		return 0, nil
	case "MONTH_OF_YEAR":
		return int64(tm.Month()), nil
	case "PROLEPTIC_MONTH":
		return int64(tm.Year())*12 + int64(tm.Month()) - 1, nil
	case "DAY_OF_MONTH":
		return int64(tm.Day()), nil
	case "DAY_OF_YEAR":
		return int64(tm.YearDay()), nil
	case "DAY_OF_WEEK":
		dow := int64(tm.Weekday())
		if dow == 0 {
			dow = 7
		}
		return dow, nil
	case "ALIGNED_DAY_OF_WEEK_IN_MONTH":
		return int64((tm.Day()-1)%7 + 1), nil
	case "ALIGNED_DAY_OF_WEEK_IN_YEAR":
		return int64((tm.YearDay()-1)%7 + 1), nil
	case "ALIGNED_WEEK_OF_MONTH":
		return int64((tm.Day()-1)/7 + 1), nil
	case "ALIGNED_WEEK_OF_YEAR":
		return int64((tm.YearDay()-1)/7 + 1), nil
	case "EPOCH_DAY":
		return time.Date(tm.Year(), tm.Month(), tm.Day(), 0, 0, 0, 0, time.UTC).Unix() / 86400, nil
	case "HOUR_OF_DAY":
		return int64(tm.Hour()), nil
	case "CLOCK_HOUR_OF_DAY":
		if tm.Hour() == 0 {
			return 24, nil
		}
		return int64(tm.Hour()), nil
	case "HOUR_OF_AMPM":
		return int64(tm.Hour() % 12), nil
	case "CLOCK_HOUR_OF_AMPM":
		h := tm.Hour() % 12
		if h == 0 {
			return 12, nil
		}
		return int64(h), nil
	case "AMPM_OF_DAY":
		if tm.Hour() >= 12 {
			return 1, nil
		}
		return 0, nil
	case "MINUTE_OF_HOUR":
		return int64(tm.Minute()), nil
	case "MINUTE_OF_DAY":
		return int64(tm.Hour()*60 + tm.Minute()), nil
	case "SECOND_OF_MINUTE":
		return int64(tm.Second()), nil
	case "SECOND_OF_DAY":
		return int64(tm.Hour()*3600 + tm.Minute()*60 + tm.Second()), nil
	case "MILLI_OF_SECOND":
		return int64(tm.Nanosecond() / 1_000_000), nil
	case "MILLI_OF_DAY":
		return int64(tm.Hour()*3600+tm.Minute()*60+tm.Second())*1_000 + int64(tm.Nanosecond()/1_000_000), nil
	case "MICRO_OF_SECOND":
		return int64(tm.Nanosecond() / 1_000), nil
	case "MICRO_OF_DAY":
		return int64(tm.Hour()*3600+tm.Minute()*60+tm.Second())*1_000_000 + int64(tm.Nanosecond()/1_000), nil
	case "NANO_OF_SECOND":
		return int64(tm.Nanosecond()), nil
	case "NANO_OF_DAY":
		return int64(tm.Hour()*3600+tm.Minute()*60+tm.Second())*1_000_000_000 + int64(tm.Nanosecond()), nil
	case "INSTANT_SECONDS":
		return tm.Unix(), nil
	case "OFFSET_SECONDS":
		_, off := tm.Zone()
		return int64(off), nil
	}
	return 0, nil
}

func evalWithChronoFieldPainless(recVal any, cf painlessChronoField, newVal int64) (any, error) {
	field := strings.ToUpper(string(cf))
	if yr, ok := recVal.(painlessYear); ok {
		switch field {
		case "YEAR", "YEAR_OF_ERA":
			return painlessYear{year: newVal}, nil
		default:
			return yr, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported field: " + field}
		}
	}
	if md, ok := recVal.(painlessMonthDay); ok {
		switch field {
		case "MONTH_OF_YEAR":
			return md.withMonth(int(newVal)), nil
		case "DAY_OF_MONTH":
			return md.withDayOfMonth(int(newVal)), nil
		default:
			return md, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported field: " + field}
		}
	}
	tm, ok := parsePainlessDateTime(recVal)
	if !ok {
		return recVal, nil
	}
	kind := "ZonedDateTime"
	if s, isStr := recVal.(string); isStr {
		if !evalIsSupportedChronoFieldPainless(s, cf) {
			return recVal, &painlessExceptionError{exType: "UnsupportedTemporalTypeException", message: "Unsupported field: " + field}
		}
		kind = classifyTemporalStringKindPainless(s)
	}
	y, m, d := tm.Year(), int(tm.Month()), tm.Day()
	hr, min, sec, nano := tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()
	switch field {
	case "YEAR", "YEAR_OF_ERA":
		y = int(newVal)
	case "MONTH_OF_YEAR":
		m = int(newVal)
	case "DAY_OF_MONTH":
		d = int(newVal)
	case "DAY_OF_YEAR":
		base := time.Date(y, 1, int(newVal), hr, min, sec, nano, tm.Location())
		y, m, d = base.Year(), int(base.Month()), base.Day()
	case "HOUR_OF_DAY":
		hr = int(newVal)
	case "MINUTE_OF_HOUR":
		min = int(newVal)
	case "SECOND_OF_MINUTE":
		sec = int(newVal)
	case "MILLI_OF_SECOND":
		nano = int(newVal) * 1_000_000
	case "MICRO_OF_SECOND":
		nano = int(newVal) * 1_000
	case "NANO_OF_SECOND":
		nano = int(newVal)
	}
	maxD := daysInMonthPainless(y, time.Month(m))
	if d > maxD {
		d = maxD
	}
	updated := time.Date(y, time.Month(m), d, hr, min, sec, nano, tm.Location())
	switch kind {
	case "YearMonth":
		return fmt.Sprintf("%04d-%02d", updated.Year(), int(updated.Month())), nil
	case "LocalDate":
		return updated.Format("2006-01-02"), nil
	case "LocalTime":
		return formatLocalTimePainless(updated.Hour(), updated.Minute(), updated.Second(), updated.Nanosecond()), nil
	case "LocalDateTime":
		if updated.Nanosecond() > 0 {
			return updated.Format("2006-01-02T15:04:05.999999999"), nil
		}
		return updated.Format("2006-01-02T15:04:05"), nil
	default:
		return updated.Format(time.RFC3339Nano), nil
	}
}

// painlessClassObject represents a java.lang.Class descriptor in Painless.
type painlessClassObject struct {
	fullName   string
	simpleName string
}

func (c painlessClassObject) String() string {
	return "class " + c.fullName
}

func painlessClassForValuePainless(val any) painlessClassObject {
	if val == nil {
		return painlessClassObject{fullName: "java.lang.Object", simpleName: "Object"}
	}
	switch tv := val.(type) {
	case painlessClassObject:
		return painlessClassObject{fullName: "java.lang.Class", simpleName: "Class"}
	case map[string]any:
		if excType, hasExc := tv["__exc_type"].(string); hasExc && excType != "" {
			if idx := strings.LastIndexByte(excType, '.'); idx >= 0 {
				return painlessClassObject{fullName: excType, simpleName: excType[idx+1:]}
			}
			switch excType {
			case "DateTimeParseException":
				return painlessClassObject{fullName: "java.time.format.DateTimeParseException", simpleName: excType}
			case "DateTimeException", "UnsupportedTemporalTypeException":
				return painlessClassObject{fullName: "java.time." + excType, simpleName: excType}
			case "NoSuchElementException":
				return painlessClassObject{fullName: "java.util.NoSuchElementException", simpleName: excType}
			case "PatternSyntaxException":
				return painlessClassObject{fullName: "java.util.regex.PatternSyntaxException", simpleName: excType}
			default:
				return painlessClassObject{fullName: "java.lang." + excType, simpleName: excType}
			}
		}
		return painlessClassObject{fullName: "java.util.HashMap", simpleName: "HashMap"}
	case []any:
		return painlessClassObject{fullName: "java.util.ArrayList", simpleName: "ArrayList"}
	case string:
		return painlessClassObject{fullName: "java.lang.String", simpleName: "String"}
	case bool:
		return painlessClassObject{fullName: "java.lang.Boolean", simpleName: "Boolean"}
	case int, int32:
		return painlessClassObject{fullName: "java.lang.Integer", simpleName: "Integer"}
	case int64:
		return painlessClassObject{fullName: "java.lang.Long", simpleName: "Long"}
	case int16:
		return painlessClassObject{fullName: "java.lang.Short", simpleName: "Short"}
	case int8, uint8:
		return painlessClassObject{fullName: "java.lang.Byte", simpleName: "Byte"}
	case float32:
		return painlessClassObject{fullName: "java.lang.Float", simpleName: "Float"}
	case float64:
		return painlessClassObject{fullName: "java.lang.Double", simpleName: "Double"}
	case json.Number:
		if !strings.ContainsAny(string(tv), ".eE") {
			return painlessClassObject{fullName: "java.lang.Long", simpleName: "Long"}
		}
		return painlessClassObject{fullName: "java.lang.Double", simpleName: "Double"}
	case *painlessStringBuilder:
		return painlessClassObject{fullName: "java.lang.StringBuilder", simpleName: "StringBuilder"}
	case *painlessBigDecimal:
		return painlessClassObject{fullName: "java.math.BigDecimal", simpleName: "BigDecimal"}
	case *painlessBigInteger:
		return painlessClassObject{fullName: "java.math.BigInteger", simpleName: "BigInteger"}
	case painlessMathContext:
		return painlessClassObject{fullName: "java.math.MathContext", simpleName: "MathContext"}
	case *painlessTemporalAdjuster:
		return painlessClassObject{fullName: "java.time.temporal.TemporalAdjuster", simpleName: "TemporalAdjuster"}
	case *painlessComparator:
		return painlessClassObject{fullName: "java.util.Comparator", simpleName: "Comparator"}
	case *painlessBitSet:
		return painlessClassObject{fullName: "java.util.BitSet", simpleName: "BitSet"}
	case *painlessStringJoiner:
		return painlessClassObject{fullName: "java.util.StringJoiner", simpleName: "StringJoiner"}
	case *painlessUserObject:
		if tv != nil && tv.class != nil {
			return painlessClassObject{fullName: tv.class.name, simpleName: tv.class.name}
		}
		return painlessClassObject{fullName: "java.lang.Object", simpleName: "Object"}
	case painlessYear:
		return painlessClassObject{fullName: "java.time.Year", simpleName: "Year"}
	case painlessMonthDay:
		return painlessClassObject{fullName: "java.time.MonthDay", simpleName: "MonthDay"}
	case painlessChronoField:
		return painlessClassObject{fullName: "java.time.temporal.ChronoField", simpleName: "ChronoField"}
	case painlessPeriod:
		return painlessClassObject{fullName: "java.time.Period", simpleName: "Period"}
	case time.Duration:
		return painlessClassObject{fullName: "java.time.Duration", simpleName: "Duration"}
	case *painlessMatcher:
		return painlessClassObject{fullName: "java.util.regex.Matcher", simpleName: "Matcher"}
	case *painlessPattern:
		return painlessClassObject{fullName: "java.util.regex.Pattern", simpleName: "Pattern"}
	case painlessHexFormat:
		return painlessClassObject{fullName: "java.util.HexFormat", simpleName: "HexFormat"}
	case painlessEmptyOptionalType:
		return painlessClassObject{fullName: "java.util.Optional", simpleName: "Optional"}
	default:
		return painlessClassObject{fullName: "java.lang.Object", simpleName: "Object"}
	}
}

// painlessPattern represents a compiled java.util.regex.Pattern in Painless.
type painlessPattern struct {
	raw     string
	re      *regexp.Regexp
	flags   int
	literal string
}

func (p *painlessPattern) String() string {
	if p == nil {
		return "null"
	}
	return p.raw
}

type painlessExceptionError struct {
	exType  string
	message string
}

func (e *painlessExceptionError) Error() string {
	switch e.exType {
	case "NoSuchElementException":
		if e.message != "" {
			return "java.util.NoSuchElementException: " + e.message
		}
		return "java.util.NoSuchElementException"
	case "IllegalArgumentException":
		if e.message != "" {
			if strings.HasPrefix(e.message, "illegal_argument_exception:") {
				return e.message + " (java.lang.IllegalArgumentException)"
			}
			return "illegal_argument_exception: " + e.message + " (java.lang.IllegalArgumentException)"
		}
		return "illegal_argument_exception (java.lang.IllegalArgumentException)"
	case "IllegalStateException":
		if e.message != "" {
			return "java.lang.IllegalStateException: " + e.message
		}
		return "java.lang.IllegalStateException"
	}
	if e.exType != "" && e.message != "" {
		return e.exType + ": " + e.message
	}
	if e.exType != "" {
		return e.exType
	}
	return e.message
}

type painlessPeriod struct {
	years  int
	months int
	days   int
}

func (p painlessPeriod) String() string {
	if p.years == 0 && p.months == 0 && p.days == 0 {
		return "P0D"
	}
	var sb strings.Builder
	sb.WriteByte('P')
	if p.years != 0 {
		sb.WriteString(strconv.Itoa(p.years))
		sb.WriteByte('Y')
	}
	if p.months != 0 {
		sb.WriteString(strconv.Itoa(p.months))
		sb.WriteByte('M')
	}
	if p.days != 0 {
		sb.WriteString(strconv.Itoa(p.days))
		sb.WriteByte('D')
	}
	return sb.String()
}

func (p painlessPeriod) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

type painlessStringBuilder struct {
	buf string
}

func (sb *painlessStringBuilder) String() string {
	if sb == nil {
		return ""
	}
	return sb.buf
}

func (sb *painlessStringBuilder) MarshalJSON() ([]byte, error) {
	return json.Marshal(sb.String())
}

type painlessBigDecimal struct {
	unscaled *big.Int
	scale    int
}

func newPainlessBigDecimal(unscaled *big.Int, scale int) *painlessBigDecimal {
	if unscaled == nil {
		unscaled = big.NewInt(0)
	} else {
		unscaled = new(big.Int).Set(unscaled)
	}
	return &painlessBigDecimal{unscaled: unscaled, scale: scale}
}

func parsePainlessBigDecimal(v any) (*painlessBigDecimal, bool) {
	switch tv := v.(type) {
	case *painlessBigDecimal:
		if tv == nil {
			return nil, false
		}
		return newPainlessBigDecimal(tv.unscaled, tv.scale), true
	case *painlessBigInteger:
		if tv == nil || tv.val == nil {
			return nil, false
		}
		return newPainlessBigDecimal(tv.val, 0), true
	case int:
		return newPainlessBigDecimal(big.NewInt(int64(tv)), 0), true
	case int64:
		return newPainlessBigDecimal(big.NewInt(tv), 0), true
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return nil, false
		}
		return parsePainlessBigDecimalString(strconv.FormatFloat(tv, 'f', -1, 64))
	case json.Number:
		return parsePainlessBigDecimalString(tv.String())
	case string:
		return parsePainlessBigDecimalString(tv)
	}
	return nil, false
}

func parsePainlessBigDecimalString(s string) (*painlessBigDecimal, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	neg := false
	switch s[0] {
	case '-':
		neg = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if s == "" {
		return nil, false
	}
	exp := 0
	if eIdx := strings.IndexAny(s, "eE"); eIdx >= 0 {
		ev, err := strconv.Atoi(s[eIdx+1:])
		if err != nil {
			return nil, false
		}
		exp = ev
		s = s[:eIdx]
	}
	scale := 0
	if dotIdx := strings.IndexByte(s, '.'); dotIdx >= 0 {
		fracLen := len(s) - dotIdx - 1
		scale = fracLen
		s = s[:dotIdx] + s[dotIdx+1:]
	}
	if s == "" {
		return nil, false
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, false
	}
	if neg && bi.Sign() != 0 {
		bi.Neg(bi)
	}
	scale -= exp
	return &painlessBigDecimal{unscaled: bi, scale: scale}, true
}

func bigTenPowPainless(n int) *big.Int {
	if n <= 0 {
		return big.NewInt(1)
	}
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
}

func (bd *painlessBigDecimal) toPlainString() string {
	if bd == nil || bd.unscaled == nil {
		return "0"
	}
	neg := bd.unscaled.Sign() < 0
	absVal := new(big.Int).Abs(bd.unscaled)
	digits := absVal.String()
	if bd.scale == 0 {
		if neg {
			return "-" + digits
		}
		return digits
	}
	if bd.scale < 0 {
		if absVal.Sign() == 0 {
			return "0"
		}
		out := digits + strings.Repeat("0", -bd.scale)
		if neg {
			return "-" + out
		}
		return out
	}
	var out string
	if len(digits) <= bd.scale {
		out = "0." + strings.Repeat("0", bd.scale-len(digits)) + digits
	} else {
		splitIdx := len(digits) - bd.scale
		out = digits[:splitIdx] + "." + digits[splitIdx:]
	}
	if neg {
		return "-" + out
	}
	return out
}

func (bd *painlessBigDecimal) String() string {
	return bd.toPlainString()
}

func (bd *painlessBigDecimal) MarshalJSON() ([]byte, error) {
	if bd == nil {
		return []byte("null"), nil
	}
	return []byte(bd.toPlainString()), nil
}

func (bd *painlessBigDecimal) float64Value() float64 {
	if bd == nil || bd.unscaled == nil {
		return 0
	}
	f, err := strconv.ParseFloat(bd.toPlainString(), 64)
	if err != nil {
		return 0
	}
	return f
}

func bigIntToLongValuePainless(val *big.Int) int64 {
	if val == nil {
		return 0
	}
	if val.IsInt64() {
		return val.Int64()
	}
	mod64 := new(big.Int).Lsh(big.NewInt(1), 64)
	rem := new(big.Int).Mod(val, mod64)
	half64 := new(big.Int).Lsh(big.NewInt(1), 63)
	if rem.Cmp(half64) >= 0 {
		rem.Sub(rem, mod64)
	}
	return rem.Int64()
}

func int64ToInt32Painless(v int64) int64 {
	return int64(int32(v)) // #nosec G115 -- Intentional Java 32-bit int narrowing semantics
}

func int64ToInt16Painless(v int64) int64 {
	return int64(int16(v)) // #nosec G115 -- Intentional Java 16-bit short narrowing semantics
}

func int64ToInt8Painless(v int64) int64 {
	return int64(int8(v)) // #nosec G115 -- Intentional Java 8-bit byte narrowing semantics
}

func (bd *painlessBigDecimal) toBigInt() *big.Int {
	if bd == nil || bd.unscaled == nil {
		return big.NewInt(0)
	}
	val := new(big.Int).Set(bd.unscaled)
	if bd.scale > 0 {
		val.Quo(val, bigTenPowPainless(bd.scale))
	} else if bd.scale < 0 {
		val.Mul(val, bigTenPowPainless(-bd.scale))
	}
	return val
}

func (bd *painlessBigDecimal) bigIntExact() (*big.Int, error) {
	if bd == nil || bd.unscaled == nil {
		return big.NewInt(0), nil
	}
	val := new(big.Int).Set(bd.unscaled)
	if bd.scale > 0 {
		q, r := new(big.Int).QuoRem(val, bigTenPowPainless(bd.scale), new(big.Int))
		if r.Sign() != 0 {
			return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Rounding necessary"}
		}
		return q, nil
	}
	if bd.scale < 0 {
		val.Mul(val, bigTenPowPainless(-bd.scale))
	}
	return val, nil
}

func (bd *painlessBigDecimal) longValue() int64 {
	return bigIntToLongValuePainless(bd.toBigInt())
}

func (bd *painlessBigDecimal) intValue() int64 {
	return int64ToInt32Painless(bd.longValue())
}

func (bd *painlessBigDecimal) shortValue() int64 {
	return int64ToInt16Painless(bd.longValue())
}

func (bd *painlessBigDecimal) byteValue() int64 {
	return int64ToInt8Painless(bd.longValue())
}

func (bd *painlessBigDecimal) longValueExact() (int64, error) {
	bi, err := bd.bigIntExact()
	if err != nil {
		return 0, err
	}
	if !bi.IsInt64() {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "Overflow"}
	}
	return bi.Int64(), nil
}

func (bd *painlessBigDecimal) intValueExact() (int64, error) {
	lv, err := bd.longValueExact()
	if err != nil {
		return 0, err
	}
	if lv < math.MinInt32 || lv > math.MaxInt32 {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "Overflow"}
	}
	return lv, nil
}

func (bd *painlessBigDecimal) shortValueExact() (int64, error) {
	lv, err := bd.longValueExact()
	if err != nil {
		return 0, err
	}
	if lv < math.MinInt16 || lv > math.MaxInt16 {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "Overflow"}
	}
	return lv, nil
}

func (bd *painlessBigDecimal) byteValueExact() (int64, error) {
	lv, err := bd.longValueExact()
	if err != nil {
		return 0, err
	}
	if lv < math.MinInt8 || lv > math.MaxInt8 {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "Overflow"}
	}
	return lv, nil
}

func (bd *painlessBigDecimal) toEngineeringString() string {
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
		switch {
		case bd.scale == 0:
			return "0"
		case bd.scale > 0 && bd.scale <= 6:
			return "0." + strings.Repeat("0", bd.scale)
		default:
			rem := adjusted % 3
			if rem < 0 {
				rem += 3
			}
			exp := adjusted - rem
			switch rem {
			case 0:
				return fmt.Sprintf("0.00E%+d", exp)
			case 1:
				return fmt.Sprintf("0.0E%+d", exp)
			default:
				return fmt.Sprintf("0E%+d", exp)
			}
		}
	}
	rem := adjusted % 3
	if rem < 0 {
		rem += 3
	}
	intDigits := rem + 1
	exp := adjusted - rem
	var mantissa string
	if intDigits >= len(digits) {
		mantissa = digits + strings.Repeat("0", intDigits-len(digits))
	} else {
		mantissa = digits[:intDigits] + "." + digits[intDigits:]
	}
	out := fmt.Sprintf("%sE%+d", mantissa, exp)
	if neg {
		return "-" + out
	}
	return out
}

func (bd *painlessBigDecimal) precision() int64 {
	if bd == nil || bd.unscaled == nil {
		return 1
	}
	absStr := new(big.Int).Abs(bd.unscaled).String()
	return int64(len(absStr))
}

func (bd *painlessBigDecimal) stripTrailingZeros() *painlessBigDecimal {
	if bd == nil || bd.unscaled == nil {
		return newPainlessBigDecimal(big.NewInt(0), 0)
	}
	if bd.unscaled.Sign() == 0 {
		return newPainlessBigDecimal(big.NewInt(0), 0)
	}
	u := new(big.Int).Set(bd.unscaled)
	sc := bd.scale
	ten := big.NewInt(10)
	rem := new(big.Int)
	for {
		q, r := new(big.Int).QuoRem(u, ten, rem)
		if r.Sign() != 0 {
			break
		}
		u = q
		sc--
	}
	return &painlessBigDecimal{unscaled: u, scale: sc}
}

func roundBigIntQuotientPainless(num, den *big.Int, mode string) (*big.Int, error) {
	q, r := new(big.Int).QuoRem(num, den, new(big.Int))
	if r.Sign() == 0 {
		return q, nil
	}
	neg := (num.Sign() < 0) != (den.Sign() < 0)
	absR := new(big.Int).Abs(r)
	absDen := new(big.Int).Abs(den)
	twiceR := new(big.Int).Lsh(absR, 1)
	cmpHalf := twiceR.Cmp(absDen)

	incMag := false
	normMode := strings.TrimPrefix(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(mode)), "ROUNDINGMODE."), "ROUND_")
	switch normMode {
	case "UP", "0":
		incMag = true
	case "DOWN", "1":
		incMag = false
	case "CEILING", "2":
		incMag = !neg
	case "FLOOR", "3":
		incMag = neg
	case "HALF_UP", "4", "":
		incMag = cmpHalf >= 0
	case "HALF_DOWN", "5":
		incMag = cmpHalf > 0
	case "HALF_EVEN", "6":
		if cmpHalf > 0 {
			incMag = true
		} else if cmpHalf == 0 {
			incMag = q.Bit(0) == 1
		}
	case "UNNECESSARY", "7":
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Rounding necessary"}
	default:
		incMag = cmpHalf >= 0
	}
	if incMag {
		if neg {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	return q, nil
}

func (bd *painlessBigDecimal) setScale(targetScale int, mode string) (*painlessBigDecimal, error) {
	if bd == nil || bd.unscaled == nil {
		return newPainlessBigDecimal(big.NewInt(0), targetScale), nil
	}
	if targetScale == bd.scale {
		return newPainlessBigDecimal(bd.unscaled, bd.scale), nil
	}
	if targetScale > bd.scale {
		mul := bigTenPowPainless(targetScale - bd.scale)
		return &painlessBigDecimal{unscaled: new(big.Int).Mul(bd.unscaled, mul), scale: targetScale}, nil
	}
	div := bigTenPowPainless(bd.scale - targetScale)
	q, err := roundBigIntQuotientPainless(bd.unscaled, div, mode)
	if err != nil {
		return nil, err
	}
	return &painlessBigDecimal{unscaled: q, scale: targetScale}, nil
}

func alignBigDecimalsPainless(a, b *painlessBigDecimal) (*big.Int, *big.Int, int) {
	if a.scale == b.scale {
		return new(big.Int).Set(a.unscaled), new(big.Int).Set(b.unscaled), a.scale
	}
	if a.scale > b.scale {
		mul := bigTenPowPainless(a.scale - b.scale)
		return new(big.Int).Set(a.unscaled), new(big.Int).Mul(b.unscaled, mul), a.scale
	}
	mul := bigTenPowPainless(b.scale - a.scale)
	return new(big.Int).Mul(a.unscaled, mul), new(big.Int).Set(b.unscaled), b.scale
}

func compareBigDecimalPainless(a, b *painlessBigDecimal) int {
	ua, ub, _ := alignBigDecimalsPainless(a, b)
	return ua.Cmp(ub)
}

func (bd *painlessBigDecimal) cmp(other *painlessBigDecimal) int {
	return compareBigDecimalPainless(bd, other)
}

func (bd *painlessBigDecimal) sub(other *painlessBigDecimal) *painlessBigDecimal {
	ua, ub, sc := alignBigDecimalsPainless(bd, other)
	return &painlessBigDecimal{unscaled: new(big.Int).Sub(ua, ub), scale: sc}
}

func (bd *painlessBigDecimal) mul(other *painlessBigDecimal) *painlessBigDecimal {
	return &painlessBigDecimal{
		unscaled: new(big.Int).Mul(bd.unscaled, other.unscaled),
		scale:    bd.scale + other.scale,
	}
}

func (bd *painlessBigDecimal) div(other *painlessBigDecimal, targetScale int, mode string) (*painlessBigDecimal, error) {
	if other == nil || other.unscaled == nil || other.unscaled.Sign() == 0 {
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Division by zero"}
	}
	num := new(big.Int).Set(bd.unscaled)
	den := new(big.Int).Set(other.unscaled)
	shift := targetScale - bd.scale + other.scale
	if shift > 0 {
		num.Mul(num, bigTenPowPainless(shift))
	} else if shift < 0 {
		den.Mul(den, bigTenPowPainless(-shift))
	}
	q, err := roundBigIntQuotientPainless(num, den, mode)
	if err != nil {
		return nil, err
	}
	return &painlessBigDecimal{unscaled: q, scale: targetScale}, nil
}

func (bd *painlessBigDecimal) divideAndRemainder(other *painlessBigDecimal) (*painlessBigDecimal, *painlessBigDecimal, error) {
	if other == nil || other.unscaled == nil || other.unscaled.Sign() == 0 {
		return nil, nil, &painlessExceptionError{exType: "ArithmeticException", message: "Division by zero"}
	}
	ua, ub, maxSc := alignBigDecimalsPainless(bd, other)
	qInt, rInt := new(big.Int).QuoRem(ua, ub, new(big.Int))
	prefScale := bd.scale - other.scale
	qBD := &painlessBigDecimal{unscaled: qInt, scale: 0}
	if prefScale > 0 {
		qBD = &painlessBigDecimal{
			unscaled: new(big.Int).Mul(qInt, bigTenPowPainless(prefScale)),
			scale:    prefScale,
		}
	}
	rBD := &painlessBigDecimal{unscaled: rInt, scale: maxSc}
	return qBD, rBD, nil
}

// painlessMathContext represents a java.math.MathContext instance in Painless.
type painlessMathContext struct {
	precision    int
	roundingMode string
}

func (mc painlessMathContext) String() string {
	mode := mc.roundingMode
	if mode == "" {
		mode = "HALF_UP"
	}
	return fmt.Sprintf("precision=%d roundingMode=%s", mc.precision, mode)
}

func normalizeRoundingModePainless(v any) string {
	if v == nil {
		return "HALF_UP"
	}
	mode := fmt.Sprintf("%v", v)
	norm := strings.TrimPrefix(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(mode)), "ROUNDINGMODE."), "ROUND_")
	switch norm {
	case "UP", "0":
		return "UP"
	case "DOWN", "1":
		return "DOWN"
	case "CEILING", "2":
		return "CEILING"
	case "FLOOR", "3":
		return "FLOOR"
	case "HALF_UP", "4", "":
		return "HALF_UP"
	case "HALF_DOWN", "5":
		return "HALF_DOWN"
	case "HALF_EVEN", "6":
		return "HALF_EVEN"
	case "UNNECESSARY", "7":
		return "UNNECESSARY"
	default:
		return "HALF_UP"
	}
}

func applyMathContextPainless(bd *painlessBigDecimal, mc painlessMathContext) (*painlessBigDecimal, error) {
	if bd == nil || bd.unscaled == nil {
		return newPainlessBigDecimal(big.NewInt(0), 0), nil
	}
	if mc.precision <= 0 || bd.unscaled.Sign() == 0 {
		return newPainlessBigDecimal(bd.unscaled, bd.scale), nil
	}
	absStr := new(big.Int).Abs(bd.unscaled).String()
	curPrec := len(absStr)
	if curPrec <= mc.precision {
		return newPainlessBigDecimal(bd.unscaled, bd.scale), nil
	}
	drop := curPrec - mc.precision
	targetScale := bd.scale - drop
	return bd.setScale(targetScale, mc.roundingMode)
}

func divideBigDecimalWithMathContextPainless(a, b *painlessBigDecimal, mc painlessMathContext) (*painlessBigDecimal, error) {
	if b == nil || b.unscaled == nil || b.unscaled.Sign() == 0 {
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Division by zero"}
	}
	if a == nil || a.unscaled == nil || a.unscaled.Sign() == 0 {
		preferredScale := 0
		if a != nil {
			preferredScale = a.scale - b.scale
		}
		return newPainlessBigDecimal(big.NewInt(0), preferredScale), nil
	}
	if mc.precision <= 0 {
		ua, ub, _ := alignBigDecimalsPainless(a, b)
		if q, r := new(big.Int).QuoRem(ua, ub, new(big.Int)); r.Sign() == 0 {
			return newPainlessBigDecimal(q, 0), nil
		}
		scale := a.scale - b.scale
		if scale < 10 {
			scale = 10
		}
		num := new(big.Int).Set(a.unscaled)
		den := new(big.Int).Set(b.unscaled)
		shift := scale - a.scale + b.scale
		if shift > 0 {
			num.Mul(num, bigTenPowPainless(shift))
		} else if shift < 0 {
			den.Mul(den, bigTenPowPainless(-shift))
		}
		if q, r := new(big.Int).QuoRem(num, den, new(big.Int)); r.Sign() == 0 {
			return (&painlessBigDecimal{unscaled: q, scale: scale}).stripTrailingZeros(), nil
		}
		return nil, &painlessExceptionError{exType: "ArithmeticException", message: "Non-terminating decimal expansion; no exact representable decimal result."}
	}
	precA := len(new(big.Int).Abs(a.unscaled).String())
	precB := len(new(big.Int).Abs(b.unscaled).String())
	extraScale := mc.precision + precB - precA + 2
	if extraScale < 0 {
		extraScale = 0
	}
	targetScale := (a.scale - b.scale) + extraScale
	num := new(big.Int).Set(a.unscaled)
	den := new(big.Int).Set(b.unscaled)
	if extraScale > 0 {
		num.Mul(num, bigTenPowPainless(extraScale))
	}
	q, err := roundBigIntQuotientPainless(num, den, mc.roundingMode)
	if err != nil {
		return nil, err
	}
	res := &painlessBigDecimal{unscaled: q, scale: targetScale}
	rounded, err := applyMathContextPainless(res, mc)
	if err != nil {
		return nil, err
	}
	// Strip unnecessary trailing zeros down to preferred scale (a.scale - b.scale) per Java BigDecimal.divide(divisor, mc)
	prefScale := a.scale - b.scale
	u := new(big.Int).Set(rounded.unscaled)
	sc := rounded.scale
	ten := big.NewInt(10)
	rem := new(big.Int)
	for sc > prefScale && u.Sign() != 0 {
		qTen, rTen := new(big.Int).QuoRem(u, ten, rem)
		if rTen.Sign() != 0 {
			break
		}
		u = qTen
		sc--
	}
	return &painlessBigDecimal{unscaled: u, scale: sc}, nil
}

// painlessBigInteger represents an arbitrary-precision java.math.BigInteger in Painless.
type painlessBigInteger struct {
	val *big.Int
}

func newPainlessBigInteger(v *big.Int) *painlessBigInteger {
	if v == nil {
		return &painlessBigInteger{val: big.NewInt(0)}
	}
	return &painlessBigInteger{val: new(big.Int).Set(v)}
}

func parsePainlessBigInteger(v any) (*painlessBigInteger, bool) {
	switch tv := v.(type) {
	case *painlessBigInteger:
		if tv == nil || tv.val == nil {
			return nil, false
		}
		return newPainlessBigInteger(tv.val), true
	case *painlessBigDecimal:
		if tv == nil || tv.unscaled == nil {
			return nil, false
		}
		return newPainlessBigInteger(tv.toBigInt()), true
	case int:
		return newPainlessBigInteger(big.NewInt(int64(tv))), true
	case int64:
		return newPainlessBigInteger(big.NewInt(tv)), true
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return nil, false
		}
		return newPainlessBigInteger(big.NewInt(int64(tv))), true
	case json.Number:
		if bi, ok := new(big.Int).SetString(strings.TrimSpace(tv.String()), 10); ok {
			return newPainlessBigInteger(bi), true
		}
		return nil, false
	case string:
		if bi, ok := new(big.Int).SetString(strings.TrimSpace(tv), 10); ok {
			return newPainlessBigInteger(bi), true
		}
		return nil, false
	}
	return nil, false
}

func newPainlessBigIntegerFromBytes(raw []byte) *painlessBigInteger {
	if len(raw) == 0 {
		return newPainlessBigInteger(big.NewInt(0))
	}
	mag := new(big.Int).SetBytes(raw)
	if raw[0]&0x80 != 0 {
		twoPow := new(big.Int).Lsh(big.NewInt(1), uint(len(raw)*8)) // #nosec G115 -- len(raw) is non-negative
		mag.Sub(mag, twoPow)
	}
	return newPainlessBigInteger(mag)
}

func (bi *painlessBigInteger) String() string {
	if bi == nil || bi.val == nil {
		return "0"
	}
	return bi.val.String()
}

func (bi *painlessBigInteger) MarshalJSON() ([]byte, error) {
	if bi == nil || bi.val == nil {
		return []byte("null"), nil
	}
	return []byte(bi.val.String()), nil
}

func (bi *painlessBigInteger) longValue() int64 {
	if bi == nil || bi.val == nil {
		return 0
	}
	return bigIntToLongValuePainless(bi.val)
}

func (bi *painlessBigInteger) intValue() int64 {
	return int64ToInt32Painless(bi.longValue())
}

func (bi *painlessBigInteger) shortValue() int64 {
	return int64ToInt16Painless(bi.longValue())
}

func (bi *painlessBigInteger) byteValue() int64 {
	return int64ToInt8Painless(bi.longValue())
}

func (bi *painlessBigInteger) float64Value() float64 {
	if bi == nil || bi.val == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(bi.val).Float64()
	return f
}

func (bi *painlessBigInteger) longValueExact() (int64, error) {
	if bi == nil || bi.val == nil {
		return 0, nil
	}
	if !bi.val.IsInt64() {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "BigInteger out of long range"}
	}
	return bi.val.Int64(), nil
}

func (bi *painlessBigInteger) intValueExact() (int64, error) {
	lv, err := bi.longValueExact()
	if err != nil {
		return 0, err
	}
	if lv < math.MinInt32 || lv > math.MaxInt32 {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "BigInteger out of int range"}
	}
	return lv, nil
}

func (bi *painlessBigInteger) shortValueExact() (int64, error) {
	lv, err := bi.longValueExact()
	if err != nil {
		return 0, err
	}
	if lv < math.MinInt16 || lv > math.MaxInt16 {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "BigInteger out of short range"}
	}
	return lv, nil
}

func (bi *painlessBigInteger) byteValueExact() (int64, error) {
	lv, err := bi.longValueExact()
	if err != nil {
		return 0, err
	}
	if lv < math.MinInt8 || lv > math.MaxInt8 {
		return 0, &painlessExceptionError{exType: "ArithmeticException", message: "BigInteger out of byte range"}
	}
	return lv, nil
}

func (bi *painlessBigInteger) bitLength() int64 {
	if bi == nil || bi.val == nil || bi.val.Sign() == 0 {
		return 0
	}
	if bi.val.Sign() > 0 {
		return int64(bi.val.BitLen())
	}
	// Java BigInteger.bitLength() for negative v is bitLength of (~v) = (-v - 1)
	negMinus1 := new(big.Int).Add(bi.val, big.NewInt(1))
	negMinus1.Abs(negMinus1)
	return int64(negMinus1.BitLen())
}

func (bi *painlessBigInteger) bitCount() int64 {
	if bi == nil || bi.val == nil || bi.val.Sign() == 0 {
		return 0
	}
	target := bi.val
	if target.Sign() < 0 {
		// Java BigInteger.bitCount() counts bits that differ from the sign bit, i.e., popcount(~v) = popcount(-v - 1)
		target = new(big.Int).Add(target, big.NewInt(1))
		target.Abs(target)
	}
	var count int64
	for _, b := range target.Bytes() {
		for x := b; x != 0; x &= x - 1 {
			count++
		}
	}
	return count
}

func (bi *painlessBigInteger) getLowestSetBit() int64 {
	if bi == nil || bi.val == nil || bi.val.Sign() == 0 {
		return -1
	}
	return int64(bi.val.TrailingZeroBits()) // #nosec G115 -- bit index fits in int64
}

func (bi *painlessBigInteger) toByteArray() []any {
	if bi == nil || bi.val == nil || bi.val.Sign() == 0 {
		return []any{int64(0)}
	}
	var raw []byte
	if bi.val.Sign() > 0 {
		raw = bi.val.Bytes()
		if len(raw) == 0 || (raw[0]&0x80) != 0 {
			raw = append([]byte{0}, raw...)
		}
	} else {
		bitLen := int(bi.bitLength())
		numBytes := (bitLen / 8) + 1
		twoPow := new(big.Int).Lsh(big.NewInt(1), uint(numBytes*8)) // #nosec G115 -- numBytes > 0
		tc := new(big.Int).Add(twoPow, bi.val)
		raw = tc.Bytes()
		for len(raw) < numBytes {
			raw = append([]byte{0}, raw...)
		}
	}
	out := make([]any, len(raw))
	for i, b := range raw {
		sb := int64(b)
		if sb >= 128 {
			sb -= 256
		}
		out[i] = sb
	}
	return out
}

// painlessTemporalAdjuster represents a java.time.temporal.TemporalAdjuster instance in Painless.
type painlessTemporalAdjuster struct {
	kind    string
	dow     int // 1 (MONDAY) .. 7 (SUNDAY)
	ordinal int
}

func (ta *painlessTemporalAdjuster) String() string {
	if ta == nil {
		return "TemporalAdjuster"
	}
	return fmt.Sprintf("TemporalAdjuster[%s]", ta.kind)
}

// painlessComparator represents a first-class java.util.Comparator in Painless.
type painlessComparator struct {
	kind       string // "natural", "reverse", "caseInsensitive", "comparing", "nullsFirst", "nullsLast", "lambda"
	keyExpr    string
	lambdaExpr string
	keyCmp     *painlessComparator
	inner      *painlessComparator
	reversed   bool
	thenList   []*painlessComparator
}

func (c *painlessComparator) clone() *painlessComparator {
	if c == nil {
		return nil
	}
	cp := *c
	if len(c.thenList) > 0 {
		cp.thenList = make([]*painlessComparator, len(c.thenList))
		copy(cp.thenList, c.thenList)
	}
	return &cp
}

func (c *painlessComparator) cloneReversed() *painlessComparator {
	if c == nil {
		return &painlessComparator{kind: "reverse"}
	}
	if len(c.thenList) > 0 {
		return &painlessComparator{
			kind:     "nullsFirst",
			inner:    c.clone(),
			reversed: true,
		}
	}
	cp := c.clone()
	cp.reversed = !cp.reversed
	return cp
}

func (c *painlessComparator) String() string {
	if c == nil {
		return "Comparator"
	}
	return fmt.Sprintf("Comparator[%s]", c.kind)
}

// painlessBitSet represents a java.util.BitSet in Painless.
type painlessBitSet struct {
	words []uint64
}

func newPainlessBitSet() *painlessBitSet {
	return &painlessBitSet{}
}

func newPainlessBitSetFromValueOf(v any) *painlessBitSet {
	bs := newPainlessBitSet()
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return bs
	}
	// Heuristic: if any element exceeds byte bounds [-128, 255] or fits 64-bit words,
	// determine whether caller passed a byte[] or long[]. In BitSet.valueOf(long[]) vs BitSet.valueOf(byte[]),
	// check if all elements are within signed byte range [-128, 127] and len > 1 with small values, or treat as long[] if any element > 127 or < -128.
	// Wait: in Java, byte[] has elements in [-128, 127], whereas long[] can also have small values like `new long[] { 5L, 10L }`.
	// How can we distinguish `new byte[] { ... }` vs `new long[] { ... }`?
	// Let's check: if `len(arr)` > 0, in `BitSet.valueOf`, we can check the argument expression in `evalStaticCallPainless` or if `v` was a byte array vs long array!
	// By default here, treat `arr` as `long[]` words, and we can also have `newPainlessBitSetFromBytes(raw []byte)`!
	words := make([]uint64, len(arr))
	for i, elem := range arr {
		iv, _ := toInt64Painless(elem)
		words[i] = uint64(iv) // #nosec G115 -- Intentional Java 64-bit word bit pattern
	}
	bs.words = words
	bs.trimWords()
	return bs
}

func (bs *painlessBitSet) clone() *painlessBitSet {
	if bs == nil {
		return newPainlessBitSet()
	}
	words := make([]uint64, len(bs.words))
	copy(words, bs.words)
	return &painlessBitSet{words: words}
}

func (bs *painlessBitSet) trimWords() {
	if bs == nil {
		return
	}
	for len(bs.words) > 0 && bs.words[len(bs.words)-1] == 0 {
		bs.words = bs.words[:len(bs.words)-1]
	}
}

func (bs *painlessBitSet) ensureWord(wordIdx int) {
	if wordIdx >= len(bs.words) {
		newWords := make([]uint64, wordIdx+1)
		copy(newWords, bs.words)
		bs.words = newWords
	}
}

func (bs *painlessBitSet) set(bitIdx int) error {
	return bs.setBit(bitIdx, true)
}

func (bs *painlessBitSet) clearBit(bitIdx int) error {
	return bs.setBit(bitIdx, false)
}

func (bs *painlessBitSet) setBit(bitIdx int, val bool) error {
	if bitIdx < 0 {
		return &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("bitIndex < 0: %d", bitIdx)}
	}
	wordIdx := bitIdx / 64
	mask := uint64(1) << uint(bitIdx%64) // #nosec G115 -- bitIdx >= 0
	if val {
		bs.ensureWord(wordIdx)
		bs.words[wordIdx] |= mask
	} else if wordIdx < len(bs.words) {
		bs.words[wordIdx] &^= mask
		bs.trimWords()
	}
	return nil
}

func (bs *painlessBitSet) setRange(fromIdx, toIdx int, val bool) error {
	if fromIdx < 0 || toIdx < 0 || fromIdx > toIdx {
		return &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex: %d, toIndex: %d", fromIdx, toIdx)}
	}
	if fromIdx == toIdx {
		return nil
	}
	for i := fromIdx; i < toIdx; i++ {
		if err := bs.setBit(i, val); err != nil {
			return err
		}
	}
	return nil
}

func (bs *painlessBitSet) flip(bitIdx int) error {
	return bs.flipBit(bitIdx)
}

func (bs *painlessBitSet) flipBit(bitIdx int) error {
	if bitIdx < 0 {
		return &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("bitIndex < 0: %d", bitIdx)}
	}
	wordIdx := bitIdx / 64
	bs.ensureWord(wordIdx)
	bs.words[wordIdx] ^= uint64(1) << uint(bitIdx%64) // #nosec G115 -- bitIdx >= 0
	bs.trimWords()
	return nil
}

func (bs *painlessBitSet) flipRange(fromIdx, toIdx int) error {
	if fromIdx < 0 || toIdx < 0 || fromIdx > toIdx {
		return &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex: %d, toIndex: %d", fromIdx, toIdx)}
	}
	for i := fromIdx; i < toIdx; i++ {
		if err := bs.flipBit(i); err != nil {
			return err
		}
	}
	return nil
}

func (bs *painlessBitSet) get(bitIdx int) (bool, error) {
	return bs.getBit(bitIdx)
}

func (bs *painlessBitSet) getBit(bitIdx int) (bool, error) {
	if bitIdx < 0 {
		return false, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("bitIndex < 0: %d", bitIdx)}
	}
	wordIdx := bitIdx / 64
	if wordIdx >= len(bs.words) {
		return false, nil
	}
	return (bs.words[wordIdx] & (uint64(1) << uint(bitIdx%64))) != 0, nil // #nosec G115 -- bitIdx >= 0
}

func (bs *painlessBitSet) getRange(fromIdx, toIdx int) (*painlessBitSet, error) {
	if fromIdx < 0 || toIdx < 0 || fromIdx > toIdx {
		return nil, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex: %d, toIndex: %d", fromIdx, toIdx)}
	}
	res := newPainlessBitSet()
	for i := fromIdx; i < toIdx; i++ {
		if b, _ := bs.getBit(i); b {
			_ = res.setBit(i-fromIdx, true)
		}
	}
	return res, nil
}

func (bs *painlessBitSet) nextSetBit(fromIdx int) (int64, error) {
	if fromIdx < 0 {
		return -1, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex < 0: %d", fromIdx)}
	}
	maxBit := len(bs.words) * 64
	for i := fromIdx; i < maxBit; i++ {
		if b, _ := bs.getBit(i); b {
			return int64(i), nil
		}
	}
	return -1, nil
}

func (bs *painlessBitSet) nextClearBit(fromIdx int) (int64, error) {
	if fromIdx < 0 {
		return -1, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex < 0: %d", fromIdx)}
	}
	maxBit := len(bs.words) * 64
	for i := fromIdx; i < maxBit; i++ {
		if b, _ := bs.getBit(i); !b {
			return int64(i), nil
		}
	}
	if fromIdx > maxBit {
		return int64(fromIdx), nil
	}
	return int64(maxBit), nil
}

func (bs *painlessBitSet) previousSetBit(fromIdx int) (int64, error) {
	if fromIdx < 0 {
		if fromIdx == -1 {
			return -1, nil
		}
		return -1, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex < -1: %d", fromIdx)}
	}
	start := fromIdx
	maxBit := len(bs.words)*64 - 1
	if start > maxBit {
		start = maxBit
	}
	for i := start; i >= 0; i-- {
		if b, _ := bs.getBit(i); b {
			return int64(i), nil
		}
	}
	return -1, nil
}

func (bs *painlessBitSet) previousClearBit(fromIdx int) (int64, error) {
	if fromIdx < 0 {
		if fromIdx == -1 {
			return -1, nil
		}
		return -1, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("fromIndex < -1: %d", fromIdx)}
	}
	for i := fromIdx; i >= 0; i-- {
		if b, _ := bs.getBit(i); !b {
			return int64(i), nil
		}
	}
	return -1, nil
}

func (bs *painlessBitSet) cardinality() int64 {
	if bs == nil {
		return 0
	}
	var count int64
	for _, w := range bs.words {
		for x := w; x != 0; x &= x - 1 {
			count++
		}
	}
	return count
}

func (bs *painlessBitSet) length() int64 {
	if bs == nil {
		return 0
	}
	bs.trimWords()
	if len(bs.words) == 0 {
		return 0
	}
	lastIdx := len(bs.words) - 1
	w := bs.words[lastIdx]
	bitPos := 0
	for w > 0 {
		bitPos++
		w >>= 1
	}
	return int64(lastIdx*64 + bitPos)
}

func (bs *painlessBitSet) size() int64 {
	if bs == nil {
		return 0
	}
	return int64(len(bs.words) * 64)
}

func (bs *painlessBitSet) intersects(other *painlessBitSet) bool {
	if bs == nil || other == nil {
		return false
	}
	minW := len(bs.words)
	if len(other.words) < minW {
		minW = len(other.words)
	}
	for i := 0; i < minW; i++ {
		if (bs.words[i] & other.words[i]) != 0 {
			return true
		}
	}
	return false
}

func (bs *painlessBitSet) and(other *painlessBitSet) {
	if bs == nil || other == nil {
		return
	}
	if bs == other {
		return
	}
	for i := range bs.words {
		if i < len(other.words) {
			bs.words[i] &= other.words[i]
		} else {
			bs.words[i] = 0
		}
	}
	bs.trimWords()
}

func (bs *painlessBitSet) or(other *painlessBitSet) {
	if bs == nil || other == nil || bs == other {
		return
	}
	if len(other.words) > len(bs.words) {
		bs.ensureWord(len(other.words) - 1)
	}
	for i := range other.words {
		bs.words[i] |= other.words[i]
	}
	bs.trimWords()
}

func (bs *painlessBitSet) xor(other *painlessBitSet) {
	if bs == nil || other == nil {
		return
	}
	if bs == other {
		bs.words = nil
		return
	}
	if len(other.words) > len(bs.words) {
		bs.ensureWord(len(other.words) - 1)
	}
	for i := range other.words {
		bs.words[i] ^= other.words[i]
	}
	bs.trimWords()
}

func (bs *painlessBitSet) andNot(other *painlessBitSet) {
	if bs == nil || other == nil {
		return
	}
	minW := len(bs.words)
	if len(other.words) < minW {
		minW = len(other.words)
	}
	for i := 0; i < minW; i++ {
		bs.words[i] &^= other.words[i]
	}
	bs.trimWords()
}

func (bs *painlessBitSet) toByteArray() []any {
	if bs == nil {
		return []any{}
	}
	bs.trimWords()
	if len(bs.words) == 0 {
		return []any{}
	}
	var raw []byte
	for _, w := range bs.words {
		for b := 0; b < 8; b++ {
			raw = append(raw, byte((w>>uint(b*8))&0xFF)) // #nosec G115 -- masked to 8 bits
		}
	}
	for len(raw) > 0 && raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	out := make([]any, len(raw))
	for i, b := range raw {
		sb := int64(b)
		if sb >= 128 {
			sb -= 256
		}
		out[i] = sb
	}
	return out
}

func (bs *painlessBitSet) toLongArray() []any {
	if bs == nil {
		return []any{}
	}
	bs.trimWords()
	out := make([]any, len(bs.words))
	for i, w := range bs.words {
		out[i] = int64(w) // #nosec G115 -- Intentional Java 64-bit signed long bit pattern
	}
	return out
}

func (bs *painlessBitSet) streamSlice() []any {
	if bs == nil {
		return []any{}
	}
	var out []any
	maxBit := len(bs.words) * 64
	for i := 0; i < maxBit; i++ {
		if b, _ := bs.getBit(i); b {
			out = append(out, int64(i))
		}
	}
	if out == nil {
		return []any{}
	}
	return out
}

func (bs *painlessBitSet) equals(other any) bool {
	o, ok := other.(*painlessBitSet)
	if !ok || bs == nil || o == nil {
		return false
	}
	bs.trimWords()
	o.trimWords()
	if len(bs.words) != len(o.words) {
		return false
	}
	for i := range bs.words {
		if bs.words[i] != o.words[i] {
			return false
		}
	}
	return true
}

func (bs *painlessBitSet) String() string {
	if bs == nil {
		return "{}"
	}
	var parts []string
	maxBit := len(bs.words) * 64
	for i := 0; i < maxBit; i++ {
		if b, _ := bs.getBit(i); b {
			parts = append(parts, strconv.Itoa(i))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// painlessStringJoiner represents a java.util.StringJoiner in Painless.
type painlessStringJoiner struct {
	delim    string
	prefix   string
	suffix   string
	parts    []string
	emptyVal *string
	hasValue bool
}

func (sj *painlessStringJoiner) length() int64 {
	if sj == nil {
		return 0
	}
	return int64(utf8.RuneCountInString(sj.String()))
}

func (sj *painlessStringJoiner) String() string {
	if sj == nil {
		return ""
	}
	if !sj.hasValue && len(sj.parts) == 0 {
		if sj.emptyVal != nil {
			return *sj.emptyVal
		}
		return sj.prefix + sj.suffix
	}
	return sj.prefix + strings.Join(sj.parts, sj.delim) + sj.suffix
}

// painlessUserField represents a field declaration in a user-defined Painless class.
type painlessUserField struct {
	name     string
	typeName string
	initExpr string
}

// painlessUserClass represents a user-defined class (`class Foo { ... }`) in Painless.
type painlessUserClass struct {
	name         string
	fields       []painlessUserField
	constructors []*painlessUserFunc
	methods      map[string][]*painlessUserFunc
}

// painlessUserObject represents an instantiated user-defined class object in Painless.
type painlessUserObject struct {
	class  *painlessUserClass
	fields map[string]any
}

func (uo *painlessUserObject) String() string {
	if uo == nil || uo.class == nil {
		return "Object"
	}
	return fmt.Sprintf("%s@%p", uo.class.name, uo)
}

// UpdateRequest models an Elasticsearch `/_update/<id>` or `/_update_by_query` mutation spec.
type UpdateRequest struct {
	Doc                map[string]any `json:"doc,omitempty"`
	DocAsUpsert        bool           `json:"doc_as_upsert,omitempty"`
	DetectNoop         *bool          `json:"detect_noop,omitempty"`
	Upsert             map[string]any `json:"upsert,omitempty"`
	ScriptedUpsert     bool           `json:"scripted_upsert,omitempty"`
	Script             *ScriptSpec    `json:"script,omitempty"`
	MetaID             string         `json:"-"`
	MetaIndex          string         `json:"-"`
	MetaRouting        string         `json:"-"`
	MetaVersion        int64          `json:"-"`
	MetaVersionNil     bool           `json:"-"`
	MetaVersionMutated bool           `json:"-"`
	MetaOp             string         `json:"-"`
	AllowMetaMutation  bool           `json:"-"`
}

type ScriptSpec struct {
	Source string         `json:"source"`
	Lang   string         `json:"lang,omitempty"`
	Params map[string]any `json:"params,omitempty"`
}

var (
	reCtxOp                = regexp.MustCompile(`(?s)^ctx\??\.op\s*=\s*(.+)$`)
	reCtxIncDec            = regexp.MustCompile(`^(?:(\+\+|--)\s*ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)|ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*(\+\+|--))$`)
	reCompoundAssign       = regexp.MustCompile(`(?s)^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>>=|>>=)\s*(.+)$`)
	reAssignParam          = regexp.MustCompile(`(?s)^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*=\s*(.+)$`)
	reRemoveField          = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.remove\(\s*(.+?)\s*\)$`)
	reClearField           = regexp.MustCompile(`^ctx\??(?:\._source\??)?(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.clear\(\s*\)$`)
	reArrayAdd             = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.add\(\s*(.+?)\s*\)$`)
	reArraySet             = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.set\(\s*(.+)\s*\)$`)
	reArrayAddAll          = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.addAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveAll       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.removeAll\(\s*(.+?)\s*\)$`)
	reArrayRetainAll       = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.retainAll\(\s*(.+?)\s*\)$`)
	reMapPut               = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.put\(\s*(.+)\s*\)$`)
	reMapPutAll            = regexp.MustCompile(`^ctx\??\._source\??(?:\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+))?\.putAll\(\s*(.+?)\s*\)$`)
	reArrayRemoveIf        = regexp.MustCompile(`^ctx\??\._source\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\.removeIf\(\s*\(?\s*(?:[a-zA-Z_$][a-zA-Z0-9_$<>[\]]*\s+)?([a-zA-Z0-9_$]+)\s*\)?\s*->\s*(.+)\s*\)$`)
	reLocalIncDec          = regexp.MustCompile(`^(?:(\+\+|--)\s*([a-zA-Z_$][a-zA-Z0-9_$]*\??(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)|([a-zA-Z_$][a-zA-Z0-9_$]*\??(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\s*(\+\+|--))$`)
	reLocalRemoveField     = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.remove\(\s*(.+?)\s*\)$`)
	reLocalClearField      = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.clear\(\s*\)$`)
	reLocalArrayAdd        = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.add\(\s*(.+?)\s*\)$`)
	reLocalArraySet        = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.set\(\s*(.+)\s*\)$`)
	reLocalArrayAddAll     = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.addAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveAll  = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.removeAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRetainAll  = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.retainAll\(\s*(.+?)\s*\)$`)
	reLocalMapPut          = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.put\(\s*(.+)\s*\)$`)
	reLocalMapPutAll       = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.putAll\(\s*(.+?)\s*\)$`)
	reLocalArrayRemoveIf   = regexp.MustCompile(`^([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\.removeIf\(\s*\(?\s*(?:[a-zA-Z_$][a-zA-Z0-9_$<>[\]]*\s+)?([a-zA-Z0-9_$]+)\s*\)?\s*->\s*(.+)\s*\)$`)
	reLocalCompoundAssign  = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*\??(?:\.[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)*)\s*(\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>>=|>>=)\s*(.+)$`)
	reLocalPropAssign      = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*)\??\.([a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+)\s*=\s*(.+)$`)
	reLocalVarAssign       = regexp.MustCompile(`(?s)^(?:(?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|CharSequence|Object|Map\.Entry|Map|HashMap|LinkedHashMap|TreeMap|NavigableMap|SortedMap|List|ArrayList|LinkedList|Set|HashSet|LinkedHashSet|TreeSet|NavigableSet|SortedSet|Deque|ArrayDeque|Queue|PriorityQueue|Collection|ZonedDateTime|OffsetDateTime|Instant|LocalDateTime|LocalDate|(?:java\.time\.)?LocalTime|(?:java\.math\.)?BigDecimal|(?:java\.math\.)?BigInteger|(?:java\.math\.)?MathContext|(?:java\.math\.)?RoundingMode|YearMonth|(?:java\.time\.)?Year|(?:java\.time\.)?MonthDay|(?:java\.time\.temporal\.)?ChronoField|(?:java\.time\.temporal\.)?TemporalAdjuster|(?:java\.time\.temporal\.)?TemporalAdjusters|DayOfWeek|Month|DateTimeFormatter|Duration|Period|ChronoUnit|ZoneId|ZoneOffset|Pattern|Matcher|StringBuilder|StringBuffer|(?:java\.lang\.)?Class|(?:java\.util\.)?UUID|(?:java\.util\.)?HexFormat|(?:java\.util\.)?Comparator|(?:java\.util\.)?BitSet|(?:java\.util\.)?StringJoiner|Optional|OptionalInt|OptionalLong|OptionalDouble|Stream|IntStream|LongStream|DoubleStream|Charset|IntSummaryStatistics|LongSummaryStatistics|DoubleSummaryStatistics)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)$`)
	reNullVarDecl          = regexp.MustCompile(`^(?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|CharSequence|Object|Map\.Entry|Map|HashMap|LinkedHashMap|TreeMap|NavigableMap|SortedMap|List|ArrayList|LinkedList|Set|HashSet|LinkedHashSet|TreeSet|NavigableSet|SortedSet|Deque|ArrayDeque|Queue|PriorityQueue|Collection|ZonedDateTime|OffsetDateTime|Instant|LocalDateTime|LocalDate|(?:java\.time\.)?LocalTime|(?:java\.math\.)?BigDecimal|(?:java\.math\.)?BigInteger|(?:java\.math\.)?MathContext|(?:java\.math\.)?RoundingMode|YearMonth|(?:java\.time\.)?Year|(?:java\.time\.)?MonthDay|(?:java\.time\.temporal\.)?ChronoField|(?:java\.time\.temporal\.)?TemporalAdjuster|(?:java\.time\.temporal\.)?TemporalAdjusters|DayOfWeek|Month|DateTimeFormatter|Duration|Period|ChronoUnit|ZoneId|ZoneOffset|Pattern|Matcher|StringBuilder|StringBuffer|(?:java\.lang\.)?Class|(?:java\.util\.)?UUID|(?:java\.util\.)?HexFormat|(?:java\.util\.)?Comparator|(?:java\.util\.)?BitSet|(?:java\.util\.)?StringJoiner|Optional|OptionalInt|OptionalLong|OptionalDouble|Stream|IntStream|LongStream|DoubleStream|Charset|IntSummaryStatistics|LongSummaryStatistics|DoubleSummaryStatistics)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*\s+([a-zA-Z_$][a-zA-Z0-9_$]*)$`)
	reVarTypeDeclPrefix    = regexp.MustCompile(`(?s)^((?:def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|CharSequence|Object|Map\.Entry|Map|HashMap|LinkedHashMap|TreeMap|NavigableMap|SortedMap|List|ArrayList|LinkedList|Set|HashSet|LinkedHashSet|TreeSet|NavigableSet|SortedSet|Deque|ArrayDeque|Queue|PriorityQueue|Collection|ZonedDateTime|OffsetDateTime|Instant|LocalDateTime|LocalDate|(?:java\.time\.)?LocalTime|(?:java\.math\.)?BigDecimal|(?:java\.math\.)?BigInteger|(?:java\.math\.)?MathContext|(?:java\.math\.)?RoundingMode|YearMonth|(?:java\.time\.)?Year|(?:java\.time\.)?MonthDay|(?:java\.time\.temporal\.)?ChronoField|(?:java\.time\.temporal\.)?TemporalAdjuster|(?:java\.time\.temporal\.)?TemporalAdjusters|DayOfWeek|Month|DateTimeFormatter|Duration|Period|ChronoUnit|ZoneId|ZoneOffset|Pattern|Matcher|StringBuilder|StringBuffer|(?:java\.lang\.)?Class|(?:java\.util\.)?UUID|(?:java\.util\.)?HexFormat|(?:java\.util\.)?Comparator|(?:java\.util\.)?BitSet|(?:java\.util\.)?StringJoiner|Optional|OptionalInt|OptionalLong|OptionalDouble|Stream|IntStream|LongStream|DoubleStream|Charset|IntSummaryStatistics|LongSummaryStatistics|DoubleSummaryStatistics)(?:\s*<[^=;]*>)?(?:\s*\[\s*\])*)\s+(.+)$`)
	reUserFuncHeaderPrefix = regexp.MustCompile(`^(void|def|boolean|Boolean|int|Integer|long|Long|double|Double|float|Float|Number|Short|short|Byte|byte|Character|char|String|CharSequence|Object|Map\.Entry|Map|HashMap|LinkedHashMap|TreeMap|NavigableMap|SortedMap|List|ArrayList|LinkedList|Set|HashSet|LinkedHashSet|TreeSet|NavigableSet|SortedSet|Deque|ArrayDeque|Queue|PriorityQueue|Collection|ZonedDateTime|OffsetDateTime|Instant|LocalDateTime|LocalDate|(?:java\.time\.)?LocalTime|(?:java\.math\.)?BigDecimal|(?:java\.math\.)?BigInteger|(?:java\.math\.)?MathContext|(?:java\.math\.)?RoundingMode|YearMonth|(?:java\.time\.)?Year|(?:java\.time\.)?MonthDay|(?:java\.time\.temporal\.)?ChronoField|(?:java\.time\.temporal\.)?TemporalAdjuster|(?:java\.time\.temporal\.)?TemporalAdjusters|DayOfWeek|Month|DateTimeFormatter|Duration|Period|ChronoUnit|ZoneId|ZoneOffset|Pattern|Matcher|StringBuilder|StringBuffer|(?:java\.lang\.)?Class|(?:java\.util\.)?UUID|(?:java\.util\.)?HexFormat|(?:java\.util\.)?Comparator|(?:java\.util\.)?BitSet|(?:java\.util\.)?StringJoiner|Optional|OptionalInt|OptionalLong|OptionalDouble|Stream|IntStream|LongStream|DoubleStream|Charset|IntSummaryStatistics|LongSummaryStatistics|DoubleSummaryStatistics|[a-zA-Z_$][a-zA-Z0-9_$]*)(?:\s*<[^>]*>)?(?:\s*\[\s*\])*\s+([a-zA-Z_$][a-zA-Z0-9_$]*)$`)
	reIdentAssign          = regexp.MustCompile(`(?s)^([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)$`)
	reIdentOnly            = regexp.MustCompile(`^[a-zA-Z_$][a-zA-Z0-9_$]*$`)
	reSimpleFieldPath      = regexp.MustCompile(`^[a-zA-Z0-9_$_.@/:?\x00-\x08\x10-\x1f\x7f-]+$`)
	reNumericLiteralSuffix = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?[lLdDfF]$`)
)

// ApplyUpdate applies either a partial `doc` deep merge or an embedded Painless `script`
// against a raw `_source` JSON payload and returns the mutated `_source` JSON bytes.
func ApplyUpdate(rawSource json.RawMessage, req *UpdateRequest) (json.RawMessage, error) {
	updated, _, err := ApplyUpdateWithResult(rawSource, req, len(bytes.TrimSpace(rawSource)) > 0)
	return updated, err
}

// ApplyUpdateWithResult applies an `UpdateRequest` and returns `(updatedSource, opResult, error)`
// where `opResult` is `"updated"`, `"created"`, `"noop"`, or `"deleted"`.
func ApplyUpdateWithResult(rawSource json.RawMessage, req *UpdateRequest, docExisted bool) (json.RawMessage, string, error) {
	var doc map[string]any
	trimmed := bytes.TrimSpace(rawSource)
	if len(trimmed) > 0 {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal _source for update: %w", err)
		}
	}
	if doc == nil {
		doc = make(map[string]any)
	}

	if !docExisted {
		if req.Upsert != nil {
			deepMergeMap(doc, req.Upsert)
			if !req.ScriptedUpsert {
				out, err := json.Marshal(doc)
				return json.RawMessage(out), "created", err
			}
		} else if req.DocAsUpsert && req.Doc != nil {
			deepMergeMap(doc, req.Doc)
			if !req.ScriptedUpsert {
				out, err := json.Marshal(doc)
				return json.RawMessage(out), "created", err
			}
		}
	}

	detectNoop := req.DetectNoop == nil || *req.DetectNoop
	var preMergeSnapshot []byte
	if docExisted && detectNoop && req.Doc != nil && (req.Script == nil || strings.TrimSpace(req.Script.Source) == "") {
		preMergeSnapshot, _ = json.Marshal(doc)
	}

	if len(req.Doc) > 0 && (docExisted || (!req.ScriptedUpsert && !req.DocAsUpsert)) {
		deepMergeMap(doc, req.Doc)
	}

	opResult := "updated"
	if !docExisted {
		opResult = "created"
	}

	if req.Script != nil && strings.TrimSpace(req.Script.Source) != "" {
		scriptParams := make(map[string]any, len(req.Script.Params)+5)
		for k, v := range req.Script.Params {
			scriptParams[k] = v
		}
		if req.MetaID != "" {
			scriptParams["_ctx_id"] = req.MetaID
		}
		if req.MetaIndex != "" {
			scriptParams["_ctx_index"] = req.MetaIndex
		}
		if req.MetaRouting != "" {
			scriptParams["_ctx_routing"] = req.MetaRouting
		}
		if req.MetaVersion != 0 {
			scriptParams["_ctx_version"] = req.MetaVersion
		}
		if req.MetaOp != "" {
			scriptParams["_ctx_op"] = req.MetaOp
		} else if !docExisted {
			scriptParams["_ctx_op"] = "create"
		} else {
			scriptParams["_ctx_op"] = "index"
		}
		if !req.AllowMetaMutation {
			scriptParams["__readonly_ctx_meta"] = true
		}
		ctxOp, err := EvalPainlessWithOp(doc, req.Script.Source, scriptParams)
		if err != nil {
			return nil, "", err
		}
		if ctxOp != "" {
			req.MetaOp = ctxOp
		}
		if v, exists := scriptParams["_ctx_routing"]; exists {
			if v == nil {
				req.MetaRouting = ""
			} else {
				req.MetaRouting = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		if req.AllowMetaMutation {
			if v, exists := scriptParams["_ctx_id"]; exists {
				if v == nil {
					req.MetaID = ""
				} else {
					req.MetaID = strings.TrimSpace(fmt.Sprintf("%v", v))
				}
			}
			if v, exists := scriptParams["_ctx_index"]; exists {
				if v == nil {
					req.MetaIndex = ""
				} else if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
					req.MetaIndex = s
				}
			}
			if v, exists := scriptParams["_ctx_version"]; exists {
				if v == nil {
					req.MetaVersion = 0
					req.MetaVersionNil = true
				} else if vf, ok := toFloat64(v); ok {
					req.MetaVersion = int64(vf)
					req.MetaVersionNil = false
				}
			}
			if mut, ok := scriptParams["_ctx_version_mutated"].(bool); ok && mut {
				req.MetaVersionMutated = true
			}
		}
		switch strings.ToLower(ctxOp) {
		case "", "index", "update":
		case "noop", "none":
			return rawSource, "noop", nil
		case "delete", "drop":
			opResult = "deleted"
		case "create":
			opResult = "created"
		default:
			return nil, "", fmt.Errorf("illegal_argument_exception: Operation [%s] is not supported, only [index, create, update, delete, noop, none] are allowed", ctxOp)
		}
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	if len(preMergeSnapshot) > 0 && jsonBytesSemanticallyEqual(preMergeSnapshot, out) {
		return rawSource, "noop", nil
	}
	return json.RawMessage(out), opResult, nil
}

func jsonBytesSemanticallyEqual(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

const (
	MaxPainlessSteps       = 10_000
	MaxPainlessDepth       = 32
	MaxPainlessSliceItems  = 10_000
	MaxPainlessStringBytes = MaxPainlessSliceItems * 100
)

type painlessUserFunc struct {
	name       string
	returnType string
	paramNames []string
	body       string
}

type painlessMatcher struct {
	re          *regexp.Regexp
	input       string
	curPos      int
	lastMatch   []int
	appendPos   int
	regionStart int
	regionEnd   int
	hasRegion   bool
}

type evalBudget struct {
	steps         int
	depth         int
	nowMillis     int64
	ctxOp         string
	hasCtxOp      bool
	ctxID         any
	hasCtxID      bool
	ctxIndex      any
	hasCtxIndex   bool
	ctxRouting    any
	hasCtxRouting bool
	ctxVersion    any
	hasCtxVersion bool
	emittedVals   []any
	userFuncs     map[string]*painlessUserFunc
	userClasses   map[string]*painlessUserClass
}

func latchCtxMetaOnBudget(budget *evalBudget, path []string, val any) {
	if budget == nil || len(path) != 1 {
		return
	}
	switch path[0] {
	case "_ctx_id":
		budget.ctxID = val
		budget.hasCtxID = true
	case "_ctx_index":
		budget.ctxIndex = val
		budget.hasCtxIndex = true
	case "_ctx_routing":
		budget.ctxRouting = val
		budget.hasCtxRouting = true
	case "_ctx_version":
		budget.ctxVersion = val
		budget.hasCtxVersion = true
	case "_ctx_op":
		if val == nil {
			budget.ctxOp = ""
		} else {
			budget.ctxOp = fmt.Sprintf("%v", val)
		}
		budget.hasCtxOp = true
	}
}

func isInternalPainlessMapKey(m map[string]any, k string) bool {
	if strings.HasPrefix(k, "__") {
		return true
	}
	switch k {
	case "_source", "_ingest", "_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_version_mutated", "_ctx_op", "_ctx_now", "_now", "_return_val", "_last_expr_val", "__raw_source":
		return true
	}
	if m != nil {
		if ep, ok := m["__explicit_params_keys"].(map[string]bool); ok {
			return !ep[k]
		}
		if sl, ok := m["__script_locals"].(map[string]bool); ok && sl[k] {
			return true
		}
		if ld, ok := m["__loop_declared"].(map[string]bool); ok && ld[k] {
			return true
		}
	}
	return false
}

func rawSourceFromSourceMapPainless(sourceMap map[string]any) (map[string]any, bool) {
	if sourceMap == nil {
		return nil, false
	}
	if rawSrc, ok := sourceMap["__raw_source"].(map[string]any); ok && rawSrc != nil {
		return rawSrc, true
	}
	return nil, false
}

func visiblePainlessMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if isInternalPainlessMapKey(m, k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if m != nil && m["__descending"] == true {
		for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
			keys[i], keys[j] = keys[j], keys[i]
		}
	}
	return keys
}

func visiblePainlessMapLen(m map[string]any) int {
	n := 0
	for k := range m {
		if !isInternalPainlessMapKey(m, k) {
			n++
		}
	}
	return n
}

func markExplicitParamsKey(params map[string]any, key string) {
	if params == nil || key == "" {
		return
	}
	if sl, ok := params["__script_locals"].(map[string]bool); ok {
		delete(sl, key)
	}
	if ld, ok := params["__loop_declared"].(map[string]bool); ok {
		delete(ld, key)
	}
	if ep, ok := params["__explicit_params_keys"].(map[string]bool); ok {
		ep[key] = true
	} else {
		params["__explicit_params_keys"] = map[string]bool{key: true}
	}
}

func unmarkExplicitParamsKey(params map[string]any, key string) {
	if params == nil || key == "" {
		return
	}
	if ep, ok := params["__explicit_params_keys"].(map[string]bool); ok {
		delete(ep, key)
	}
}

func isPainlessReservedKeyword(w string) bool {
	switch w {
	case "if", "else", "for", "while", "do", "switch", "case", "default", "try", "catch", "finally", "return", "break", "continue", "throw", "new", "class", "instanceof":
		return true
	}
	return false
}

func parseParamListNamesPainless(paramStr string) []string {
	paramStr = strings.TrimSpace(paramStr)
	if paramStr == "" {
		return nil
	}
	var paramNames []string
	for _, p := range splitTopLevelCommaPainless(paramStr) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if closeIdx := strings.LastIndexAny(p, ">]"); closeIdx >= 0 && closeIdx+1 < len(p) {
			p = strings.TrimSpace(p[closeIdx+1:])
		}
		fields := strings.Fields(p)
		if len(fields) > 0 {
			paramNames = append(paramNames, fields[len(fields)-1])
		}
	}
	return paramNames
}

func parseUserClassDecl(stmt string) (*painlessUserClass, bool) {
	t := strings.TrimSpace(stmt)
	if !strings.HasPrefix(t, "class ") && !strings.HasPrefix(t, "class\t") && !strings.HasPrefix(t, "class\n") {
		return nil, false
	}
	rest := strings.TrimSpace(t[len("class"):])
	openBrace := strings.IndexByte(rest, '{')
	if openBrace <= 0 {
		return nil, false
	}
	className := strings.TrimSpace(rest[:openBrace])
	if !reIdentOnly.MatchString(className) || isPainlessReservedKeyword(className) {
		return nil, false
	}
	bodyPart := strings.TrimSpace(rest[openBrace:])
	if !strings.HasPrefix(bodyPart, "{") || findMatchingDelimiter(bodyPart, 0, '{', '}') != len(bodyPart)-1 {
		return nil, false
	}
	classBody := strings.TrimSpace(bodyPart[1 : len(bodyPart)-1])
	cls := &painlessUserClass{
		name:    className,
		methods: make(map[string][]*painlessUserFunc),
	}
	memberStmts := splitTopLevelStatements(classBody)
	for _, mStmt := range memberStmts {
		mStmt = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(mStmt), ";"))
		if mStmt == "" {
			continue
		}
		// Check constructor: <ClassName>(...) { ... }
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
		if fnDecl, ok := parseUserFuncDecl(mStmt); ok {
			cls.methods[fnDecl.name] = append(cls.methods[fnDecl.name], fnDecl)
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
			if idx == 0 {
				lastSpace := strings.LastIndexAny(declPart, " \t\n\r>]")
				if lastSpace > 0 {
					if declPart[lastSpace] == '>' || declPart[lastSpace] == ']' {
						sharedType = strings.TrimSpace(declPart[:lastSpace+1])
						fieldName := strings.TrimSpace(declPart[lastSpace+1:])
						if reIdentOnly.MatchString(fieldName) {
							cls.fields = append(cls.fields, painlessUserField{
								name:     fieldName,
								typeName: sharedType,
								initExpr: initExpr,
							})
						}
					} else {
						sharedType = strings.TrimSpace(declPart[:lastSpace])
						fieldName := strings.TrimSpace(declPart[lastSpace+1:])
						if reIdentOnly.MatchString(fieldName) {
							cls.fields = append(cls.fields, painlessUserField{
								name:     fieldName,
								typeName: sharedType,
								initExpr: initExpr,
							})
						}
					}
				}
			} else if reIdentOnly.MatchString(declPart) && sharedType != "" {
				cls.fields = append(cls.fields, painlessUserField{
					name:     declPart,
					typeName: sharedType,
					initExpr: initExpr,
				})
			}
		}
	}
	return cls, true
}

func parseUserFuncDecl(stmt string) (*painlessUserFunc, bool) {
	t := strings.TrimSpace(stmt)
	openP := strings.IndexByte(t, '(')
	if openP <= 0 {
		return nil, false
	}
	headerPrefix := strings.TrimSpace(t[:openP])
	m := reUserFuncHeaderPrefix.FindStringSubmatch(headerPrefix)
	if m == nil {
		return nil, false
	}
	if isPainlessReservedKeyword(m[1]) || isPainlessReservedKeyword(m[2]) {
		return nil, false
	}
	closeP := findMatchingDelimiter(t, openP, '(', ')')
	if closeP < 0 {
		return nil, false
	}
	rest := strings.TrimSpace(t[closeP+1:])
	if !strings.HasPrefix(rest, "{") || findMatchingDelimiter(rest, 0, '{', '}') != len(rest)-1 {
		return nil, false
	}
	paramNames := parseParamListNamesPainless(t[openP+1 : closeP])
	return &painlessUserFunc{
		name:       m[2],
		returnType: m[1],
		paramNames: paramNames,
		body:       strings.TrimSpace(rest[1 : len(rest)-1]),
	}, true
}

func (b *evalBudget) step() error {
	b.steps++
	if b.steps > MaxPainlessSteps {
		return fmt.Errorf("painless script exceeded maximum step budget (%d)", MaxPainlessSteps)
	}
	return nil
}

func newEvalBudget(params map[string]any) *evalBudget {
	nowMillis := time.Now().UTC().UnixMilli()
	if params != nil {
		if v, ok := params["_ctx_now"]; ok && v != nil {
			if f, fOk := toFloat64(v); fOk && f > 0 {
				nowMillis = int64(f)
			}
		} else if v, ok := params["_now"]; ok && v != nil {
			if f, fOk := toFloat64(v); fOk && f > 0 {
				nowMillis = int64(f)
			}
		}
	}
	return &evalBudget{nowMillis: nowMillis}
}

func getOrInitEvalBudget(params map[string]any) *evalBudget {
	if params != nil {
		if b, ok := params["__eval_budget"].(*evalBudget); ok && b != nil {
			if b.nowMillis == 0 {
				b.nowMillis = newEvalBudget(params).nowMillis
			}
			return b
		}
		b := newEvalBudget(params)
		params["__eval_budget"] = b
		return b
	}
	return newEvalBudget(nil)
}

// Eval evaluates a Painless script expression or multi-statement block and returns its result value.
func Eval(sourceMap map[string]any, scriptSource string, params map[string]any) (any, error) {
	evalParams := make(map[string]any, len(params)+4)
	explicitParams := make(map[string]bool, len(params))
	for k, v := range params {
		evalParams[k] = v
		if !isInternalPainlessMapKey(nil, k) {
			explicitParams[k] = true
		}
	}
	evalParams["__script_locals"] = make(map[string]bool)
	evalParams["__explicit_params_keys"] = explicitParams
	if sourceMap != nil && evalParams["_source"] == nil {
		if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok {
			evalParams["_source"] = rawSrc
		} else {
			evalParams["_source"] = sourceMap
		}
	}
	cleaned := strings.TrimSpace(stripPainlessComments(scriptSource))
	if cleaned == "" {
		return nil, nil
	}
	ctxOp := ""
	budget := newEvalBudget(evalParams)
	evalParams["__eval_budget"] = budget
	stmts := splitTopLevelStatements(cleaned)
	err := execBlock(sourceMap, cleaned, evalParams, &ctxOp, budget)
	if budget.hasCtxOp {
		evalParams["_ctx_op"] = budget.ctxOp
	} else if ctxOp != "" {
		evalParams["_ctx_op"] = ctxOp
	}
	if budget.hasCtxID {
		evalParams["_ctx_id"] = budget.ctxID
	}
	if budget.hasCtxIndex {
		evalParams["_ctx_index"] = budget.ctxIndex
	}
	if budget.hasCtxRouting {
		evalParams["_ctx_routing"] = budget.ctxRouting
	}
	if budget.hasCtxVersion {
		evalParams["_ctx_version"] = budget.ctxVersion
	}
	if params != nil {
		for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_op"} {
			if v, exists := evalParams[metaKey]; exists {
				params[metaKey] = v
			}
		}
	}
	if err != nil && !errors.Is(err, errPainlessReturn) {
		return nil, err
	}
	if len(budget.emittedVals) > 0 {
		if params != nil {
			params["__emitted_vals"] = budget.emittedVals
		}
		if _, hasRet := evalParams["_return_val"]; !hasRet {
			if len(budget.emittedVals) == 1 {
				return unwrapEmptyOptionalPainless(budget.emittedVals[0]), nil
			}
			return unwrapEmptyOptionalPainless(budget.emittedVals), nil
		}
	}
	if retVal, hasRet := evalParams["_return_val"]; hasRet {
		if params != nil {
			params["__had_explicit_return"] = true
		}
		return unwrapEmptyOptionalPainless(retVal), nil
	}
	if len(stmts) > 0 {
		lastStmt := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmts[len(stmts)-1]), ";"))
		hasExplicitReturn := false
		if strings.HasPrefix(lastStmt, "return ") || strings.HasPrefix(lastStmt, "return(") {
			lastStmt = strings.TrimSpace(strings.TrimPrefix(lastStmt, "return"))
			hasExplicitReturn = true
			if params != nil {
				params["__had_explicit_return"] = true
			}
		}
		if lastStmt != "" && lastStmt != "return" && !strings.HasPrefix(lastStmt, "if ") && !strings.HasPrefix(lastStmt, "if(") && !strings.HasPrefix(lastStmt, "for ") && !strings.HasPrefix(lastStmt, "for(") && !strings.HasPrefix(lastStmt, "while ") && !strings.HasPrefix(lastStmt, "while(") && !strings.HasPrefix(lastStmt, "switch ") && !strings.HasPrefix(lastStmt, "switch(") && !strings.HasPrefix(lastStmt, "try ") && !strings.HasPrefix(lastStmt, "try{") && !strings.HasPrefix(lastStmt, "do ") && !strings.HasPrefix(lastStmt, "do{") && !strings.HasPrefix(lastStmt, "throw ") {
			isAggStateMutation := !hasExplicitReturn && isTopLevelAssignmentStmt(lastStmt) &&
				(strings.HasPrefix(lastStmt, "_agg.") || strings.HasPrefix(lastStmt, "_agg[") ||
					strings.HasPrefix(lastStmt, "state.") || strings.HasPrefix(lastStmt, "state[") ||
					strings.HasPrefix(lastStmt, "params._agg.") || strings.HasPrefix(lastStmt, "params._agg[") ||
					strings.HasPrefix(lastStmt, "params.state.") || strings.HasPrefix(lastStmt, "params.state[") ||
					strings.HasPrefix(lastStmt, "params?._agg.") || strings.HasPrefix(lastStmt, "params?._agg[") ||
					strings.HasPrefix(lastStmt, "params?.state.") || strings.HasPrefix(lastStmt, "params?.state["))
			if !isAggStateMutation {
				if lastVal, hasLast := evalParams["_last_expr_val"]; hasLast {
					return unwrapEmptyOptionalPainless(lastVal), nil
				}
			}
			if !isTopLevelAssignmentStmt(lastStmt) {
				val, evalErr := evalRHSExpr(sourceMap, lastStmt, evalParams)
				if evalErr != nil {
					var pEx *painlessExceptionError
					if errors.As(evalErr, &pEx) {
						return nil, evalErr
					}
				}
				if evalErr == nil && (val != nil || findTopLevelOpPainless(lastStmt, "?") > 0 || findTopLevelOpPainless(lastStmt, "?:") > 0) {
					return unwrapEmptyOptionalPainless(val), nil
				}
				if strings.ContainsAny(lastStmt, "><=!&|") || strings.Contains(lastStmt, ".empty") || strings.Contains(lastStmt, ".contains(") || strings.Contains(lastStmt, ".startsWith(") || strings.Contains(lastStmt, ".endsWith(") || strings.Contains(lastStmt, ".isEmpty()") || strings.Contains(lastStmt, ".matches(") || strings.Contains(lastStmt, ".containsKey(") || strings.Contains(lastStmt, ".equals(") || strings.Contains(lastStmt, ".equalsIgnoreCase(") {
					return evalCondition(sourceMap, lastStmt, evalParams), nil
				}
			}
		}
	}
	return nil, nil
}

func isTopLevelAssignmentStmt(s string) bool {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 {
				if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '~') {
					i++
					continue
				}
				if i > 0 && (s[i-1] == '=' || s[i-1] == '!') {
					continue
				}
				if i > 0 && s[i-1] == '<' && (i < 2 || s[i-2] != '<') {
					continue
				}
				if i > 0 && s[i-1] == '>' && (i < 2 || s[i-2] != '>') {
					continue
				}
				return true
			}
		}
	}
	return false
}

// EvalNumber evaluates a Painless script and coerces the result to float64.
func EvalNumber(sourceMap map[string]any, scriptSource string, params map[string]any) (float64, bool, error) {
	val, err := Eval(sourceMap, scriptSource, params)
	if err != nil || val == nil {
		return 0, false, err
	}
	f, ok := toFloat64(val)
	return f, ok, nil
}

// EvalFilter evaluates a boolean Painless filter script (`script` query or `bucket_selector`).
func EvalFilter(sourceMap map[string]any, scriptSource string, params map[string]any) (bool, error) {
	val, err := Eval(sourceMap, scriptSource, params)
	if err != nil {
		return false, err
	}
	switch v := val.(type) {
	case bool:
		return v, nil
	case nil:
		return false, nil
	default:
		if f, ok := toFloat64(v); ok {
			return f != 0, nil
		}
		return fmt.Sprintf("%v", v) == "true", nil
	}
}

// EvalPainless evaluates common Painless script statements used by OpenMetadata and DataHub
// against `sourceMap` (`ctx._source`) with `params`.
func EvalPainless(sourceMap map[string]any, scriptSource string, params map[string]any) error {
	_, err := EvalPainlessWithOp(sourceMap, scriptSource, params)
	return err
}

// EvalPainlessWithOp evaluates a Painless script and returns any `ctx.op` set by the script.
func EvalPainlessWithOp(sourceMap map[string]any, scriptSource string, params map[string]any) (string, error) {
	origVer, hadOrigVer := params["_ctx_version"]
	evalParams := make(map[string]any, len(params)+6)
	explicitParams := make(map[string]bool, len(params))
	for k, v := range params {
		evalParams[k] = v
		if !isInternalPainlessMapKey(nil, k) {
			explicitParams[k] = true
		}
	}
	evalParams["__script_locals"] = make(map[string]bool)
	evalParams["__explicit_params_keys"] = explicitParams
	if sourceMap != nil {
		if _, exists := evalParams["_source"]; !exists {
			if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok {
				evalParams["_source"] = rawSrc
			} else {
				evalParams["_source"] = sourceMap
			}
		}
	}
	ctxOp := ""
	budget := newEvalBudget(evalParams)
	evalParams["__eval_budget"] = budget
	cleaned := stripPainlessComments(scriptSource)
	err := execBlock(sourceMap, cleaned, evalParams, &ctxOp, budget)
	if errors.Is(err, errPainlessReturn) {
		err = nil
	}
	if budget.hasCtxOp {
		ctxOp = budget.ctxOp
		evalParams["_ctx_op"] = budget.ctxOp
	} else if ctxOp == "" {
		if opStr, ok := evalParams["_ctx_op"].(string); ok && opStr != "" {
			ctxOp = opStr
		}
	} else {
		evalParams["_ctx_op"] = ctxOp
	}
	if budget.hasCtxID {
		evalParams["_ctx_id"] = budget.ctxID
	}
	if budget.hasCtxIndex {
		evalParams["_ctx_index"] = budget.ctxIndex
	}
	if budget.hasCtxRouting {
		evalParams["_ctx_routing"] = budget.ctxRouting
	}
	if budget.hasCtxVersion {
		evalParams["_ctx_version"] = budget.ctxVersion
	}
	if params != nil {
		for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_op"} {
			if v, exists := evalParams[metaKey]; exists {
				params[metaKey] = v
			}
		}
		if budget.hasCtxVersion {
			params["_ctx_version_mutated"] = true
		} else if curV, hasCur := evalParams["_ctx_version"]; hasCur && (!hadOrigVer || !reflect.DeepEqual(curV, origVer)) {
			params["_ctx_version_mutated"] = true
		}
	}
	return ctxOp, err
}

func stripPainlessComments(s string) string {
	if !strings.Contains(s, "//") && !strings.Contains(s, "/*") {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if inQuotes == 0 && s[i] == '/' && i+1 < len(s) {
			if s[i+1] == '/' {
				i += 2
				for i < len(s) && s[i] != '\n' {
					i++
				}
				if i < len(s) {
					out.WriteByte('\n')
				}
				continue
			}
			if s[i+1] == '*' {
				i += 2
				for i+1 < len(s) && (s[i] != '*' || s[i+1] != '/') {
					i++
				}
				i++
				continue
			}
		}
		_ = stepQuoteState(s, i, &inQuotes, &inRegexClass)
		out.WriteByte(s[i])
	}
	return out.String()
}

func execBlock(sourceMap map[string]any, block string, params map[string]any, ctxOp *string, budget *evalBudget) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if pEx, ok := r.(*painlessExceptionError); ok {
				err = pEx
			} else {
				panic(r)
			}
		}
	}()
	if params != nil && budget != nil {
		params["__eval_budget"] = budget
	}
	budget.depth++
	defer func() { budget.depth-- }()
	if budget.depth > MaxPainlessDepth {
		return fmt.Errorf("painless script exceeded maximum recursion depth (%d)", MaxPainlessDepth)
	}

	stmts := splitTopLevelStatements(block)
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if err := budget.step(); err != nil {
			return err
		}
		if loopLabel, strippedStmt, hasLabel := stripLeadingLoopLabelPainless(stmt); hasLabel {
			stmt = strippedStmt
			if params != nil {
				params["__next_loop_label"] = loopLabel
			}
		}
		if strings.HasPrefix(stmt, "if") && (len(stmt) == 2 || stmt[2] == ' ' || stmt[2] == '(') {
			if err := execIfStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "for") && (len(stmt) == 3 || stmt[3] == ' ' || stmt[3] == '(') {
			if err := execForStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "while") && (len(stmt) == 5 || stmt[5] == ' ' || stmt[5] == '(') {
			if err := execWhileStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "do") && (len(stmt) == 2 || stmt[2] == ' ' || stmt[2] == '\t' || stmt[2] == '\n' || stmt[2] == '{') {
			if err := execDoWhileStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "try") && (len(stmt) == 3 || stmt[3] == ' ' || stmt[3] == '\t' || stmt[3] == '\n' || stmt[3] == '{') {
			if err := execTryStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(stmt, "switch") && (len(stmt) == 6 || stmt[6] == ' ' || stmt[6] == '\t' || stmt[6] == '\n' || stmt[6] == '(') {
			if err := execSwitchStatement(sourceMap, stmt, params, ctxOp, budget); err != nil {
				return err
			}
			continue
		}
		if clsDecl, ok := parseUserClassDecl(stmt); ok {
			if budget.userClasses == nil {
				budget.userClasses = make(map[string]*painlessUserClass)
			}
			budget.userClasses[clsDecl.name] = clsDecl
			continue
		}
		if fnDecl, ok := parseUserFuncDecl(stmt); ok {
			if budget.userFuncs == nil {
				budget.userFuncs = make(map[string]*painlessUserFunc)
			}
			budget.userFuncs[fnDecl.name] = fnDecl
			continue
		}
		if err := execSimpleStmt(sourceMap, stmt, params, ctxOp, budget); err != nil {
			return err
		}
	}
	return nil
}

type painlessSwitchClause struct {
	isDefault bool
	isArrow   bool
	hadBraces bool
	caseExprs []string
	body      string
}

func findSwitchLabelEndPainless(s string) (endIdx int, isArrow bool) {
	pDepth := 0
	inQuotes := byte(0)
	inRegexClass := false
	qCount := 0
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			pDepth++
		case ')', ']', '}':
			if pDepth > 0 {
				pDepth--
			}
		case '-':
			if pDepth == 0 && i+1 < len(s) && s[i+1] == '>' {
				return i, true
			}
		case '?':
			if pDepth == 0 {
				if i+1 < len(s) && (s[i+1] == ':' || s[i+1] == '.') {
					i++
					continue
				}
				qCount++
			}
		case ':':
			if pDepth == 0 {
				if i+1 < len(s) && s[i+1] == ':' {
					i++
					continue
				}
				if qCount > 0 {
					qCount--
					continue
				}
				return i, false
			}
		}
	}
	return -1, false
}

func parseSwitchClauses(body string) []painlessSwitchClause {
	type labelSpan struct {
		isDefault  bool
		isArrow    bool
		caseExpr   string
		labelStart int
		labelAfter int
	}
	var spans []labelSpan
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(body); i++ {
		if stepQuoteState(body, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch body[i] {
		case '(', '[', '{':
			depth++
			continue
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if i > 0 && (isIdentByte(body[i-1]) || body[i-1] == '.') {
			continue
		}
		if strings.HasPrefix(body[i:], "case") && len(body) > i+4 && !isIdentByte(body[i+4]) {
			rest := body[i+4:]
			cIdx, isArrow := findSwitchLabelEndPainless(rest)
			if cIdx >= 0 {
				afterIdx := i + 4 + cIdx + 1
				if isArrow {
					afterIdx = i + 4 + cIdx + 2
				}
				spans = append(spans, labelSpan{
					isDefault:  false,
					isArrow:    isArrow,
					caseExpr:   strings.TrimSpace(rest[:cIdx]),
					labelStart: i,
					labelAfter: afterIdx,
				})
				i = afterIdx - 1
				continue
			}
		}
		if strings.HasPrefix(body[i:], "default") && len(body) > i+7 && !isIdentByte(body[i+7]) {
			j := i + 7
			for j < len(body) && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r') {
				j++
			}
			if j < len(body) && body[j] == ':' {
				spans = append(spans, labelSpan{
					isDefault:  true,
					isArrow:    false,
					labelStart: i,
					labelAfter: j + 1,
				})
				i = j
				continue
			}
			if j+1 < len(body) && body[j] == '-' && body[j+1] == '>' {
				spans = append(spans, labelSpan{
					isDefault:  true,
					isArrow:    true,
					labelStart: i,
					labelAfter: j + 2,
				})
				i = j + 1
				continue
			}
		}
	}
	clauses := make([]painlessSwitchClause, 0, len(spans))
	for idx, sp := range spans {
		endIdx := len(body)
		if idx+1 < len(spans) {
			endIdx = spans[idx+1].labelStart
		}
		cBody := strings.TrimSpace(body[sp.labelAfter:endIdx])
		hadBraces := false
		trimmedForBrace := strings.TrimSpace(strings.TrimSuffix(cBody, ";"))
		if strings.HasPrefix(trimmedForBrace, "{") && findMatchingDelimiter(trimmedForBrace, 0, '{', '}') == len(trimmedForBrace)-1 {
			hadBraces = true
			cBody = strings.TrimSpace(trimmedForBrace[1 : len(trimmedForBrace)-1])
		}
		var caseExprs []string
		if !sp.isDefault {
			for _, part := range splitTopLevelCommaPainless(sp.caseExpr) {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					caseExprs = append(caseExprs, trimmed)
				}
			}
		}
		clauses = append(clauses, painlessSwitchClause{
			isDefault: sp.isDefault,
			isArrow:   sp.isArrow,
			hadBraces: hadBraces,
			caseExprs: caseExprs,
			body:      cBody,
		})
	}
	return clauses
}

func matchSwitchClauseIndexPainless(sourceMap map[string]any, switchVal any, clauses []painlessSwitchClause, params map[string]any) (int, error) {
	matchIdx := -1
	defaultIdx := -1
	for idx, cl := range clauses {
		if cl.isDefault {
			if defaultIdx < 0 {
				defaultIdx = idx
			}
			continue
		}
		for _, ce := range cl.caseExprs {
			cVal, cErr := evalRHSExpr(sourceMap, ce, params)
			if cErr != nil {
				return -1, cErr
			}
			if painlessValuesEqual(switchVal, cVal) || valuesEqual(switchVal, cVal) {
				matchIdx = idx
				break
			}
			if f1, ok1 := toFloat64(switchVal); ok1 && switchVal != nil {
				if f2, ok2 := toFloat64(cVal); ok2 && cVal != nil && f1 == f2 {
					matchIdx = idx
					break
				}
			}
		}
		if matchIdx >= 0 {
			break
		}
	}
	if matchIdx < 0 {
		matchIdx = defaultIdx
	}
	return matchIdx, nil
}

func execSwitchStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	switchExpr := strings.TrimSpace(stmt[openParen+1 : closeParen])
	rest := strings.TrimSpace(stmt[closeParen+1:])
	if !strings.HasPrefix(rest, "{") {
		return nil
	}
	closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
	if closeBrace < 0 {
		return nil
	}
	switchVal, err := evalRHSExpr(sourceMap, switchExpr, params)
	if err != nil {
		return err
	}
	clauses := parseSwitchClauses(rest[1:closeBrace])
	if len(clauses) == 0 {
		return nil
	}
	matchIdx, err := matchSwitchClauseIndexPainless(sourceMap, switchVal, clauses, params)
	if err != nil {
		return err
	}
	if matchIdx < 0 {
		return nil
	}
	if clauses[matchIdx].isArrow {
		if clauses[matchIdx].body == "" {
			return nil
		}
		if err := execBlock(sourceMap, clauses[matchIdx].body, params, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) || errors.Is(err, errPainlessYield) {
				return nil
			}
			return err
		}
		return nil
	}
	for i := matchIdx; i < len(clauses); i++ {
		if clauses[i].body == "" {
			continue
		}
		if err := execBlock(sourceMap, clauses[i].body, params, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) || errors.Is(err, errPainlessYield) {
				return nil
			}
			return err
		}
	}
	return nil
}

func evalSwitchExprPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	if !strings.HasPrefix(rhs, "switch ") && !strings.HasPrefix(rhs, "switch(") {
		return nil, false, nil
	}
	openParen := strings.IndexByte(rhs, '(')
	if openParen < 0 {
		return nil, false, nil
	}
	closeParen := findMatchingDelimiter(rhs, openParen, '(', ')')
	if closeParen < 0 {
		return nil, false, nil
	}
	rest := strings.TrimSpace(rhs[closeParen+1:])
	if !strings.HasPrefix(rest, "{") || findMatchingDelimiter(rest, 0, '{', '}') != len(rest)-1 {
		return nil, false, nil
	}
	switchExpr := strings.TrimSpace(rhs[openParen+1 : closeParen])
	switchVal, err := evalRHSExprDepth(sourceMap, switchExpr, params, depth+1)
	if err != nil {
		return nil, true, err
	}
	clauses := parseSwitchClauses(rest[1 : len(rest)-1])
	if len(clauses) == 0 {
		return nil, true, nil
	}
	matchIdx, err := matchSwitchClauseIndexPainless(sourceMap, switchVal, clauses, params)
	if err != nil {
		return nil, true, err
	}
	if matchIdx < 0 {
		return nil, true, nil
	}
	if params == nil {
		params = make(map[string]any)
	}
	prevYield, hadPrevYield := params["__switch_yield_val"]
	delete(params, "__switch_yield_val")
	defer func() {
		if hadPrevYield {
			params["__switch_yield_val"] = prevYield
		} else {
			delete(params, "__switch_yield_val")
		}
	}()
	budget, ok := params["__eval_budget"].(*evalBudget)
	if !ok || budget == nil {
		budget = &evalBudget{}
	}
	cl := clauses[matchIdx]
	if cl.isArrow {
		cBody := strings.TrimSpace(cl.body)
		if !cl.hadBraces {
			exprStr := strings.TrimSpace(strings.TrimSuffix(cBody, ";"))
			if strings.HasPrefix(exprStr, "throw ") || strings.HasPrefix(exprStr, "throw(") {
				if err := execBlock(sourceMap, cBody, params, nil, budget); err != nil {
					return nil, true, err
				}
				return nil, true, nil
			}
			if strings.HasPrefix(exprStr, "yield ") || strings.HasPrefix(exprStr, "yield(") {
				val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(exprStr[5:]), params, depth+1)
				return val, true, err
			}
			val, err := evalRHSExprDepth(sourceMap, exprStr, params, depth+1)
			return val, true, err
		}
		if err := execBlock(sourceMap, cBody, params, nil, budget); err != nil {
			if errors.Is(err, errPainlessYield) || errors.Is(err, errPainlessBreak) {
				return params["__switch_yield_val"], true, nil
			}
			return nil, true, err
		}
		return params["__switch_yield_val"], true, nil
	}
	for i := matchIdx; i < len(clauses); i++ {
		if clauses[i].body == "" {
			continue
		}
		if err := execBlock(sourceMap, clauses[i].body, params, nil, budget); err != nil {
			if errors.Is(err, errPainlessYield) || errors.Is(err, errPainlessBreak) {
				return params["__switch_yield_val"], true, nil
			}
			return nil, true, err
		}
	}
	return params["__switch_yield_val"], true, nil
}

func syncLoopScopeBack(params, loopParams map[string]any, preExistingKeys, excludedVars, loopDeclared map[string]bool) {
	ep, _ := loopParams["__explicit_params_keys"].(map[string]bool)
	for k, v := range loopParams {
		if k == "__loop_declared" {
			continue
		}
		if (((ep != nil && ep[k]) || preExistingKeys[k]) && !excludedVars[k] && !loopDeclared[k]) || k == "_return_val" || k == "_ctx_op" || k == "_ctx_id" || k == "_ctx_index" || k == "_ctx_routing" || k == "_ctx_version" {
			params[k] = v
		} else if strings.HasPrefix(k, "__alias_") {
			baseVar := strings.TrimPrefix(k, "__alias_")
			if preExistingKeys[baseVar] && !excludedVars[baseVar] && !loopDeclared[baseVar] {
				params[k] = v
			}
		}
	}
	for k := range preExistingKeys {
		if k == "__loop_declared" || k == "__script_locals" || k == "__explicit_params_keys" || k == "__eval_budget" || k == "__user_funcs" || k == "__reassigned_vars" {
			continue
		}
		if strings.HasPrefix(k, "__alias_") {
			baseVar := strings.TrimPrefix(k, "__alias_")
			if !excludedVars[baseVar] && !loopDeclared[baseVar] {
				if _, stillExists := loopParams[k]; !stillExists {
					delete(params, k)
				}
			}
			continue
		}
		if !excludedVars[k] && !loopDeclared[k] {
			if _, stillExists := loopParams[k]; !stillExists {
				delete(params, k)
			}
		}
	}
}

func execWhileStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	var myLabel string
	if params != nil {
		myLabel, _ = params["__next_loop_label"].(string)
		delete(params, "__next_loop_label")
	}
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	cond := strings.TrimSpace(stmt[openParen+1 : closeParen])
	body := strings.TrimSpace(stmt[closeParen+1:])
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = body[1 : len(body)-1]
	}
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error
	for {
		if err := budget.step(); err != nil {
			loopErr = err
			break
		}
		if cond != "" && !evalCondition(sourceMap, cond, loopParams) {
			break
		}
		if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) {
				break
			}
			if errors.Is(err, errPainlessContinue) {
				continue
			}
			var lblJump *painlessLabeledJumpError
			if errors.As(err, &lblJump) && myLabel != "" && lblJump.label == myLabel {
				if lblJump.isBreak {
					break
				}
				continue
			}
			loopErr = err
			break
		}
	}
	syncLoopScopeBack(params, loopParams, preExistingKeys, nil, loopDeclared)
	return loopErr
}

func execDoWhileStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	var myLabel string
	if params != nil {
		myLabel, _ = params["__next_loop_label"].(string)
		delete(params, "__next_loop_label")
	}
	rest := strings.TrimSpace(stmt[2:])
	if !strings.HasPrefix(rest, "{") {
		return nil
	}
	closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
	if closeBrace < 0 {
		return nil
	}
	body := rest[1:closeBrace]
	after := strings.TrimSpace(rest[closeBrace+1:])
	if !strings.HasPrefix(after, "while") {
		return nil
	}
	openParen := strings.IndexByte(after, '(')
	closeParen := findMatchingDelimiter(after, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	cond := strings.TrimSpace(after[openParen+1 : closeParen])
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error
	for {
		if err := budget.step(); err != nil {
			loopErr = err
			break
		}
		if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) {
				break
			}
			if !errors.Is(err, errPainlessContinue) {
				var lblJump *painlessLabeledJumpError
				if errors.As(err, &lblJump) && myLabel != "" && lblJump.label == myLabel {
					if lblJump.isBreak {
						break
					}
				} else {
					loopErr = err
					break
				}
			}
		}
		if cond != "" && !evalCondition(sourceMap, cond, loopParams) {
			break
		}
	}
	syncLoopScopeBack(params, loopParams, preExistingKeys, nil, loopDeclared)
	return loopErr
}

type painlessCatchClause struct {
	excTypes []string
	varName  string
	body     string
}

func parseTryStatement(stmt string) (tryBody string, catches []painlessCatchClause, finallyBody string, hasFinally bool, ok bool) {
	rest := strings.TrimSpace(stmt[3:])
	if !strings.HasPrefix(rest, "{") {
		return "", nil, "", false, false
	}
	closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
	if closeBrace < 0 {
		return "", nil, "", false, false
	}
	tryBody = rest[1:closeBrace]
	rem := strings.TrimSpace(rest[closeBrace+1:])
	for rem != "" {
		if strings.HasPrefix(rem, "catch") && (len(rem) == 5 || rem[5] == ' ' || rem[5] == '\t' || rem[5] == '\n' || rem[5] == '(') {
			rem = strings.TrimSpace(rem[5:])
			if !strings.HasPrefix(rem, "(") {
				break
			}
			cp := findMatchingDelimiter(rem, 0, '(', ')')
			if cp < 0 {
				break
			}
			header := strings.TrimSpace(rem[1:cp])
			rem = strings.TrimSpace(rem[cp+1:])
			if !strings.HasPrefix(rem, "{") {
				break
			}
			cb := findMatchingDelimiter(rem, 0, '{', '}')
			if cb < 0 {
				break
			}
			cBody := rem[1:cb]
			rem = strings.TrimSpace(rem[cb+1:])
			var excTypes []string
			varName := "e"
			if header != "" {
				fields := strings.Fields(header)
				if len(fields) == 1 {
					varName = fields[0]
				} else if len(fields) >= 2 {
					varName = fields[len(fields)-1]
					typePart := strings.TrimSpace(header[:strings.LastIndex(header, varName)])
					for _, tp := range strings.Split(typePart, "|") {
						tp = strings.TrimSpace(tp)
						if tp != "" {
							excTypes = append(excTypes, tp)
						}
					}
				}
			}
			catches = append(catches, painlessCatchClause{
				excTypes: excTypes,
				varName:  varName,
				body:     cBody,
			})
			continue
		}
		if strings.HasPrefix(rem, "finally") && (len(rem) == 7 || rem[7] == ' ' || rem[7] == '\t' || rem[7] == '\n' || rem[7] == '{') {
			rem = strings.TrimSpace(rem[7:])
			if strings.HasPrefix(rem, "{") {
				cb := findMatchingDelimiter(rem, 0, '{', '}')
				if cb >= 0 {
					finallyBody = rem[1:cb]
					hasFinally = true
				}
			}
			break
		}
		break
	}
	return tryBody, catches, finallyBody, hasFinally, len(catches) > 0 || hasFinally
}

func matchesCatchException(err error, excTypes []string) bool {
	if len(excTypes) == 0 {
		return true
	}
	var pEx *painlessExceptionError
	errExType := "RuntimeException"
	errMsg := err.Error()
	if errors.As(err, &pEx) && pEx.exType != "" {
		errExType = pEx.exType
	}
	for _, t := range excTypes {
		switch t {
		case "Exception", "RuntimeException", "Throwable", "Object", "def":
			return true
		default:
			if t == errExType || strings.HasSuffix(errExType, "."+t) || strings.Contains(errMsg, t) {
				return true
			}
		}
	}
	return false
}

func isUnrecoverableSandboxError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "exceeded maximum step budget") ||
		strings.Contains(msg, "exceeded maximum recursion depth") ||
		strings.Contains(msg, "exceeded maximum size")
}

func execTryStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	tryBody, catches, finallyBody, hasFinally, ok := parseTryStatement(stmt)
	if !ok {
		return nil
	}
	tryErr := execBlock(sourceMap, tryBody, params, ctxOp, budget)
	if isUnrecoverableSandboxError(tryErr) {
		return tryErr
	}
	if tryErr != nil && !errors.Is(tryErr, errPainlessReturn) && !errors.Is(tryErr, errPainlessBreak) && !errors.Is(tryErr, errPainlessContinue) {
		for _, clause := range catches {
			if matchesCatchException(tryErr, clause.excTypes) {
				prevVal, hadPrev := params[clause.varName]
				sl, _ := params["__script_locals"].(map[string]bool)
				hadSL := sl != nil && sl[clause.varName]
				if sl != nil && !hadPrev {
					sl[clause.varName] = true
				}
				msg := tryErr.Error()
				exType := "RuntimeException"
				var pEx *painlessExceptionError
				if errors.As(tryErr, &pEx) {
					msg = pEx.message
					if pEx.exType != "" {
						exType = pEx.exType
					}
				}
				params[clause.varName] = map[string]any{
					"message":    msg,
					"type":       exType,
					"__exc_type": exType,
				}
				tryErr = execBlock(sourceMap, clause.body, params, ctxOp, budget)
				if hadPrev {
					params[clause.varName] = prevVal
				} else {
					delete(params, clause.varName)
					if sl != nil && !hadSL {
						delete(sl, clause.varName)
					}
				}
				if isUnrecoverableSandboxError(tryErr) {
					return tryErr
				}
				break
			}
		}
	}
	if hasFinally {
		savedRet, hadRet := params["_return_val"]
		savedLast, hadLast := params["_last_expr_val"]
		delete(params, "_return_val")
		delete(params, "_last_expr_val")
		finErr := execBlock(sourceMap, finallyBody, params, ctxOp, budget)
		if finErr != nil {
			tryErr = finErr
		} else {
			if hadRet {
				params["_return_val"] = savedRet
			}
			if hadLast {
				params["_last_expr_val"] = savedLast
			} else {
				delete(params, "_last_expr_val")
			}
		}
	}
	return tryErr
}

func execIfStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	cond, thenBody, elseBody, ok := parseIfBlocks(stmt)
	if !ok {
		return nil
	}
	if evalCondition(sourceMap, cond, params) {
		return execBlock(sourceMap, thenBody, params, ctxOp, budget)
	}
	if strings.TrimSpace(elseBody) != "" {
		return execBlock(sourceMap, elseBody, params, ctxOp, budget)
	}
	return nil
}

func execForStatement(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	var myLabel string
	if params != nil {
		myLabel, _ = params["__next_loop_label"].(string)
		delete(params, "__next_loop_label")
	}
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return nil
	}
	header := strings.TrimSpace(stmt[openParen+1 : closeParen])
	rest := strings.TrimSpace(stmt[closeParen+1:])
	body := strings.TrimSpace(rest)
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = body[1 : len(body)-1]
	}

	var varName, iterExpr string
	if clauses := splitTopLevelSemicolonPainless(header); len(clauses) == 3 {
		preExistingKeys := make(map[string]bool, len(params))
		loopParams := make(map[string]any, len(params)+3)
		for k, v := range params {
			preExistingKeys[k] = true
			loopParams[k] = v
		}
		loopDeclared := make(map[string]bool)
		loopParams["__loop_declared"] = loopDeclared
		initVars := make(map[string]bool)
		if initStmt := strings.TrimSpace(clauses[0]); initStmt != "" {
			var initTypePrefix string
			initRest := initStmt
			if tm := reVarTypeDeclPrefix.FindStringSubmatch(initStmt); tm != nil {
				initTypePrefix = tm[1]
				initRest = tm[2]
			}
			for _, subInit := range splitTopLevelCommaPainless(initRest) {
				subInit = strings.TrimSpace(subInit)
				if subInit == "" {
					continue
				}
				fullSubInit := subInit
				if initTypePrefix != "" && !reVarTypeDeclPrefix.MatchString(subInit) {
					fullSubInit = initTypePrefix + " " + subInit
				}
				if m := reLocalVarAssign.FindStringSubmatch(fullSubInit); m != nil {
					if initTypePrefix != "" || reVarTypeDeclPrefix.MatchString(fullSubInit) {
						initVars[m[1]] = true
						loopDeclared[m[1]] = true
					} else if _, existed := params[m[1]]; !existed {
						initVars[m[1]] = true
						loopDeclared[m[1]] = true
					}
				} else if m := reNullVarDecl.FindStringSubmatch(fullSubInit); m != nil {
					initVars[m[1]] = true
					loopDeclared[m[1]] = true
				}
				if err := execSimpleStmt(sourceMap, fullSubInit, loopParams, ctxOp, budget); err != nil {
					return err
				}
			}
		}
		condExpr := strings.TrimSpace(clauses[1])
		postStmt := strings.TrimSpace(clauses[2])
		var loopErr error
		for {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
			if condExpr != "" && !evalCondition(sourceMap, condExpr, loopParams) {
				break
			}
			if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
				if errors.Is(err, errPainlessBreak) {
					break
				}
				if !errors.Is(err, errPainlessContinue) {
					var lblJump *painlessLabeledJumpError
					if errors.As(err, &lblJump) && myLabel != "" && lblJump.label == myLabel {
						if lblJump.isBreak {
							break
						}
					} else {
						loopErr = err
						break
					}
				}
			}
			if postStmt != "" {
				for _, subPost := range splitTopLevelCommaPainless(postStmt) {
					subPost = strings.TrimSpace(subPost)
					if subPost == "" {
						continue
					}
					if err := execSimpleStmt(sourceMap, subPost, loopParams, ctxOp, budget); err != nil {
						loopErr = err
						break
					}
				}
				if loopErr != nil {
					break
				}
			}
		}
		syncLoopScopeBack(params, loopParams, preExistingKeys, initVars, loopDeclared)
		return loopErr
	} else if idx, sepLen := findTopLevelForInOrColon(header); idx >= 0 {
		varName = strings.TrimSpace(header[:idx])
		iterExpr = strings.TrimSpace(header[idx+sepLen:])
	} else {
		return nil
	}
	if closeIdx := strings.LastIndexAny(varName, ">]"); closeIdx >= 0 && closeIdx+1 < len(varName) {
		varName = strings.TrimSpace(varName[closeIdx+1:])
	}
	fields := strings.Fields(varName)
	if len(fields) > 0 {
		varName = fields[len(fields)-1]
	}

	var iterVal any
	expIter := strings.TrimSpace(expandDynamicBrackets(iterExpr, sourceMap, params, 0))
	if (strings.HasPrefix(expIter, "doc.") || strings.HasPrefix(expIter, "doc?.")) &&
		!strings.HasSuffix(expIter, ".value") && !strings.Contains(expIter, ".value.") && !strings.Contains(expIter, ".values.") && !strings.Contains(expIter, "(") {
		docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expIter, "doc?."), "doc."), ".values")
		iterVal = resolveDocValuesSlice(sourceMap, docPath)
	} else {
		var err error
		iterVal, err = evalRHSExpr(sourceMap, iterExpr, params)
		if err != nil {
			return err
		}
	}
	slice, ok := iterVal.([]any)
	if !ok {
		if mVal, isMap := iterVal.(map[string]any); isMap {
			keys := visiblePainlessMapKeys(mVal)
			slice = make([]any, len(keys))
			for i, k := range keys {
				slice[i] = map[string]any{"key": k, "value": mVal[k], "__parent_map": mVal}
			}
		} else {
			return nil
		}
	}
	// Copy slice header + elements so in-loop mutations do not mutate the iteration snapshot
	snapshot := make([]any, len(slice))
	copy(snapshot, slice)

	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	if !preExistingKeys[varName] || len(fields) > 1 {
		loopDeclared[varName] = true
	}
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error
	for _, item := range snapshot {
		if err := budget.step(); err != nil {
			loopErr = err
			break
		}
		loopParams[varName] = item
		if err := execBlock(sourceMap, body, loopParams, ctxOp, budget); err != nil {
			if errors.Is(err, errPainlessBreak) {
				break
			}
			if errors.Is(err, errPainlessContinue) {
				continue
			}
			var lblJump *painlessLabeledJumpError
			if errors.As(err, &lblJump) && myLabel != "" && lblJump.label == myLabel {
				if lblJump.isBreak {
					break
				}
				continue
			}
			loopErr = err
			break
		}
	}
	syncLoopScopeBack(params, loopParams, preExistingKeys, map[string]bool{varName: true}, loopDeclared)
	return loopErr
}

func findTopLevelForInOrColon(header string) (int, int) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	colonIdx := -1
	for i := 0; i < len(header); i++ {
		if stepQuoteState(header, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch header[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				if strings.HasPrefix(header[i:], " in ") {
					return i, 4
				}
				if header[i] == ':' && colonIdx < 0 {
					colonIdx = i
				}
			}
		}
	}
	if colonIdx >= 0 {
		return colonIdx, 1
	}
	return -1, 0
}

func isIdentByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}

func isBracketReceiverByte(c byte) bool {
	return isIdentByte(c) || c == ']' || c == ')' || c == '?' || (c >= '\x00' && c <= '\x08') || (c >= '\x10' && c <= '\x1f') || c == '\x7f'
}

func encodeBracketKey(key string) string {
	var out strings.Builder
	out.Grow(len(key))
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '.':
			out.WriteByte('\x00')
		case ' ':
			out.WriteByte('\x01')
		case '/':
			out.WriteByte('\x02')
		case ':':
			out.WriteByte('\x03')
		case '-':
			out.WriteByte('\x04')
		case '+':
			out.WriteByte('\x05')
		case '*':
			out.WriteByte('\x06')
		case '%':
			out.WriteByte('\x07')
		case '?':
			out.WriteByte('\x08')
		case '!':
			out.WriteByte('\x10')
		case '=':
			out.WriteByte('\x11')
		case '<':
			out.WriteByte('\x12')
		case '>':
			out.WriteByte('\x13')
		case '&':
			out.WriteByte('\x14')
		case '|':
			out.WriteByte('\x15')
		case '(':
			out.WriteByte('\x16')
		case ')':
			out.WriteByte('\x17')
		case '[':
			out.WriteByte('\x18')
		case ']':
			out.WriteByte('\x19')
		case '{':
			out.WriteByte('\x1a')
		case '}':
			out.WriteByte('\x1b')
		case ',':
			out.WriteByte('\x1c')
		case ';':
			out.WriteByte('\x1d')
		case '^':
			out.WriteByte('\x1e')
		case '~':
			out.WriteByte('\x1f')
		case '#':
			out.WriteByte('\x7f')
		default:
			out.WriteByte(key[i])
		}
	}
	return out.String()
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
		if s == "" {
			return false
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func decodeBracketSeg(seg string) string {
	seg = strings.TrimSuffix(seg, "?")
	seg = strings.ReplaceAll(seg, "\x00", ".")
	seg = strings.ReplaceAll(seg, "\x01", " ")
	seg = strings.ReplaceAll(seg, "\x02", "/")
	seg = strings.ReplaceAll(seg, "\x03", ":")
	seg = strings.ReplaceAll(seg, "\x04", "-")
	seg = strings.ReplaceAll(seg, "\x05", "+")
	seg = strings.ReplaceAll(seg, "\x06", "*")
	seg = strings.ReplaceAll(seg, "\x07", "%")
	seg = strings.ReplaceAll(seg, "\x08", "?")
	seg = strings.ReplaceAll(seg, "\x10", "!")
	seg = strings.ReplaceAll(seg, "\x11", "=")
	seg = strings.ReplaceAll(seg, "\x12", "<")
	seg = strings.ReplaceAll(seg, "\x13", ">")
	seg = strings.ReplaceAll(seg, "\x14", "&")
	seg = strings.ReplaceAll(seg, "\x15", "|")
	seg = strings.ReplaceAll(seg, "\x16", "(")
	seg = strings.ReplaceAll(seg, "\x17", ")")
	seg = strings.ReplaceAll(seg, "\x18", "[")
	seg = strings.ReplaceAll(seg, "\x19", "]")
	seg = strings.ReplaceAll(seg, "\x1a", "{")
	seg = strings.ReplaceAll(seg, "\x1b", "}")
	seg = strings.ReplaceAll(seg, "\x1c", ",")
	seg = strings.ReplaceAll(seg, "\x1d", ";")
	seg = strings.ReplaceAll(seg, "\x1e", "^")
	seg = strings.ReplaceAll(seg, "\x1f", "~")
	seg = strings.ReplaceAll(seg, "\x7f", "#")
	return seg
}

func findNextUnquotedSubstr(s, sub string, from int) int {
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		if i >= from && strings.HasPrefix(s[i:], sub) {
			return i
		}
	}
	return -1
}

func isNewArrayDimensionBracketPainless(s string, openBrackIdx int) bool {
	if openBrackIdx <= 0 || openBrackIdx >= len(s) || s[openBrackIdx] != '[' {
		return false
	}
	// Map each closing ']' to its matching opening '[' using quote-aware scanning
	closeToOpen := make(map[int]int)
	var stack []int
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i <= openBrackIdx && i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		if s[i] == '[' {
			stack = append(stack, i)
		} else if s[i] == ']' && len(stack) > 0 {
			openIdx := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			closeToOpen[i] = openIdx
		}
	}
	pos := openBrackIdx
	for {
		for pos > 0 && (s[pos-1] == ' ' || s[pos-1] == '\t' || s[pos-1] == '\n' || s[pos-1] == '\r') {
			pos--
		}
		if pos > 0 && s[pos-1] == ']' {
			if prevOpen, ok := closeToOpen[pos-1]; ok {
				pos = prevOpen
				continue
			}
		}
		break
	}
	typeEnd := pos
	typeStart := typeEnd
	for typeStart > 0 && (isIdentByte(s[typeStart-1]) || s[typeStart-1] == '.') {
		typeStart--
	}
	if typeStart == typeEnd {
		return false
	}
	wsEnd := typeStart
	for wsEnd > 0 && (s[wsEnd-1] == ' ' || s[wsEnd-1] == '\t' || s[wsEnd-1] == '\n' || s[wsEnd-1] == '\r') {
		wsEnd--
	}
	if wsEnd == typeStart || wsEnd < 3 || s[wsEnd-3:wsEnd] != "new" {
		return false
	}
	newStart := wsEnd - 3
	if newStart > 0 && (isIdentByte(s[newStart-1]) || s[newStart-1] == '.') {
		return false
	}
	return true
}

func isBracketReceiverAt(s string, openBrackIdx int, closeBrackIdx int) (isReceiver bool, hasSafeDot bool) {
	if openBrackIdx <= 0 {
		return false, false
	}
	if isNewArrayDimensionBracketPainless(s, openBrackIdx) {
		return false, false
	}
	prev := s[openBrackIdx-1]
	if prev == '.' && openBrackIdx >= 2 && s[openBrackIdx-2] == '?' {
		return true, true
	}
	if prev == '?' {
		if openBrackIdx < 2 || (!isIdentByte(s[openBrackIdx-2]) && s[openBrackIdx-2] != ']' && s[openBrackIdx-2] != ')') {
			return false, false
		}
		if closeBrackIdx > openBrackIdx && findMatchingTernaryColonPainless(s[closeBrackIdx+1:]) >= 0 {
			return false, false
		}
		return true, false
	}
	if isIdentByte(prev) {
		j := openBrackIdx - 1
		for j > 0 && isIdentByte(s[j-1]) {
			j--
		}
		word := s[j:openBrackIdx]
		switch word {
		case "return", "case", "throw", "new", "in", "instanceof", "else", "yield":
			return false, false
		}
		return true, false
	}
	return prev == ']' || prev == ')' || (prev >= '\x00' && prev <= '\x08') || (prev >= '\x10' && prev <= '\x1f') || prev == '\x7f', false
}

func isUnboundIdentIndex(inner string, params map[string]any) bool {
	if !reSimpleFieldPath.MatchString(inner) || strings.Contains(inner, ".") {
		return false
	}
	if inner == "true" || inner == "false" || inner == "null" {
		return false
	}
	if params == nil {
		return true
	}
	_, exists := params[inner]
	return !exists
}

func findLambdaBodyEndPainless(s string, bodyStart int) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for j := bodyStart; j < len(s); j++ {
		if stepQuoteState(s, j, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[j] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return j
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return j
			}
		}
	}
	return len(s)
}

func isInsideCallArgsOrBrackets(s string, targetIdx int) bool {
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < targetIdx && i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		if s[i] == '(' && i > 0 && isIdentByte(s[i-1]) {
			closeP := findMatchingDelimiter(s, i, '(', ')')
			if closeP > targetIdx {
				return true
			}
			if closeP > i {
				i = closeP
				continue
			}
		}
		if s[i] == '[' {
			closeB := findMatchingDelimiter(s, i, '[', ']')
			if closeB > targetIdx {
				return true
			}
			if closeB > i {
				i = closeB
				continue
			}
		}
	}
	return false
}

func expandDynamicBrackets(s string, sourceMap map[string]any, params map[string]any, depth int) string {
	if (strings.IndexByte(s, '[') < 0 && !strings.Contains(s, ".get(")) || depth > 64 {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			out.WriteByte(c)
			continue
		}
		if c == '-' && i+1 < len(s) && s[i+1] == '>' {
			endIdx := findLambdaBodyEndPainless(s, i+2)
			out.WriteString(s[i:endIdx])
			i = endIdx - 1
			continue
		}
		if c == '(' && i > 0 && isIdentByte(s[i-1]) {
			closeParen := findMatchingDelimiter(s, i, '(', ')')
			if closeParen > i {
				out.WriteString(s[i : closeParen+1])
				i = closeParen
				continue
			}
		}
		if c == '[' {
			closeIdx := findMatchingDelimiter(s, i, '[', ']')
			if closeIdx > i+1 && i > 0 {
				if isRecv, hasSafeDot := isBracketReceiverAt(s, i, closeIdx); isRecv {
					inner := strings.TrimSpace(s[i+1 : closeIdx])
					if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0] {
						q := inner[0]
						rawKey := inner[1 : len(inner)-1]
						validLiteral := true
						for k := 0; k < len(rawKey); k++ {
							if rawKey[k] == '\\' {
								k++
								continue
							}
							if rawKey[k] == q {
								validLiteral = false
								break
							}
						}
						if validLiteral {
							unescKey := unescapePainlessString(rawKey)
							if !hasSafeDot {
								out.WriteByte('.')
							}
							if unescKey == "_source" {
								out.WriteString("_source")
							} else {
								out.WriteString(encodeBracketKey(unescKey))
							}
							i = closeIdx
							continue
						}
					}
					if isIntegerLiteral(inner) {
						if !hasSafeDot {
							out.WriteByte('.')
						}
						out.WriteString(encodeBracketKey(inner))
						i = closeIdx
						continue
					}
					if (sourceMap != nil || params != nil) && !isUnboundIdentIndex(inner, params) {
						if idxVal, err := evalRHSExprDepth(sourceMap, inner, params, depth+1); err == nil && idxVal != nil {
							var keyStr string
							if strVal, isStr := idxVal.(string); isStr {
								keyStr = strVal
							} else if f, ok := toFloat64(idxVal); ok && f == float64(int64(f)) {
								keyStr = strconv.FormatInt(int64(f), 10)
							} else {
								keyStr = fmt.Sprintf("%v", idxVal)
							}
							if keyStr != "" {
								if !hasSafeDot {
									out.WriteByte('.')
								}
								if keyStr == "_source" {
									out.WriteString("_source")
								} else {
									out.WriteString(encodeBracketKey(keyStr))
								}
								i = closeIdx
								continue
							}
						}
					}
				}
			}
			if closeIdx > i && (i == 0 || func() bool { r, _ := isBracketReceiverAt(s, i, closeIdx); return !r }()) {
				out.WriteString(s[i : closeIdx+1])
				i = closeIdx
				continue
			}
		}
		out.WriteByte(c)
	}
	res := out.String()
	searchFrom := 0
	for {
		getIdx := findNextUnquotedSubstr(res, ".get(", searchFrom)
		if getIdx < 0 {
			break
		}
		arrowIdx := findNextUnquotedSubstr(res, "->", searchFrom)
		if arrowIdx >= 0 && arrowIdx < getIdx {
			lambdaEnd := findLambdaBodyEndPainless(res, arrowIdx+2)
			if getIdx < lambdaEnd {
				searchFrom = lambdaEnd
				continue
			}
		}
		openParen := getIdx + 4
		closeParen := findMatchingDelimiter(res, openParen, '(', ')')
		if closeParen <= openParen {
			break
		}
		if isInsideCallArgsOrBrackets(res, getIdx) {
			searchFrom = closeParen + 1
			continue
		}
		after := strings.TrimSpace(res[closeParen+1:])
		isChainedOrAssign := false
		if after != "" {
			if after[0] == '.' || strings.HasPrefix(after, "?.") || after[0] == '[' ||
				strings.HasPrefix(after, "+=") || strings.HasPrefix(after, "-=") ||
				strings.HasPrefix(after, "*=") || strings.HasPrefix(after, "/=") || strings.HasPrefix(after, "%=") ||
				strings.HasPrefix(after, "&=") || strings.HasPrefix(after, "|=") || strings.HasPrefix(after, "^=") ||
				strings.HasPrefix(after, "<<=") || strings.HasPrefix(after, ">>>=") || strings.HasPrefix(after, ">>=") ||
				strings.HasPrefix(after, "++") || strings.HasPrefix(after, "--") ||
				(after[0] == '=' && !strings.HasPrefix(after, "==") && !strings.HasPrefix(after, "=~")) {
				isChainedOrAssign = true
			}
		}
		recvEnd := getIdx
		if recvEnd > 0 && res[recvEnd-1] == '?' {
			recvEnd--
		}
		recvStart := recvEnd
		for recvStart > 0 && (isBracketReceiverByte(res[recvStart-1]) || res[recvStart-1] == '.') {
			recvStart--
		}
		if !isChainedOrAssign {
			before := strings.TrimSpace(res[:recvStart])
			if strings.HasSuffix(before, "++") || strings.HasSuffix(before, "--") {
				isChainedOrAssign = true
			}
		}
		if !isChainedOrAssign {
			searchFrom = closeParen + 1
			continue
		}
		inner := strings.TrimSpace(res[openParen+1 : closeParen])
		idxVal, err := evalRHSExprDepth(sourceMap, inner, params, depth+1)
		if err != nil || idxVal == nil {
			searchFrom = closeParen + 1
			continue
		}
		var keyStr string
		if strVal, isStr := idxVal.(string); isStr {
			keyStr = strVal
		} else if f, ok := toFloat64(idxVal); ok && f == float64(int64(f)) {
			keyStr = strconv.FormatInt(int64(f), 10)
		} else {
			keyStr = fmt.Sprintf("%v", idxVal)
		}
		if keyStr == "" {
			searchFrom = closeParen + 1
			continue
		}
		recvToken := res[recvStart:recvEnd]
		if recvToken == "ctx" && (params == nil || params["ctx"] == nil) {
			switch keyStr {
			case "_index", "_id", "_routing", "_version", "op", "_now", "_ingest":
				repl := "." + encodeBracketKey(keyStr)
				res = res[:getIdx] + repl + res[closeParen+1:]
				searchFrom = getIdx
				continue
			case "_source":
				res = res[:recvStart] + "ctx._source" + res[closeParen+1:]
				searchFrom = recvStart + len("ctx._source")
				continue
			default:
				repl := "ctx._source." + encodeBracketKey(keyStr)
				res = res[:recvStart] + repl + res[closeParen+1:]
				searchFrom = recvStart + len("ctx._source")
				continue
			}
		}
		repl := "." + encodeBracketKey(keyStr)
		if keyStr == "_source" {
			repl = "._source"
		}
		res = res[:getIdx] + repl + res[closeParen+1:]
		searchFrom = getIdx
	}
	return res
}

func mutateCtxDirectMapKey(keyStr string, val any, isRemove, ifAbsentOnly bool, sourceMap, params map[string]any) (any, error) {
	budget := getOrInitEvalBudget(params)
	switch keyStr {
	case "_id", "_index", "_routing", "_version":
		metaKey, err := checkCtxMetaLHS([]string{"ctx", keyStr}, sourceMap, params)
		if err != nil {
			return nil, err
		}
		prev := params[metaKey]
		if isRemove {
			params[metaKey] = nil
			latchCtxMetaOnBudget(budget, []string{metaKey}, nil)
			return prev, nil
		}
		if ifAbsentOnly && prev != nil {
			return prev, nil
		}
		params[metaKey] = val
		latchCtxMetaOnBudget(budget, []string{metaKey}, val)
		return prev, nil
	case "op":
		prev := params["_ctx_op"]
		if prev == nil {
			prev = "index"
		}
		if isRemove {
			params["_ctx_op"] = ""
			latchCtxMetaOnBudget(budget, []string{"_ctx_op"}, "")
			return prev, nil
		}
		if ifAbsentOnly && params["_ctx_op"] != nil {
			return prev, nil
		}
		opStr := ""
		if val != nil {
			opStr = fmt.Sprintf("%v", val)
		}
		params["_ctx_op"] = opStr
		latchCtxMetaOnBudget(budget, []string{"_ctx_op"}, opStr)
		return prev, nil
	case "_source":
		if isRemove {
			for k := range sourceMap {
				if !isInternalPainlessMapKey(sourceMap, k) {
					delete(sourceMap, k)
				}
			}
			return sourceMap, nil
		}
		if subMap, ok := val.(map[string]any); ok {
			for k := range sourceMap {
				if !isInternalPainlessMapKey(sourceMap, k) {
					delete(sourceMap, k)
				}
			}
			for k, v := range subMap {
				if !isInternalPainlessMapKey(subMap, k) {
					sourceMap[k] = v
				}
			}
		}
		return sourceMap, nil
	default:
		if isRemove {
			old := sourceMap[keyStr]
			delete(sourceMap, keyStr)
			return old, nil
		}
		prev, exists := sourceMap[keyStr]
		if ifAbsentOnly && exists && prev != nil {
			return prev, nil
		}
		sourceMap[keyStr] = val
		syncSourceAliasToLocalVars(sourceMap, params, keyStr)
		return prev, nil
	}
}

func checkCtxMetaLHS(rawPath []string, sourceMap, params map[string]any) (string, error) {
	if len(rawPath) == 2 && decodeBracketSeg(rawPath[0]) == "ctx" {
		metaField := decodeBracketSeg(rawPath[1])
		if metaField == "_id" || metaField == "_index" || metaField == "_routing" || metaField == "_version" {
			if readonly, ok := params["__readonly_ctx_meta"].(bool); ok && readonly && metaField != "_routing" {
				return "", fmt.Errorf("cannot modify read-only metadata field [ctx.%s]", metaField)
			}
			metaKey := "_ctx" + metaField
			if params != nil {
				if _, exists := params[metaKey]; !exists && sourceMap != nil {
					if v, ok := sourceMap[metaField]; ok {
						params[metaKey] = v
					}
				}
			}
			return metaKey, nil
		}
	}
	return "", nil
}

func normalizeLocalLHSPath(path []string, params map[string]any) []string {
	if len(path) == 2 && decodeBracketSeg(path[0]) == "ctx" {
		metaField := decodeBracketSeg(path[1])
		if metaField == "_id" || metaField == "_index" || metaField == "_routing" || metaField == "_version" {
			return []string{"_ctx" + metaField}
		}
		if metaField == "op" {
			return []string{"_ctx_op"}
		}
	}
	if len(path) >= 1 && decodeBracketSeg(path[0]) == "params" {
		if _, hasExplicit := params["params"]; !hasExplicit {
			return path[1:]
		}
	}
	return path
}

func normalizeIncDecPrevVal(v any) any {
	if jn, ok := v.(json.Number); ok {
		if iv, err := jn.Int64(); err == nil {
			return iv
		}
		if fv, err := jn.Float64(); err == nil {
			return fv
		}
	}
	if f, ok := toFloat64(v); ok {
		if f >= float64(math.MinInt64) && f < float64(math.MaxInt64) && f == float64(int64(f)) {
			return int64(f)
		}
		return f
	}
	return int64(0)
}

func syncLocalVarAlias(sourceMap map[string]any, params map[string]any, varName string) {
	if sourceMap == nil || params == nil || varName == "" {
		return
	}
	if wb, ok := params["__wb_"+varName].(func(any)); ok && wb != nil {
		wb(params[varName])
	}
	if aliasPath, ok := params["__alias_"+varName].(string); ok && aliasPath != "" {
		if aliasPath == "@root" {
			for k := range sourceMap {
				syncSourceAliasToLocalVars(sourceMap, params, k)
			}
			return
		}
		val := params[varName]
		switch val.(type) {
		case []any, map[string]any:
			setValueAtPath(sourceMap, strings.Split(aliasPath, "."), val)
		}
		syncSourceAliasToLocalVars(sourceMap, params, aliasPath)
	}
}

func syncSourceAliasToLocalVars(sourceMap map[string]any, params map[string]any, targetPath string) {
	if sourceMap == nil || params == nil || targetPath == "" {
		return
	}
	for k, v := range params {
		if strings.HasPrefix(k, "__alias_") {
			if aliasPath, ok := v.(string); ok && aliasPath != "@root" && (aliasPath == targetPath || strings.HasPrefix(aliasPath, targetPath+".") || strings.HasPrefix(targetPath, aliasPath+".")) {
				varName := strings.TrimPrefix(k, "__alias_")
				params[varName] = resolveParamPath(sourceMap, strings.Split(aliasPath, "."))
			}
		}
	}
}

func findTopLevelAssignOpStartPainless(s string) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 {
				if i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '~') {
					i++
					continue
				}
				if i > 0 && (s[i-1] == '=' || s[i-1] == '!' || s[i-1] == '~') {
					continue
				}
				if i > 0 && s[i-1] == '<' && (i < 2 || s[i-2] != '<') {
					continue
				}
				if i > 0 && s[i-1] == '>' && (i < 2 || s[i-2] != '>') {
					continue
				}
				if i >= 3 && s[i-3:i] == ">>>" {
					return i - 3
				}
				if i >= 2 && (s[i-2:i] == "<<" || s[i-2:i] == ">>") {
					return i - 2
				}
				if i >= 1 && strings.IndexByte("+-*/%&|^", s[i-1]) >= 0 {
					return i - 1
				}
				return i
			}
		}
	}
	return -1
}

func expandStmtTargetsOnly(stmt string, sourceMap, params map[string]any) string {
	stmt = strings.TrimSpace(stmt)
	if stmt == "return" || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return;") ||
		strings.HasPrefix(stmt, "return(") || strings.HasPrefix(stmt, "return[") ||
		strings.HasPrefix(stmt, "return'") || strings.HasPrefix(stmt, "return\"") || strings.HasPrefix(stmt, "return/") ||
		stmt == "yield" || strings.HasPrefix(stmt, "yield ") || strings.HasPrefix(stmt, "yield(") ||
		strings.HasPrefix(stmt, "yield[") || strings.HasPrefix(stmt, "yield'") || strings.HasPrefix(stmt, "yield\"") ||
		stmt == "break" || strings.HasPrefix(stmt, "break ") || stmt == "continue" || strings.HasPrefix(stmt, "continue ") ||
		stmt == "throw" || strings.HasPrefix(stmt, "throw ") || strings.HasPrefix(stmt, "throw(") ||
		reVarTypeDeclPrefix.MatchString(stmt) {
		return stmt
	}
	_, hasRawSrc := rawSourceFromSourceMapPainless(sourceMap)
	if opStart := findTopLevelAssignOpStartPainless(stmt); opStart > 0 {
		lhs := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expandDynamicBrackets(stmt[:opStart]+" =", sourceMap, params, 0)), "="))
		if !hasRawSrc {
			for _, pfx := range []string{"params?._source?.", "params?._source.", "params._source?.", "params._source."} {
				if strings.HasPrefix(lhs, pfx) {
					lhs = "ctx._source." + strings.TrimPrefix(lhs, pfx)
					break
				}
			}
		}
		return strings.TrimSpace(lhs + " " + stmt[opStart:])
	}
	if strings.HasPrefix(stmt, "++") || strings.HasPrefix(stmt, "--") ||
		strings.HasSuffix(stmt, "++") || strings.HasSuffix(stmt, "--") ||
		(strings.HasSuffix(stmt, ")") && !strings.HasPrefix(stmt, "(")) {
		exp := strings.TrimSpace(expandDynamicBrackets(stmt, sourceMap, params, 0))
		if !hasRawSrc {
			for _, pfx := range []string{"params?._source?.", "params?._source.", "params._source?.", "params._source."} {
				if strings.HasPrefix(exp, pfx) {
					exp = "ctx._source." + strings.TrimPrefix(exp, pfx)
					break
				}
				if strings.HasPrefix(exp, "++"+pfx) {
					exp = "++ctx._source." + strings.TrimPrefix(exp, "++"+pfx)
					break
				}
				if strings.HasPrefix(exp, "--"+pfx) {
					exp = "--ctx._source." + strings.TrimPrefix(exp, "--"+pfx)
					break
				}
			}
		}
		return exp
	}
	return stmt
}

func normalizeUserClassVarDeclPainless(stmt string, budget *evalBudget) string {
	if budget == nil || len(budget.userClasses) == 0 {
		return stmt
	}
	t := strings.TrimSpace(stmt)
	endIdent := 0
	for endIdent < len(t) && isIdentByte(t[endIdent]) {
		endIdent++
	}
	if endIdent == 0 {
		return stmt
	}
	clsName := t[:endIdent]
	if _, exists := budget.userClasses[clsName]; !exists {
		return stmt
	}
	pos := endIdent
	for pos < len(t) {
		wsPos := pos
		for wsPos < len(t) && (t[wsPos] == ' ' || t[wsPos] == '\t') {
			wsPos++
		}
		if wsPos < len(t) && t[wsPos] == '[' {
			closeBr := findMatchingDelimiter(t, wsPos, '[', ']')
			if closeBr > wsPos && strings.TrimSpace(t[wsPos+1:closeBr]) == "" {
				pos = closeBr + 1
				continue
			}
		}
		break
	}
	wsEnd := pos
	for wsEnd < len(t) && (t[wsEnd] == ' ' || t[wsEnd] == '\t') {
		wsEnd++
	}
	if wsEnd == pos || wsEnd >= len(t) || !isIdentByte(t[wsEnd]) {
		return stmt
	}
	return "def" + t[endIdent:]
}

func execSimpleStmt(sourceMap map[string]any, stmt string, params map[string]any, ctxOp *string, budget *evalBudget) error {
	delete(params, "_last_expr_val")
	stmt = normalizeUserClassVarDeclPainless(stmt, budget)
	stmt = expandStmtTargetsOnly(stmt, sourceMap, params)
	if stmt == "return" || strings.HasPrefix(stmt, "return ") || strings.HasPrefix(stmt, "return;") || strings.HasPrefix(stmt, "return(") || strings.HasPrefix(stmt, "return[") || strings.HasPrefix(stmt, "return'") || strings.HasPrefix(stmt, "return\"") || strings.HasPrefix(stmt, "return/") {
		retExpr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(stmt, "return")), ";"))
		if retExpr == "" {
			params["_return_val"] = nil
			return errPainlessReturn
		}
		val, err := evalRHSExpr(sourceMap, retExpr, params)
		if err != nil {
			return err
		}
		params["_return_val"] = val
		return errPainlessReturn
	}
	if stmt == "break" {
		return errPainlessBreak
	}
	if strings.HasPrefix(stmt, "break ") {
		lbl := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmt[6:]), ";"))
		if reIdentOnly.MatchString(lbl) {
			return &painlessLabeledJumpError{label: lbl, isBreak: true}
		}
	}
	if stmt == "continue" {
		return errPainlessContinue
	}
	if strings.HasPrefix(stmt, "continue ") {
		lbl := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stmt[9:]), ";"))
		if reIdentOnly.MatchString(lbl) {
			return &painlessLabeledJumpError{label: lbl, isBreak: false}
		}
	}
	if strings.HasPrefix(stmt, "yield ") || strings.HasPrefix(stmt, "yield(") || strings.HasPrefix(stmt, "yield[") || strings.HasPrefix(stmt, "yield'") || strings.HasPrefix(stmt, "yield\"") {
		yieldExpr := strings.TrimSpace(stmt[5:])
		val, err := evalRHSExpr(sourceMap, yieldExpr, params)
		if err != nil {
			return err
		}
		if params != nil {
			params["__switch_yield_val"] = val
		}
		return errPainlessYield
	}
	if stmt == "throw" || strings.HasPrefix(stmt, "throw ") || strings.HasPrefix(stmt, "throw(") {
		throwExpr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(stmt, "throw")), ";"))
		if strings.HasPrefix(throwExpr, "new ") {
			rest := strings.TrimSpace(throwExpr[4:])
			openP := strings.IndexByte(rest, '(')
			closeP := findMatchingDelimiter(rest, openP, '(', ')')
			if openP > 0 && closeP == len(rest)-1 {
				exType := strings.TrimSpace(rest[:openP])
				argExpr := strings.TrimSpace(rest[openP+1 : closeP])
				msg := ""
				if argExpr != "" {
					if v, err := evalRHSExpr(sourceMap, argExpr, params); err == nil && v != nil {
						msg = fmt.Sprintf("%v", v)
					} else {
						msg = argExpr
					}
				}
				return &painlessExceptionError{exType: exType, message: msg}
			}
		}
		if v, err := evalRHSExpr(sourceMap, throwExpr, params); err == nil && v != nil {
			if m, ok := v.(map[string]any); ok {
				exType, _ := m["__exc_type"].(string)
				msg, _ := m["message"].(string)
				return &painlessExceptionError{exType: exType, message: msg}
			}
			return &painlessExceptionError{exType: "RuntimeException", message: fmt.Sprintf("%v", v)}
		}
		return &painlessExceptionError{exType: "RuntimeException", message: throwExpr}
	}
	if m := reCtxOp.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[1]), "=") && !strings.HasPrefix(strings.TrimSpace(m[1]), "~") {
		val, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[1]), params)
		if err != nil {
			return err
		}
		if val == nil {
			*ctxOp = ""
		} else {
			*ctxOp = fmt.Sprintf("%v", val)
		}
		params["_ctx_op"] = *ctxOp
		if budget != nil {
			budget.ctxOp = *ctxOp
			budget.hasCtxOp = true
		}
		return nil
	}
	if m := reCtxIncDec.FindStringSubmatch(stmt); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		pathStr := m[2]
		if op == "" {
			pathStr = m[3]
			op = m[4]
		}
		lhsPath := strings.Split(pathStr, ".")
		curVal := resolveParamPath(sourceMap, lhsPath)
		nextVal := applyArithmetic(curVal, int64(1), op == "++")
		setValueAtPath(sourceMap, lhsPath, nextVal)
		syncSourceAliasToLocalVars(sourceMap, params, pathStr)
		if isPrefix {
			params["_last_expr_val"] = nextVal
		} else {
			params["_last_expr_val"] = normalizeIncDecPrevVal(curVal)
		}
		return nil
	}
	if m := reLocalIncDec.FindStringSubmatch(stmt); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		lhs := m[2]
		if op == "" {
			lhs = m[3]
			op = m[4]
		}
		rawPath := strings.Split(lhs, ".")
		if _, err := checkCtxMetaLHS(rawPath, sourceMap, params); err != nil {
			return err
		}
		path := normalizeLocalLHSPath(rawPath, params)
		if len(path) > 0 {
			curVal := resolveParamPath(params, path)
			nextVal := applyArithmetic(curVal, int64(1), op == "++")
			setValueAtPath(params, path, nextVal)
			if len(rawPath) > 0 && decodeBracketSeg(rawPath[0]) == "params" && len(path) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(path[0]))
			}
			latchCtxMetaOnBudget(budget, path, nextVal)
			if isPrefix {
				params["_last_expr_val"] = nextVal
			} else {
				params["_last_expr_val"] = normalizeIncDecPrevVal(curVal)
			}
			if len(path) > 1 {
				syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
			}
		}
		return nil
	}

	// 1. Check `removeIf` on array of objects or scalars
	if m := reArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		changed, err := removeIfCondFromSlice(sourceMap, sourceMap, arrPath, m[2], strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = changed
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}

	// 2. Check `.addAll(...)` on array
	if m := reArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if addAllArgs := splitTopLevelCommaPainless(m[2]); len(addAllArgs) == 2 {
			idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[0]), params)
			if err != nil {
				return err
			}
			valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[1]), params)
			if err != nil {
				return err
			}
			items, _ := valToAdd.([]any)
			changed, err := insertAllIntoSliceAtPath(sourceMap, arrPath, idxVal, items, budget)
			if err != nil {
				return err
			}
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
			params["_last_expr_val"] = changed
			return nil
		}
		valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		changed := false
		if items, ok := valToAdd.([]any); ok {
			// Snapshot items before appending to prevent self-aliasing issues
			itemsCopy := make([]any, len(items))
			copy(itemsCopy, items)
			for _, item := range itemsCopy {
				if err := budget.step(); err != nil {
					return err
				}
				if err := appendToSlice(sourceMap, arrPath, item); err != nil {
					return err
				}
				changed = true
			}
		}
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		params["_last_expr_val"] = changed
		return nil
	}

	if m := reArrayRemoveAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, false)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}
	if m := reArrayRetainAll.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, true)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		return nil
	}

	// 3. Check `.add(...)` / `.set(idx, val)` on array
	if m := reArrayAdd.FindStringSubmatch(stmt); m != nil {
		arrPath := strings.Split(m[1], ".")
		if addArgs := splitTopLevelCommaPainless(m[2]); len(addArgs) == 2 {
			idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[0]), params)
			if err != nil {
				return err
			}
			valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[1]), params)
			if err != nil {
				return err
			}
			if err := insertIntoSliceAtPath(sourceMap, arrPath, idxVal, valToAdd); err != nil {
				return err
			}
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
			params["_last_expr_val"] = true
			return nil
		}
		valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		if err := appendToSlice(sourceMap, arrPath, valToAdd); err != nil {
			return err
		}
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		params["_last_expr_val"] = true
		return nil
	}
	if m := reArraySet.FindStringSubmatch(stmt); m != nil {
		if setArgs := splitTopLevelCommaPainless(m[2]); len(setArgs) == 2 {
			arrPath := strings.Split(m[1], ".")
			idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[0]), params)
			if err != nil {
				return err
			}
			newVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[1]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = setSliceElementAtPath(sourceMap, arrPath, idxVal, newVal)
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
			return nil
		}
	}

	// 4. Check `.putAll(...)` on map
	if m := reMapPutAll.FindStringSubmatch(stmt); m != nil {
		var targetPath []string
		if m[1] != "" {
			targetPath = strings.Split(m[1], ".")
		}
		mapVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		if subMap, ok := mapVal.(map[string]any); ok {
			putAllAtPath(sourceMap, targetPath, subMap)
			if m[1] != "" {
				syncSourceAliasToLocalVars(sourceMap, params, m[1])
				for k := range subMap {
					syncSourceAliasToLocalVars(sourceMap, params, m[1]+"."+k)
				}
			} else {
				for k := range subMap {
					syncSourceAliasToLocalVars(sourceMap, params, k)
				}
			}
		}
		params["_last_expr_val"] = nil
		return nil
	}

	// 5. Check `.put(k, v)` on map
	if m := reMapPut.FindStringSubmatch(stmt); m != nil {
		if putArgs := splitTopLevelCommaPainless(m[2]); len(putArgs) == 2 {
			var targetPath []string
			if m[1] != "" {
				targetPath = strings.Split(m[1], ".")
			}
			kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[0]), params)
			if err != nil {
				return err
			}
			vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[1]), params)
			if err != nil {
				return err
			}
			keyStr := encodeBracketKey(fmt.Sprintf("%v", kVal))
			fullKeyPath := append(targetPath, keyStr)
			params["_last_expr_val"] = resolveParamPath(sourceMap, fullKeyPath)
			setValueAtPath(sourceMap, fullKeyPath, vVal)
			if m[1] != "" {
				syncSourceAliasToLocalVars(sourceMap, params, m[1])
			}
			syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
			return nil
		}
	}

	// 6. Check `.remove('field')` or `.remove(params.key)` or `.remove(0)` or `.clear()`
	if m := reRemoveField.FindStringSubmatch(stmt); m != nil {
		var parentPath []string
		if m[1] != "" {
			parentPath = strings.Split(m[1], ".")
		}
		if remArgs := splitTopLevelCommaPainless(m[2]); len(remArgs) == 2 {
			kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[0]), params)
			if err != nil {
				return err
			}
			vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[1]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = removeKeyValueAtPath(sourceMap, parentPath, kVal, vVal)
			if m[1] != "" {
				syncSourceAliasToLocalVars(sourceMap, params, m[1])
			}
			return nil
		}
		argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = removeKeyOrIndexAtPath(sourceMap, parentPath, argVal)
		if m[1] != "" {
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
		}
		return nil
	}
	if m := reClearField.FindStringSubmatch(stmt); m != nil {
		var targetPath []string
		if m[1] != "" {
			targetPath = strings.Split(m[1], ".")
		}
		clearAtPath(sourceMap, targetPath)
		if m[1] != "" {
			syncSourceAliasToLocalVars(sourceMap, params, m[1])
		}
		params["_last_expr_val"] = nil
		return nil
	}

	// 6b. Check `.removeIf`, `.addAll`, `.add`, `.putAll`, `.put`, `.remove`, `.clear` on local/loop variables
	if m := reLocalArrayRemoveIf.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				changed, err := removeIfCondFromSlice(sourceMap, params, arrPath, m[2], strings.TrimSpace(m[3]), params)
				if err != nil {
					return err
				}
				params["_last_expr_val"] = changed
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayAddAll.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				if addAllArgs := splitTopLevelCommaPainless(m[2]); len(addAllArgs) == 2 {
					idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[0]), params)
					if err != nil {
						return err
					}
					valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addAllArgs[1]), params)
					if err != nil {
						return err
					}
					items, _ := valToAdd.([]any)
					changed, err := insertAllIntoSliceAtPath(params, arrPath, idxVal, items, budget)
					if err != nil {
						return err
					}
					params["_last_expr_val"] = changed
					syncLocalVarAlias(sourceMap, params, rootVar)
					return nil
				}
				valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				changed := false
				if items, ok := valToAdd.([]any); ok {
					itemsCopy := make([]any, len(items))
					copy(itemsCopy, items)
					for _, item := range itemsCopy {
						if err := budget.step(); err != nil {
							return err
						}
						if err := appendToSlice(params, arrPath, item); err != nil {
							return err
						}
						changed = true
					}
				}
				params["_last_expr_val"] = changed
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayRemoveAll.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(params, arrPath, argVal, false)
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayRetainAll.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
				if err != nil {
					return err
				}
				params["_last_expr_val"] = mutateSliceRemoveOrRetainAtPath(params, arrPath, argVal, true)
				syncLocalVarAlias(sourceMap, params, rootVar)
				return nil
			}
		}
	}
	if m := reLocalArrayAdd.FindStringSubmatch(stmt); m != nil {
		arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
		if len(arrPath) > 0 {
			rootVar := decodeBracketSeg(arrPath[0])
			if _, ok := params[rootVar]; ok {
				targetVal := resolveParamPath(params, arrPath)
				_, isBD := targetVal.(*painlessBigDecimal)
				_, isBI := targetVal.(*painlessBigInteger)
				_, isSJ := targetVal.(*painlessStringJoiner)
				_, isUO := targetVal.(*painlessUserObject)
				if !isBD && !isBI && !isSJ && !isUO {
					if addArgs := splitTopLevelCommaPainless(m[2]); len(addArgs) == 2 {
						idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[0]), params)
						if err != nil {
							return err
						}
						valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(addArgs[1]), params)
						if err != nil {
							return err
						}
						if err := insertIntoSliceAtPath(params, arrPath, idxVal, valToAdd); err != nil {
							return err
						}
						params["_last_expr_val"] = true
						syncLocalVarAlias(sourceMap, params, rootVar)
						return nil
					}
					valToAdd, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
					if err != nil {
						return err
					}
					if err := appendToSlice(params, arrPath, valToAdd); err != nil {
						return err
					}
					params["_last_expr_val"] = true
					syncLocalVarAlias(sourceMap, params, rootVar)
					return nil
				}
			}
		}
	}
	if m := reLocalArraySet.FindStringSubmatch(stmt); m != nil {
		if setArgs := splitTopLevelCommaPainless(m[2]); len(setArgs) == 2 {
			arrPath := normalizeLocalLHSPath(strings.Split(m[1], "."), params)
			if len(arrPath) > 0 {
				rootVar := decodeBracketSeg(arrPath[0])
				if _, ok := params[rootVar]; ok {
					targetVal := resolveParamPath(params, arrPath)
					_, isBS := targetVal.(*painlessBitSet)
					_, isUO := targetVal.(*painlessUserObject)
					if !isBS && !isUO {
						idxVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[0]), params)
						if err != nil {
							return err
						}
						newVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(setArgs[1]), params)
						if err != nil {
							return err
						}
						params["_last_expr_val"] = setSliceElementAtPath(params, arrPath, idxVal, newVal)
						syncLocalVarAlias(sourceMap, params, rootVar)
						return nil
					}
				}
			}
		}
	}
	if m := reLocalMapPutAll.FindStringSubmatch(stmt); m != nil {
		rawPath := strings.Split(m[1], ".")
		targetPath := normalizeLocalLHSPath(rawPath, params)
		isRootParams := len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
		rootVar := ""
		hasRoot := isRootParams
		if len(targetPath) > 0 {
			rootVar = decodeBracketSeg(targetPath[0])
			_, hasRoot = params[rootVar]
		}
		if hasRoot {
			mapVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			if subMap, ok := mapVal.(map[string]any); ok {
				putAllAtPath(params, targetPath, subMap)
				if isRootParams {
					for k := range subMap {
						markExplicitParamsKey(params, k)
					}
				}
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
			}
			params["_last_expr_val"] = nil
			return nil
		}
	}
	if m := reLocalMapPut.FindStringSubmatch(stmt); m != nil {
		if putArgs := splitTopLevelCommaPainless(m[2]); len(putArgs) == 2 {
			rawPath := strings.Split(m[1], ".")
			targetPath := normalizeLocalLHSPath(rawPath, params)
			isRootParams := len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
			rootVar := ""
			hasRoot := isRootParams
			if len(targetPath) > 0 {
				rootVar = decodeBracketSeg(targetPath[0])
				_, hasRoot = params[rootVar]
			}
			if hasRoot {
				kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[0]), params)
				if err != nil {
					return err
				}
				vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(putArgs[1]), params)
				if err != nil {
					return err
				}
				keyStr := fmt.Sprintf("%v", kVal)
				encKey := encodeBracketKey(keyStr)
				fullKeyPath := append(targetPath, encKey)
				if tm, ok := resolveParamPath(params, targetPath).(map[string]any); ok && tm != nil && len(targetPath) > 0 {
					params["_last_expr_val"] = tm[keyStr]
					tm[keyStr] = vVal
				} else {
					params["_last_expr_val"] = resolveParamPath(params, fullKeyPath)
					setValueAtPath(params, fullKeyPath, vVal)
				}
				if isRootParams {
					markExplicitParamsKey(params, keyStr)
				}
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
				return nil
			}
		}
	}
	if m := reLocalRemoveField.FindStringSubmatch(stmt); m != nil {
		rawPath := strings.Split(m[1], ".")
		parentPath := normalizeLocalLHSPath(rawPath, params)
		isRootParams := len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
		rootVar := ""
		hasRoot := isRootParams
		if len(parentPath) > 0 {
			rootVar = decodeBracketSeg(parentPath[0])
			_, hasRoot = params[rootVar]
		}
		if hasRoot {
			if remArgs := splitTopLevelCommaPainless(m[2]); len(remArgs) == 2 {
				kVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[0]), params)
				if err != nil {
					return err
				}
				vVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(remArgs[1]), params)
				if err != nil {
					return err
				}
				removed := removeKeyValueAtPath(params, parentPath, kVal, vVal)
				if isRootParams && removed && kVal != nil {
					unmarkExplicitParamsKey(params, fmt.Sprintf("%v", kVal))
				}
				params["_last_expr_val"] = removed
				if rootVar != "" {
					syncLocalVarAlias(sourceMap, params, rootVar)
				}
				return nil
			}
			argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[2]), params)
			if err != nil {
				return err
			}
			params["_last_expr_val"] = removeKeyOrIndexAtPath(params, parentPath, argVal)
			if isRootParams && argVal != nil {
				unmarkExplicitParamsKey(params, fmt.Sprintf("%v", argVal))
			}
			if rootVar != "" {
				syncLocalVarAlias(sourceMap, params, rootVar)
			}
			return nil
		}
	}
	if m := reLocalClearField.FindStringSubmatch(stmt); m != nil {
		rawPath := strings.Split(m[1], ".")
		targetPath := normalizeLocalLHSPath(rawPath, params)
		isRootParams := len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params"
		rootVar := ""
		hasRoot := isRootParams
		if len(targetPath) > 0 {
			rootVar = decodeBracketSeg(targetPath[0])
			_, hasRoot = params[rootVar]
		}
		if hasRoot {
			targetVal := resolveParamPath(params, targetPath)
			if _, isUO := targetVal.(*painlessUserObject); !isUO {
				if isRootParams {
					for k := range params {
						if !isInternalPainlessMapKey(params, k) {
							delete(params, k)
							unmarkExplicitParamsKey(params, k)
						}
					}
				} else {
					clearAtPath(params, targetPath)
					if rootVar != "" {
						syncLocalVarAlias(sourceMap, params, rootVar)
					}
				}
				params["_last_expr_val"] = nil
				return nil
			}
		}
	}
	if !isTopLevelAssignmentStmt(stmt) && !strings.HasPrefix(stmt, "return ") && !strings.HasPrefix(stmt, "return(") {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(stmt, ".setValue("); ok {
			recVal, err := evalRHSExpr(sourceMap, recExpr, params)
			if err != nil {
				return err
			}
			argVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(argExpr), params)
			if err != nil {
				return err
			}
			if m, ok := recVal.(map[string]any); ok {
				oldVal := m["value"]
				m["value"] = argVal
				if pm, ok := m["__parent_map"].(map[string]any); ok {
					pm[fmt.Sprintf("%v", m["key"])] = argVal
				}
				params["_last_expr_val"] = oldVal
			}
			return nil
		}
	}

	// 7. Check compound assignment `+=` / `-=` / `*=` / `/=` / `%=` / `&=` / `|=` / `^=` / `<<=` / `>>=` / `>>>=`
	if m := reCompoundAssign.FindStringSubmatch(stmt); m != nil {
		lhsPath := strings.Split(m[1], ".")
		op := m[2]
		rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		curVal := resolveParamPath(sourceMap, lhsPath)
		var nextVal any
		switch op {
		case "+=":
			nextVal = applyArithmetic(curVal, rhsVal, true)
		case "-=":
			nextVal = applyArithmetic(curVal, rhsVal, false)
		case "*=":
			nextVal = applyMulDiv(curVal, rhsVal, '*')
		case "/=":
			nextVal = applyMulDiv(curVal, rhsVal, '/')
		case "%=":
			nextVal = applyMulDiv(curVal, rhsVal, '%')
		case "&=", "|=", "^=", "<<=", ">>=", ">>>=":
			nextVal = applyBitwiseAssign(curVal, rhsVal, op)
		}
		setValueAtPath(sourceMap, lhsPath, nextVal)
		syncSourceAliasToLocalVars(sourceMap, params, m[1])
		params["_last_expr_val"] = nextVal
		return nil
	}

	// 8. Check field assignment (`ctx._source.deleted = params.deleted`, arithmetic, or literal)
	if m := reAssignParam.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[2]), "=") && !strings.HasPrefix(strings.TrimSpace(m[2]), "~") {
		lhsPath := strings.Split(m[1], ".")
		rhsExpr := strings.TrimSpace(m[2])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		setValueAtPath(sourceMap, lhsPath, val)
		for k, v := range params {
			if strings.HasPrefix(k, "__alias_") {
				if aliasPath, ok := v.(string); ok && (aliasPath == m[1] || strings.HasPrefix(aliasPath, m[1]+".")) {
					delete(params, k)
				}
			}
		}
		if reSimpleFieldPath.MatchString(rhsExpr) && !strings.Contains(rhsExpr, ".") {
			if _, exists := params[rhsExpr]; exists {
				switch val.(type) {
				case []any, map[string]any:
					params["__alias_"+rhsExpr] = m[1]
				}
			}
		}
		params["_last_expr_val"] = val
		return nil
	}

	// 9. Check local/loop variable compound assignment (`sum += x`, `item.count += 1`, `items[0].qty += 2`)
	if m := reLocalCompoundAssign.FindStringSubmatch(stmt); m != nil {
		lhs := m[1]
		op := m[2]
		rawPath := strings.Split(lhs, ".")
		if _, err := checkCtxMetaLHS(rawPath, sourceMap, params); err != nil {
			return err
		}
		rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(m[3]), params)
		if err != nil {
			return err
		}
		path := normalizeLocalLHSPath(rawPath, params)
		if len(path) == 0 {
			return nil
		}
		curVal := resolveParamPath(params, path)
		var nextVal any
		switch op {
		case "+=":
			nextVal = applyArithmetic(curVal, rhsVal, true)
		case "-=":
			nextVal = applyArithmetic(curVal, rhsVal, false)
		case "*=":
			nextVal = applyMulDiv(curVal, rhsVal, '*')
		case "/=":
			nextVal = applyMulDiv(curVal, rhsVal, '/')
		case "%=":
			nextVal = applyMulDiv(curVal, rhsVal, '%')
		case "&=", "|=", "^=", "<<=", ">>=", ">>>=":
			nextVal = applyBitwiseAssign(curVal, rhsVal, op)
		}
		setValueAtPath(params, path, nextVal)
		if len(rawPath) > 0 && decodeBracketSeg(rawPath[0]) == "params" && len(path) == 1 {
			markExplicitParamsKey(params, decodeBracketSeg(path[0]))
		}
		latchCtxMetaOnBudget(budget, path, nextVal)
		params["_last_expr_val"] = nextVal
		if len(path) > 1 {
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
		}
		return nil
	}

	// 10. Check local/loop variable property/index assignment (`tag.status = 'active'`, `items[0] = 'x'`)
	if m := reLocalPropAssign.FindStringSubmatch(stmt); m != nil && m[1] != "doc" && !strings.HasPrefix(strings.TrimSpace(m[3]), "=") && !strings.HasPrefix(strings.TrimSpace(m[3]), "~") {
		varName := m[1]
		propPath := strings.Split(m[2], ".")
		if _, err := checkCtxMetaLHS(append([]string{varName}, propPath...), sourceMap, params); err != nil {
			return err
		}
		rhsExpr := strings.TrimSpace(m[3])
		val, err := evalRHSExpr(sourceMap, rhsExpr, params)
		if err != nil {
			return err
		}
		if decodeBracketSeg(varName) == "ctx" && len(propPath) == 1 && decodeBracketSeg(propPath[0]) == "_source" && params["ctx"] == nil {
			if _, err := mutateCtxDirectMapKey("_source", val, false, false, sourceMap, params); err != nil {
				return err
			}
			params["_last_expr_val"] = sourceMap
			return nil
		}
		fullPath := normalizeLocalLHSPath(append([]string{varName}, propPath...), params)
		if len(fullPath) > 0 {
			setValueAtPath(params, fullPath, val)
			if decodeBracketSeg(varName) == "params" && len(fullPath) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(fullPath[0]))
			}
			latchCtxMetaOnBudget(budget, fullPath, val)
			if len(propPath) == 1 && propPath[0] == "value" {
				if entryMap, ok := params[varName].(map[string]any); ok {
					if pm, ok := entryMap["__parent_map"].(map[string]any); ok {
						pm[fmt.Sprintf("%v", entryMap["key"])] = val
					}
				}
			}
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(fullPath[0]))
		}
		params["_last_expr_val"] = val
		return nil
	}
	if eqIdx := findTopLevelOpPainless(stmt, "="); eqIdx > 0 && (eqIdx+1 >= len(stmt) || (stmt[eqIdx+1] != '=' && stmt[eqIdx+1] != '~')) && stmt[eqIdx-1] != '!' && stmt[eqIdx-1] != '<' && stmt[eqIdx-1] != '>' {
		lhsExpr := strings.TrimSpace(stmt[:eqIdx])
		if callExpr, tailPath, ok := splitPostCallPropertyAccess(lhsExpr); ok {
			callVal, err := evalRHSExpr(sourceMap, callExpr, params)
			if err != nil {
				return err
			}
			rhsVal, err := evalRHSExpr(sourceMap, strings.TrimSpace(stmt[eqIdx+1:]), params)
			if err != nil {
				return err
			}
			if callVal != nil {
				setValueAtPath(map[string]any{"_v": callVal}, append([]string{"_v"}, strings.Split(tailPath, ".")...), rhsVal)
				params["_last_expr_val"] = rhsVal
			}
			return nil
		}
	}

	// 11. Check local variable declaration/assignment (`def x = ...`, `boolean ok = ...`, `int a = 1, b = 2`, `x = ...`)
	if tm := reVarTypeDeclPrefix.FindStringSubmatch(stmt); tm != nil {
		typePrefix := tm[1]
		decls := splitTopLevelCommaPainless(tm[2])
		if len(decls) > 1 {
			allValid := true
			for _, d := range decls {
				d = strings.TrimSpace(d)
				if !reIdentAssign.MatchString(d) && !reIdentOnly.MatchString(d) {
					allValid = false
					break
				}
			}
			if allValid {
				for _, d := range decls {
					d = strings.TrimSpace(d)
					if err := execSimpleStmt(sourceMap, typePrefix+" "+d, params, ctxOp, budget); err != nil {
						return err
					}
				}
				return nil
			}
		}
	} else if commaStmts := splitTopLevelCommaPainless(stmt); len(commaStmts) > 1 {
		allSimple := true
		for _, cs := range commaStmts {
			cs = strings.TrimSpace(cs)
			if cs == "" || (!isTopLevelAssignmentStmt(cs) && !strings.HasPrefix(cs, "++") && !strings.HasPrefix(cs, "--") && !strings.HasSuffix(cs, "++") && !strings.HasSuffix(cs, "--")) {
				allSimple = false
				break
			}
		}
		if allSimple {
			for _, cs := range commaStmts {
				if err := execSimpleStmt(sourceMap, strings.TrimSpace(cs), params, ctxOp, budget); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if m := reLocalVarAssign.FindStringSubmatch(stmt); m != nil && !strings.HasPrefix(strings.TrimSpace(m[2]), "=") && !strings.HasPrefix(strings.TrimSpace(m[2]), "~") {
		varName := m[1]
		_, existed := params[varName]
		var isLocalDecl bool
		if reVarTypeDeclPrefix.MatchString(stmt) {
			isLocalDecl = true
			if ld, ok := params["__loop_declared"].(map[string]bool); ok {
				ld[varName] = true
			}
			if sl, ok := params["__script_locals"].(map[string]bool); ok && !existed {
				sl[varName] = true
			}
		} else if !existed {
			hasImplicitField := false
			if uo, isThis := params["this"].(*painlessUserObject); isThis && uo != nil && uo.fields != nil {
				_, hasImplicitField = uo.fields[varName]
			}
			if !hasImplicitField {
				if sl, ok := params["__script_locals"].(map[string]bool); ok {
					sl[varName] = true
				}
			}
		}
		rhsExpr := strings.TrimSpace(m[2])
		val, writeBack, err := resolveMutableReceiverPainless(sourceMap, rhsExpr, params, 0)
		if err != nil {
			return err
		}
		params[varName] = val
		if writeBack != nil {
			params["__wb_"+varName] = writeBack
		} else {
			delete(params, "__wb_"+varName)
		}
		if !isLocalDecl {
			if uo, isThis := params["this"].(*painlessUserObject); isThis && uo != nil && uo.fields != nil && varName != "this" {
				shadowed := false
				if mp, okMP := params["__method_params"].(map[string]bool); okMP && mp[varName] {
					shadowed = true
				}
				if sl, okSL := params["__script_locals"].(map[string]bool); okSL && sl[varName] {
					shadowed = true
				}
				if !shadowed {
					if _, hasField := uo.fields[varName]; hasField {
						uo.fields[varName] = val
					}
				}
			}
		}
		if rv, ok := params["__reassigned_vars"].(map[string]bool); ok {
			rv[varName] = true
		}
		trimmedCtor := strings.TrimSpace(rhsExpr)
		for _, pkgPfx := range []string{"new java.util.", "new "} {
			if strings.HasPrefix(trimmedCtor, pkgPfx) {
				restCtor := strings.TrimSpace(strings.TrimPrefix(trimmedCtor, pkgPfx))
				switch {
				case strings.HasPrefix(restCtor, "TreeSet"):
					params["__col_kind_"+varName] = "TreeSet"
				case strings.HasPrefix(restCtor, "HashSet"), strings.HasPrefix(restCtor, "LinkedHashSet"):
					params["__col_kind_"+varName] = "Set"
				case strings.HasPrefix(restCtor, "PriorityQueue"):
					params["__col_kind_"+varName] = "PriorityQueue"
				default:
					delete(params, "__col_kind_"+varName)
				}
				break
			}
		}
		matchedAlias := false
		_, hasRawSrcAlias := rawSourceFromSourceMapPainless(sourceMap)
		expRHS := strings.TrimSpace(expandDynamicBrackets(rhsExpr, sourceMap, params, 0))
		if expRHS == "ctx._source" || expRHS == "ctx?._source" || expRHS == "ctx._source?" || expRHS == "ctx?._source?" ||
			(!hasRawSrcAlias && (expRHS == "params._source" || expRHS == "params?._source" || expRHS == "params._source?" || expRHS == "params?._source?")) {
			params["__alias_"+varName] = "@root"
			matchedAlias = true
		}
		for _, pfx := range []string{
			"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source.",
			"params?._source?.", "params?._source.", "params._source?.", "params._source.",
		} {
			if hasRawSrcAlias && strings.HasPrefix(pfx, "params") {
				continue
			}
			if strings.HasPrefix(expRHS, pfx) {
				tail := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(expRHS, pfx)), "?")
				if reSimpleFieldPath.MatchString(tail) && !strings.HasSuffix(tail, ".size()") && !strings.HasSuffix(tail, ".length()") {
					switch val.(type) {
					case []any, map[string]any:
						params["__alias_"+varName] = tail
						matchedAlias = true
					}
				}
				break
			}
		}
		if !matchedAlias && reSimpleFieldPath.MatchString(expRHS) && !strings.HasSuffix(expRHS, ".size()") && !strings.HasSuffix(expRHS, ".length()") {
			rhsParts := normalizeLocalLHSPath(strings.Split(expRHS, "."), params)
			if len(rhsParts) > 0 {
				rootVar := decodeBracketSeg(rhsParts[0])
				if baseAlias, ok := params["__alias_"+rootVar].(string); ok && baseAlias != "" {
					switch val.(type) {
					case []any, map[string]any:
						if baseAlias == "@root" {
							if len(rhsParts) > 1 {
								params["__alias_"+varName] = strings.Join(rhsParts[1:], ".")
							} else {
								params["__alias_"+varName] = "@root"
							}
						} else {
							params["__alias_"+varName] = strings.Join(append([]string{baseAlias}, rhsParts[1:]...), ".")
						}
						matchedAlias = true
					}
				}
			}
		}
		if !matchedAlias {
			delete(params, "__alias_"+varName)
		}
		if !reVarTypeDeclPrefix.MatchString(stmt) {
			params["_last_expr_val"] = val
		}
		return nil
	}
	if m := reNullVarDecl.FindStringSubmatch(stmt); m != nil {
		if ld, ok := params["__loop_declared"].(map[string]bool); ok {
			ld[m[1]] = true
		}
		if _, existed := params[m[1]]; !existed {
			if sl, ok := params["__script_locals"].(map[string]bool); ok {
				sl[m[1]] = true
			}
		}
		params[m[1]] = nil
		if rv, ok := params["__reassigned_vars"].(map[string]bool); ok {
			rv[m[1]] = true
		}
		delete(params, "__alias_"+m[1])
		return nil
	}

	if strings.HasSuffix(stmt, ")") {
		val, err := evalRHSExpr(sourceMap, stmt, params)
		if err != nil {
			return err
		}
		params["_last_expr_val"] = val
		return nil
	}
	if stmt != "" && !isTopLevelAssignmentStmt(stmt) {
		val, err := evalRHSExpr(sourceMap, stmt, params)
		if err != nil {
			var pEx *painlessExceptionError
			if errors.As(err, &pEx) {
				return err
			}
		}
		if err == nil && (val != nil || findTopLevelOpPainless(stmt, "?") > 0 || findTopLevelOpPainless(stmt, "?:") > 0) {
			params["_last_expr_val"] = val
			return nil
		}
		if strings.ContainsAny(stmt, "><=!&|") || strings.Contains(stmt, ".empty") || strings.Contains(stmt, ".contains(") || strings.Contains(stmt, ".startsWith(") || strings.Contains(stmt, ".endsWith(") || strings.Contains(stmt, ".isEmpty()") || strings.Contains(stmt, ".matches(") || strings.Contains(stmt, ".containsKey(") || strings.Contains(stmt, ".equals(") || strings.Contains(stmt, ".equalsIgnoreCase(") {
			params["_last_expr_val"] = evalCondition(sourceMap, stmt, params)
			return nil
		}
	}

	return nil
}

func trimBalancedParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		if findMatchingDelimiter(s, 0, '(', ')') == len(s)-1 {
			s = strings.TrimSpace(s[1 : len(s)-1])
		} else {
			break
		}
	}
	return s
}

func splitTopLevelCondOp(s, op string) []string {
	var parts []string
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastStart := 0
	for i := 0; i <= len(s)-len(op); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+len(op)] == op {
				parts = append(parts, s[lastStart:i])
				lastStart = i + len(op)
				i += len(op) - 1
			}
		}
	}
	if len(parts) > 0 {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func evalCondition(sourceMap map[string]any, cond string, params map[string]any) bool {
	return evalConditionDepth(sourceMap, cond, params, 0)
}

func isEscapedAt(s string, idx int) bool {
	bs := 0
	for j := idx - 1; j >= 0 && s[j] == '\\'; j-- {
		bs++
	}
	return bs%2 == 1
}

func findMatchingRegexSlash(s string, openIdx int) int {
	if openIdx < 0 || openIdx >= len(s)-1 || s[openIdx] != '/' || s[openIdx+1] == '/' || s[openIdx+1] == '*' {
		return -1
	}
	inClass := false
	for k := openIdx + 1; k < len(s); k++ {
		if s[k] == '\n' || s[k] == '\r' {
			return -1
		}
		if isEscapedAt(s, k) {
			continue
		}
		if s[k] == '[' && !inClass {
			inClass = true
			continue
		}
		if s[k] == ']' && inClass {
			inClass = false
			continue
		}
		if s[k] == '/' && !inClass {
			if k > openIdx+1 {
				return k
			}
			return -1
		}
	}
	return -1
}

func isRegexSlashAt(s string, idx int) bool {
	if findMatchingRegexSlash(s, idx) <= idx+1 {
		return false
	}
	for j := idx - 1; j >= 0; j-- {
		if s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r' {
			continue
		}
		if s[j] == '>' && j > 0 && s[j-1] == '-' {
			return true
		}
		if j >= 5 && s[j-5:j+1] == "return" && (j == 5 || !isIdentByte(s[j-6])) {
			return true
		}
		switch s[j] {
		case '~', '(', ',', '=', ':', '?', '!', '&', '|', '[', '{', ';':
			return true
		default:
			return false
		}
	}
	return true
}

func stepQuoteState(s string, i int, inQuotes *byte, inRegexClass *bool) bool {
	c := s[i]
	if *inQuotes != 0 {
		if *inQuotes == '/' && !isEscapedAt(s, i) {
			if c == '[' && !*inRegexClass {
				*inRegexClass = true
				return true
			}
			if c == ']' && *inRegexClass {
				*inRegexClass = false
				return true
			}
			if *inRegexClass {
				return true
			}
		}
		if c == *inQuotes && !isEscapedAt(s, i) {
			*inQuotes = 0
			*inRegexClass = false
		}
		return true
	}
	if c == '/' && isRegexSlashAt(s, i) {
		*inQuotes = '/'
		*inRegexClass = false
		return true
	}
	if c == '\'' || c == '"' {
		*inQuotes = c
		return true
	}
	return false
}

func findTopLevelOpPainless(s, op string) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i <= len(s)-len(op); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+len(op)] == op {
				if op == "==" && ((i+2 < len(s) && (s[i+2] == '~' || s[i+2] == '=')) || (i > 0 && (s[i-1] == '=' || s[i-1] == '!'))) {
					continue
				}
				if op == "=~" && i > 0 && s[i-1] == '=' {
					continue
				}
				if op == "!=" && i+2 < len(s) && s[i+2] == '=' {
					continue
				}
				if op == ">" && ((i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '>')) || (i > 0 && (s[i-1] == '>' || s[i-1] == '-'))) {
					continue
				}
				if op == "<" && ((i+1 < len(s) && (s[i+1] == '=' || s[i+1] == '<')) || (i > 0 && s[i-1] == '<')) {
					continue
				}
				if op == "|" && ((i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '=')) || (i > 0 && s[i-1] == '|')) {
					continue
				}
				if op == "&" && ((i+1 < len(s) && (s[i+1] == '&' || s[i+1] == '=')) || (i > 0 && s[i-1] == '&')) {
					continue
				}
				if op == "^" && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				if op == ">>" && ((i+2 < len(s) && (s[i+2] == '>' || s[i+2] == '=')) || (i > 0 && s[i-1] == '>')) {
					continue
				}
				if (op == "<<" || op == ">>>") && i+len(op) < len(s) && s[i+len(op)] == '=' {
					continue
				}
				if op == "?" && i+1 < len(s) && (s[i+1] == '.' || s[i+1] == ':') {
					continue
				}
				if op == ":" && i > 0 && s[i-1] == '?' {
					continue
				}
				return i
			}
		}
	}
	return -1
}

func findLastTopLevelOpPainless(s string, ops ...string) (int, string) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastIdx := -1
	lastOp := ""
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth != 0 {
				continue
			}
			for _, op := range ops {
				if i+len(op) > len(s) || s[i:i+len(op)] != op {
					continue
				}
				if op == "|" && ((i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '=')) || (i > 0 && s[i-1] == '|')) {
					continue
				}
				if op == "&" && ((i+1 < len(s) && (s[i+1] == '&' || s[i+1] == '=')) || (i > 0 && s[i-1] == '&')) {
					continue
				}
				if op == "^" && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				if op == ">>" && ((i+2 < len(s) && (s[i+2] == '>' || s[i+2] == '=')) || (i > 0 && s[i-1] == '>')) {
					continue
				}
				if op == "<<" && ((i+2 < len(s) && s[i+2] == '=') || (i > 0 && s[i-1] == '<')) {
					continue
				}
				if op == ">>>" && ((i+3 < len(s) && s[i+3] == '=') || (i > 0 && s[i-1] == '>')) {
					continue
				}
				lastIdx = i
				lastOp = op
				if len(op) > 1 {
					i += len(op) - 1
				}
				break
			}
		}
	}
	return lastIdx, lastOp
}

func findMatchingTernaryColonPainless(s string) int {
	depth := 0
	ternaryDepth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '?':
			if depth == 0 && (i+1 >= len(s) || (s[i+1] != '.' && s[i+1] != ':')) {
				ternaryDepth++
			}
		case ':':
			if depth == 0 && (i == 0 || s[i-1] != '?') {
				if ternaryDepth == 0 {
					return i
				}
				ternaryDepth--
			}
		}
	}
	return -1
}

func isRawRegexLiteralPainless(expr string) bool {
	expr = trimBalancedParens(strings.TrimSpace(expr))
	return len(expr) >= 3 && expr[0] == '/' && findMatchingRegexSlash(expr, 0) == len(expr)-1
}

func isQuotedStringExprPainless(expr string) bool {
	s := trimBalancedParens(strings.TrimSpace(expr))
	return len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"'))
}

func evalRegexMatchPainless(lhsVal, rhsVal any, isRegexLit, fullMatch bool) bool {
	if lhsVal == nil || rhsVal == nil {
		return false
	}
	lhsStr := fmt.Sprintf("%v", lhsVal)
	if pp, ok := rhsVal.(*painlessPattern); ok && pp != nil && pp.re != nil {
		if fullMatch {
			re, err := compilePainlessRegexp("^(?:" + pp.re.String() + ")$")
			if err != nil {
				return false
			}
			return re.MatchString(lhsStr)
		}
		return pp.re.MatchString(lhsStr)
	}
	pat := strings.TrimSpace(fmt.Sprintf("%v", rhsVal))
	if (isRegexLit || isRawRegexLiteralPainless(pat)) && len(pat) >= 2 && pat[0] == '/' && pat[len(pat)-1] == '/' {
		pat = strings.ReplaceAll(pat[1:len(pat)-1], `\/`, `/`)
	}
	if fullMatch {
		pat = "^(?:" + pat + ")$"
	}
	re, err := compilePainlessRegexp(pat)
	if err != nil {
		return false
	}
	return re.MatchString(lhsStr)
}

func evalConditionDepth(sourceMap map[string]any, cond string, params map[string]any, depth int) bool {
	if depth > 64 {
		return false
	}
	cond = trimBalancedParens(cond)
	if cond == "" || cond == "false" {
		return false
	}
	if cond == "true" {
		return true
	}
	elvisIdx := findTopLevelOpPainless(cond, "?:")
	qIdx := findTopLevelOpPainless(cond, "?")
	if qIdx > 0 && (elvisIdx < 0 || qIdx < elvisIdx) {
		rest := cond[qIdx+1:]
		if cIdx := findMatchingTernaryColonPainless(rest); cIdx >= 0 {
			if evalConditionDepth(sourceMap, strings.TrimSpace(cond[:qIdx]), params, depth+1) {
				return evalConditionDepth(sourceMap, strings.TrimSpace(rest[:cIdx]), params, depth+1)
			}
			return evalConditionDepth(sourceMap, strings.TrimSpace(rest[cIdx+1:]), params, depth+1)
		}
	}
	if elvisIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:elvisIdx]), params, depth+1)
		if err == nil && !isEmptyOptionalOrNilPainless(leftVal) {
			if b, ok := leftVal.(bool); ok {
				return b
			}
			if f, ok := toFloat64(leftVal); ok {
				return f != 0
			}
			return true
		}
		return evalConditionDepth(sourceMap, strings.TrimSpace(cond[elvisIdx+2:]), params, depth+1)
	}
	if parts := splitTopLevelCondOp(cond, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalConditionDepth(sourceMap, p, params, depth+1) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevelCondOp(cond, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalConditionDepth(sourceMap, p, params, depth+1) {
				return false
			}
		}
		return true
	}
	for _, bwOp := range []string{"|", "^", "&"} {
		if idx, _ := findLastTopLevelOpPainless(cond, bwOp); idx > 0 {
			leftExpr := strings.TrimSpace(cond[:idx])
			rightExpr := strings.TrimSpace(cond[idx+1:])
			if hasTopLevelBooleanOrRegexOp(trimBalancedParens(leftExpr)) || hasTopLevelBooleanOrRegexOp(trimBalancedParens(rightExpr)) {
				lb := evalConditionDepth(sourceMap, leftExpr, params, depth+1)
				rb := evalConditionDepth(sourceMap, rightExpr, params, depth+1)
				switch bwOp {
				case "|":
					return lb || rb
				case "^":
					return lb != rb
				case "&":
					return lb && rb
				}
			}
		}
	}
	if idx := findTopLevelOpPainless(cond, "!=="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+3:]), params, depth+1)
		return !valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "==="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+3:]), params, depth+1)
		return valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "!="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+2:]), params, depth+1)
		return !valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "=="); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+2:]), params, depth+1)
		return valuesEqual(lhs, rhs)
	}
	if idx := findTopLevelOpPainless(cond, "==~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+3:])
		isRegexLit := isRawRegexLiteralPainless(rhsRaw)
		var rhs any = rhsRaw
		if !isRegexLit {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return evalRegexMatchPainless(lhs, rhs, isRegexLit, true)
	}
	if idx := findTopLevelOpPainless(cond, "=~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+2:])
		isRegexLit := isRawRegexLiteralPainless(rhsRaw)
		var rhs any = rhsRaw
		if !isRegexLit {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return evalRegexMatchPainless(lhs, rhs, isRegexLit, false)
	}
	if idx := findTopLevelOpPainless(cond, "!~"); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		rhsRaw := strings.TrimSpace(cond[idx+2:])
		isRegexLit := isRawRegexLiteralPainless(rhsRaw)
		var rhs any = rhsRaw
		if !isRegexLit {
			rhs, _ = evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		}
		return !evalRegexMatchPainless(lhs, rhs, isRegexLit, false)
	}
	for _, op := range []string{">=", "<=", ">", "<"} {
		if idx := findTopLevelOpPainless(cond, op); idx > 0 {
			lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
			rhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+len(op):]), params, depth+1)
			return compareOrderedValues(lhs, rhs, op)
		}
	}
	if strings.HasPrefix(cond, "!") && !strings.HasPrefix(cond, "!=") {
		return !evalConditionDepth(sourceMap, cond[1:], params, depth+1)
	}
	if idx := findTopLevelOpPainless(cond, " instanceof "); idx > 0 {
		lhs, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		typeName := strings.TrimSpace(cond[idx+len(" instanceof "):])
		return evalInstanceOfPainless(lhs, typeName)
	}
	cond = trimBalancedParens(expandDynamicBrackets(cond, sourceMap, params, depth+1))

	// Check `.isEmpty()`
	if strings.HasSuffix(cond, ".isEmpty()") {
		val, err := evalRHSExprDepth(sourceMap, cond, params, depth+1)
		if err == nil {
			if b, ok := val.(bool); ok {
				return b
			}
		}
		return false
	}

	val, _ := evalRHSExprDepth(sourceMap, cond, params, depth+1)
	if b, ok := val.(bool); ok {
		return b
	}
	if val == nil {
		return false
	}
	if f, ok := toFloat64(val); ok {
		return f != 0
	}
	return true
}

func compareOrderedValues(a, b any, op string) bool {
	if a == nil || b == nil {
		return false
	}
	fa, oka := toFloat64(a)
	fb, okb := toFloat64(b)
	if oka && okb {
		switch op {
		case ">=":
			return fa >= fb
		case "<=":
			return fa <= fb
		case ">":
			return fa > fb
		case "<":
			return fa < fb
		}
	}
	sa, soka := a.(string)
	sb, sokb := b.(string)
	if soka && sokb {
		switch op {
		case ">=":
			return sa >= sb
		case "<=":
			return sa <= sb
		case ">":
			return sa > sb
		case "<":
			return sa < sb
		}
	}
	return false
}

func isIntegerValuePainless(v any) (int64, bool) {
	switch tv := v.(type) {
	case int:
		return int64(tv), true
	case int8:
		return int64(tv), true
	case int16:
		return int64(tv), true
	case int32:
		return int64(tv), true
	case int64:
		return tv, true
	case uint:
		if uint64(tv) <= math.MaxInt64 {
			return int64(tv), true // #nosec G115 -- bounded by math.MaxInt64
		}
		return math.MaxInt64, true
	case uint8:
		return int64(tv), true
	case uint16:
		return int64(tv), true
	case uint32:
		return int64(tv), true
	case uint64:
		if tv <= math.MaxInt64 {
			return int64(tv), true // #nosec G115 -- bounded by math.MaxInt64
		}
		return math.MaxInt64, true
	case json.Number:
		s := string(tv)
		if !strings.ContainsAny(s, ".eE") {
			if iv, err := tv.Int64(); err == nil {
				return iv, true
			}
		}
		return 0, false
	case *painlessBigInteger:
		if tv != nil && tv.val != nil && tv.val.IsInt64() {
			return tv.val.Int64(), true
		}
		return 0, false
	case *big.Int:
		if tv != nil && tv.IsInt64() {
			return tv.Int64(), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// painlessValuesEqual performs type-safe Java/Painless Object.equals semantics:
// numbers compare equal across numeric types if numerically equal, strings only equal strings, etc.
func painlessValuesEqual(a, b any) bool {
	a = unwrapEmptyOptionalPainless(a)
	b = unwrapEmptyOptionalPainless(b)
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if bsa, okA := a.(*painlessBitSet); okA {
		bsb, okB := b.(*painlessBitSet)
		return okB && bsa.equals(bsb)
	}
	if isNumericValuePainless(a) || isNumericValuePainless(b) {
		if !isNumericValuePainless(a) || !isNumericValuePainless(b) {
			return false
		}
		if bia, okA := a.(*painlessBigInteger); okA && bia != nil && bia.val != nil {
			if bib, okB := parsePainlessBigInteger(b); okB && bib != nil && bib.val != nil {
				return bia.val.Cmp(bib.val) == 0
			}
		}
		if bib, okB := b.(*painlessBigInteger); okB && bib != nil && bib.val != nil {
			if bia, okA := parsePainlessBigInteger(a); okA && bia != nil && bia.val != nil {
				return bia.val.Cmp(bib.val) == 0
			}
		}
		if bda, okA := a.(*painlessBigDecimal); okA && bda != nil {
			if bdb, okB := parsePainlessBigDecimal(b); okB && bdb != nil {
				return compareBigDecimalPainless(bda, bdb) == 0
			}
		}
		if bdb, okB := b.(*painlessBigDecimal); okB && bdb != nil {
			if bda, okA := parsePainlessBigDecimal(a); okA && bda != nil {
				return compareBigDecimalPainless(bda, bdb) == 0
			}
		}
		if ai, aOk := isIntegerValuePainless(a); aOk {
			if bi, bOk := isIntegerValuePainless(b); bOk {
				return ai == bi
			}
		}
		af, aOk := toFloat64(a)
		bf, bOk := toFloat64(b)
		return aOk && bOk && af == bf
	}
	if sa, ok := a.(string); ok {
		sb, okB := b.(string)
		return okB && sa == sb
	}
	if ba, ok := a.(bool); ok {
		bb, okB := b.(bool)
		return okB && ba == bb
	}
	if reflect.DeepEqual(a, b) {
		return true
	}
	return false
}

func painlessDeepEquals(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if sa, okA := a.([]any); okA {
		sb, okB := b.([]any)
		if !okB || len(sa) != len(sb) {
			return false
		}
		for i := range sa {
			if !painlessDeepEquals(sa[i], sb[i]) {
				return false
			}
		}
		return true
	}
	return painlessValuesEqual(a, b)
}

func valuesEqual(a, b any) bool {
	a = unwrapEmptyOptionalPainless(a)
	b = unwrapEmptyOptionalPainless(b)
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if reflect.DeepEqual(a, b) {
		return true
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func evalRHSExpr(sourceMap map[string]any, rhs string, params map[string]any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			if pEx, ok := r.(*painlessExceptionError); ok {
				res = nil
				err = pEx
			} else {
				panic(r)
			}
		}
	}()
	return evalRHSExprDepth(sourceMap, rhs, params, 0)
}

func evalRHSExprDepth(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("painless expression exceeded maximum recursion depth (64)")
	}
	rhs = trimBalancedParens(rhs)
	if len(rhs) >= 3 && rhs[0] == '/' && findMatchingRegexSlash(rhs, 0) == len(rhs)-1 {
		return rhs, nil
	}

	if swVal, swOk, swErr := evalSwitchExprPainless(sourceMap, rhs, params, depth+1); swOk || swErr != nil {
		return swVal, swErr
	}

	// Check Elvis operator `?:` and ternary `cond ? trueExpr : falseExpr` in left-to-right order
	elvisIdx := findTopLevelOpPainless(rhs, "?:")
	qIdx := findTopLevelOpPainless(rhs, "?")
	if qIdx > 0 && (elvisIdx < 0 || qIdx < elvisIdx) {
		rest := rhs[qIdx+1:]
		if cIdx := findMatchingTernaryColonPainless(rest); cIdx >= 0 {
			condStr := strings.TrimSpace(rhs[:qIdx])
			if evalConditionDepth(sourceMap, condStr, params, depth+1) {
				return evalRHSExprDepth(sourceMap, strings.TrimSpace(rest[:cIdx]), params, depth+1)
			}
			return evalRHSExprDepth(sourceMap, strings.TrimSpace(rest[cIdx+1:]), params, depth+1)
		}
	}
	if elvisIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[:elvisIdx]), params, depth+1)
		if err != nil {
			return nil, err
		}
		if !isEmptyOptionalOrNilPainless(leftVal) {
			return leftVal, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[elvisIdx+2:]), params, depth+1)
	}

	if cVal, cOk, cErr := evalCollectionConstructorPainless(sourceMap, rhs, params, depth+1); cOk || cErr != nil {
		return cVal, cErr
	}

	// Check boolean logical, relational, or regex operators on RHS (`||`, `&&`, `=~`, `==~`, `==`, `!=`, `>=`, `<=`, `>`, `<`, `!`)
	if hasTopLevelBooleanOrRegexOp(rhs) {
		return evalConditionDepth(sourceMap, rhs, params, depth+1), nil
	}

	// Check bitwise and shift operators (`|`, `^`, `&`, `<<`, `>>>`, `>>`)
	if bwVal, bwOk, bwErr := evalBitwiseOrShiftPainless(sourceMap, rhs, params, depth+1); bwOk || bwErr != nil {
		return bwVal, bwErr
	}

	// Check binary `+` or `-` outside quotes
	if opIdx, isAdd := findTopLevelAddSub(rhs); opIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, rhs[:opIdx], params, depth+1)
		if err != nil {
			return nil, err
		}
		rightVal, err := evalRHSExprDepth(sourceMap, rhs[opIdx+1:], params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(leftVal, rightVal, isAdd), nil
	}
	if opIdx, opCh := findTopLevelMulDiv(rhs); opIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, rhs[:opIdx], params, depth+1)
		if err != nil {
			return nil, err
		}
		rightVal, err := evalRHSExprDepth(sourceMap, rhs[opIdx+1:], params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyMulDiv(leftVal, rightVal, opCh), nil
	}
	if castType, castRest, ok := splitLeadingTypeCastPainless(rhs); ok {
		innerVal, err := evalRHSExprDepth(sourceMap, castRest, params, depth+1)
		if err != nil || innerVal == nil {
			return nil, err
		}
		switch castType {
		case "int", "long", "short", "byte", "Integer", "Long", "Short", "Byte":
			if f, fOk := toFloat64(innerVal); fOk {
				switch castType {
				case "short", "Short":
					v := int64(f) & 0xFFFF
					if v >= 0x8000 {
						v -= 0x10000
					}
					return v, nil
				case "byte", "Byte":
					v := int64(f) & 0xFF
					if v >= 0x80 {
						v -= 0x100
					}
					return v, nil
				default:
					return int64(f), nil
				}
			}
			if s, sOk := innerVal.(string); sOk && utf8.RuneCountInString(s) == 1 {
				r, _ := utf8.DecodeRuneInString(s)
				return int64(r), nil
			}
			return int64(0), nil
		case "char", "Character":
			if f, fOk := toFloat64(innerVal); fOk {
				return string(rune(int64(f) & 0xFFFF)), nil // #nosec G115 -- Java 16-bit char code unit
			}
			if s, sOk := innerVal.(string); sOk && len(s) > 0 {
				r, _ := utf8.DecodeRuneInString(s)
				return string(r), nil
			}
			return "", nil
		case "double", "float", "Double", "Float":
			if f, fOk := toFloat64(innerVal); fOk {
				return f, nil
			}
			return float64(0), nil
		case "String":
			return fmt.Sprintf("%v", innerVal), nil
		case "boolean", "Boolean":
			if b, bOk := innerVal.(bool); bOk {
				return b, nil
			}
			if f, fOk := toFloat64(innerVal); fOk {
				return f != 0, nil
			}
			return strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", innerVal)), "true"), nil
		case "def", "Object", "List", "Map":
			return innerVal, nil
		}
	}
	rhs = trimBalancedParens(expandDynamicBrackets(rhs, sourceMap, params, depth+1))
	if m := reCtxIncDec.FindStringSubmatch(rhs); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		pathStr := m[2]
		if op == "" {
			pathStr = m[3]
			op = m[4]
		}
		lhsPath := strings.Split(pathStr, ".")
		curVal := resolveParamPath(sourceMap, lhsPath)
		nextVal := applyArithmetic(curVal, int64(1), op == "++")
		setValueAtPath(sourceMap, lhsPath, nextVal)
		syncSourceAliasToLocalVars(sourceMap, params, pathStr)
		if isPrefix {
			return nextVal, nil
		}
		return normalizeIncDecPrevVal(curVal), nil
	}
	if m := reLocalIncDec.FindStringSubmatch(rhs); m != nil {
		isPrefix := m[1] != ""
		op := m[1]
		lhs := m[2]
		if op == "" {
			lhs = m[3]
			op = m[4]
		}
		rawPath := strings.Split(lhs, ".")
		if _, err := checkCtxMetaLHS(rawPath, sourceMap, params); err != nil {
			return nil, err
		}
		path := normalizeLocalLHSPath(rawPath, params)
		if len(path) > 0 {
			curVal := resolveParamPath(params, path)
			nextVal := applyArithmetic(curVal, int64(1), op == "++")
			setValueAtPath(params, path, nextVal)
			if len(rawPath) > 0 && decodeBracketSeg(rawPath[0]) == "params" && len(path) == 1 {
				markExplicitParamsKey(params, decodeBracketSeg(path[0]))
			}
			latchCtxMetaOnBudget(getOrInitEvalBudget(params), path, nextVal)
			if len(path) > 1 {
				syncLocalVarAlias(sourceMap, params, decodeBracketSeg(path[0]))
			}
			if isPrefix {
				return nextVal, nil
			}
			return normalizeIncDecPrevVal(curVal), nil
		}
	}
	if strings.HasPrefix(rhs, "+") && len(rhs) > 1 && rhs[1] != '+' {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(int64(0), innerVal, true), nil
	}
	if strings.HasPrefix(rhs, "-") && len(rhs) > 1 && (rhs[1] < '0' || rhs[1] > '9') {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		return applyArithmetic(int64(0), innerVal, false), nil
	}
	if strings.HasPrefix(rhs, "~") && len(rhs) > 1 {
		innerVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[1:]), params, depth+1)
		if err != nil {
			return nil, err
		}
		if f, ok := toFloat64(innerVal); ok {
			return ^int64(f), nil
		}
		return int64(-1), nil
	}

	if streamVal, handled, err := evalStreamPipelinePainless(sourceMap, rhs, params, depth+1); handled {
		return streamVal, err
	}

	// Check trailing zero-arg methods `.toLowerCase()`, `.toUpperCase()`, `.trim()`, `.strip()`, `.stripLeading()`, `.stripTrailing()`, `.isBlank()`, `.length()`, `.size()`, `.keySet()`, `.values()`, `.entrySet()`, `.getKey()`, `.getValue()`, `.getMessage()`, `.toString()`, and ZonedDateTime/Duration/Period/Matcher/StringBuilder getters
	for _, mSuffix := range []string{
		".toLowerCase()", ".toUpperCase()", ".trim()", ".strip()", ".stripLeading()", ".stripTrailing()", ".isBlank()", ".toCharArray()",
		".lines()", ".chars()", ".codePoints()", ".getBytes()", ".withoutPadding()", ".reverse()", ".capacity()", ".trimToSize()", ".clear()",
		".intValue()", ".longValue()", ".doubleValue()", ".floatValue()", ".shortValue()", ".byteValue()",
		".intValueExact()", ".longValueExact()", ".shortValueExact()", ".byteValueExact()",
		".length()", ".size()", ".keySet()", ".values()", ".entrySet()", ".getKey()", ".getValue()", ".getMessage()", ".toString()",
		".getYear()", ".getMonthValue()", ".getMonthOfYear()", ".getMonth()", ".getDayOfMonth()", ".getDayOfYear()", ".getDate()", ".getHour()", ".getHourOfDay()", ".getMinute()", ".getMinuteOfHour()", ".getSecond()", ".getSecondOfMinute()", ".getNano()",
		".getDayOfWeek()", ".getDayOfWeekEnum()", ".getMillis()", ".toEpochMilli()", ".getEpochSecond()", ".toInstant()",
		".toEpochDay()", ".toLocalDate()", ".toLocalDateTime()", ".toLocalTime()", ".toSecondOfDay()", ".toNanoOfDay()", ".atStartOfDay()", ".lengthOfMonth()", ".lengthOfYear()", ".isLeapYear()", ".isLeap()", ".atEndOfMonth()",
		".getYears()", ".getMonths()", ".getDays()", ".toTotalMonths()", ".normalized()",
		".toDays()", ".toHours()", ".toMinutes()", ".toSeconds()", ".toMillis()", ".toNanos()", ".getSeconds()", ".isZero()", ".isNegative()", ".abs()", ".negated()",
		".stripTrailingZeros()", ".scale()", ".precision()", ".signum()", ".negate()", ".plus()", ".toPlainString()",
		".ulp()", ".toEngineeringString()", ".toBigInteger()", ".toBigIntegerExact()", ".unscaledValue()",
		".not()", ".bitLength()", ".bitCount()", ".getLowestSetBit()", ".toByteArray()", ".toLongArray()", ".cardinality()",
		".getPrecision()", ".getRoundingMode()", ".reversed()",
		".find()", ".matches()", ".lookingAt()", ".group()", ".groupCount()", ".start()", ".end()", ".reset()", ".pattern()", ".flags()", ".regionStart()", ".regionEnd()",
		".getCount()", ".getSum()", ".getMin()", ".getMax()", ".getAverage()",
		".isPresent()", ".getAsInt()", ".getAsLong()", ".getAsDouble()", ".orElseThrow()", ".stream()",
		".clone()", ".getClass()", ".getName()", ".getSimpleName()", ".getCanonicalName()", ".getTypeName()", ".name()",
		".getMostSignificantBits()", ".getLeastSignificantBits()", ".version()", ".variant()",
		".withUpperCase()", ".withLowerCase()", ".translateEscapes()",
		".firstKey()", ".lastKey()", ".firstEntry()", ".lastEntry()", ".pollFirstEntry()", ".pollLastEntry()", ".descendingKeySet()", ".navigableKeySet()", ".descendingMap()",
		".first()", ".last()", ".getFirst()", ".getLast()", ".peekFirst()", ".peekLast()", ".peek()", ".element()", ".pollFirst()", ".pollLast()", ".poll()", ".removeFirst()", ".removeLast()", ".pop()", ".descendingSet()",
	} {
		if strings.HasSuffix(rhs, mSuffix) {
			recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(mSuffix)], "?"))
			if (mSuffix == ".length()" || mSuffix == ".size()") && (strings.HasPrefix(recExpr, "doc.") || strings.HasPrefix(recExpr, "doc?.")) &&
				!strings.HasSuffix(recExpr, ".value") && !strings.Contains(recExpr, ".values.") {
				docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recExpr, "doc?."), "doc."), ".values")
				return int64(len(resolveDocValuesSlice(sourceMap, docPath))), nil
			}
			if mSuffix == ".toString()" && (recExpr == "Arrays" || recExpr == "Objects" || recExpr == "Integer" || recExpr == "Long" || recExpr == "Short" || recExpr == "Byte" || recExpr == "Double" || recExpr == "Float" || recExpr == "Boolean" || recExpr == "Character") {
				continue
			}
			if b := getOrInitEvalBudget(params); b != nil && len(b.userClasses) > 0 {
				mBare := strings.TrimSuffix(strings.TrimPrefix(mSuffix, "."), "()")
				if uVal, uErr := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); uErr == nil {
					if uo, isUO := uVal.(*painlessUserObject); isUO && uo != nil && uo.class != nil && uo.class.methods[mBare] != nil {
						return evalUserObjectMethodPainless(uo, mBare, "", sourceMap, params, depth+1)
					}
				}
			}
			if mSuffix == ".clear()" {
				if (recExpr == "ctx" || recExpr == "ctx?" || recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?") && params["ctx"] == nil {
					clearAtPath(sourceMap, nil)
					return nil, nil
				}
				if !strings.Contains(recExpr, "(") {
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							clearAtPath(sourceMap, strings.Split(relPath, "."))
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return nil, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					targetPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(targetPath) > 0 {
						rootVar := decodeBracketSeg(targetPath[0])
						if _, exists := params[rootVar]; exists {
							clearAtPath(params, targetPath)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return nil, nil
						}
					}
				}
				recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1)
				if err != nil {
					return nil, err
				}
				switch tv := recVal.(type) {
				case *painlessBitSet:
					if tv != nil {
						tv.words = nil
					}
				case map[string]any:
					for k := range tv {
						if !isInternalPainlessMapKey(tv, k) {
							delete(tv, k)
						}
					}
				case []any:
					if writeBack != nil {
						writeBack([]any{})
					}
				}
				return nil, nil
			}
			var recVal any
			var err error
			if (mSuffix == ".keySet()" || mSuffix == ".values()" || mSuffix == ".entrySet()" || mSuffix == ".length()" || mSuffix == ".size()") &&
				(recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
				recVal = sourceMap
			} else {
				recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			}
			if err != nil {
				return nil, err
			}
			if mSuffix == ".isPresent()" {
				return !isEmptyOptionalOrNilPainless(recVal), nil
			}
			if mSuffix == ".stream()" {
				if isEmptyOptionalOrNilPainless(recVal) {
					return []any{}, nil
				}
				if bs, isBS := recVal.(*painlessBitSet); isBS {
					return bs.streamSlice(), nil
				}
				if s, ok := recVal.([]any); ok {
					return s, nil
				}
				return []any{recVal}, nil
			}
			if mSuffix == ".orElseThrow()" {
				if isEmptyOptionalOrNilPainless(recVal) {
					return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
				}
				return recVal, nil
			}
			if isEmptyOptionalOrNilPainless(recVal) {
				if mSuffix == ".getAsInt()" || mSuffix == ".getAsLong()" || mSuffix == ".getAsDouble()" {
					return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
				}
				if mSuffix == ".getClass()" && recVal == painlessEmptyOptional {
					return painlessClassForValuePainless(recVal), nil
				}
				return nil, nil
			}
			switch mSuffix {
			case ".withUpperCase()", ".withLowerCase()":
				if hf, ok := recVal.(painlessHexFormat); ok {
					hf.upperCase = mSuffix == ".withUpperCase()"
					return hf, nil
				}
				return recVal, nil
			case ".translateEscapes()":
				return translateEscapesPainless(fmt.Sprintf("%v", recVal)), nil
			case ".getMostSignificantBits()", ".getLeastSignificantBits()", ".version()", ".variant()":
				return evalUUIDZeroArgMethodPainless(mSuffix, recVal)
			case ".firstKey()", ".lastKey()", ".firstEntry()", ".lastEntry()", ".pollFirstEntry()", ".pollLastEntry()", ".descendingKeySet()", ".navigableKeySet()", ".descendingMap()",
				".first()", ".last()", ".getFirst()", ".getLast()", ".peekFirst()", ".peekLast()", ".peek()", ".element()", ".pollFirst()", ".pollLast()", ".poll()", ".removeFirst()", ".removeLast()", ".pop()", ".descendingSet()":
				return evalCollectionZeroArgMethodPainless(mSuffix, recExpr, recVal, sourceMap, params)
			case ".stripTrailingZeros()", ".scale()", ".precision()", ".signum()", ".negate()", ".plus()", ".toPlainString()",
				".ulp()", ".toEngineeringString()", ".toBigInteger()", ".toBigIntegerExact()", ".unscaledValue()",
				".not()", ".bitLength()", ".bitCount()", ".getLowestSetBit()", ".toByteArray()", ".toLongArray()", ".cardinality()",
				".getPrecision()", ".getRoundingMode()", ".reversed()":
				if cmp, isCmp := recVal.(*painlessComparator); isCmp && cmp != nil && mSuffix == ".reversed()" {
					return cmp.cloneReversed(), nil
				}
				if mc, isMC := recVal.(painlessMathContext); isMC {
					switch mSuffix {
					case ".getPrecision()":
						return int64(mc.precision), nil
					case ".getRoundingMode()":
						return mc.roundingMode, nil
					}
				}
				if bs, isBS := recVal.(*painlessBitSet); isBS && bs != nil {
					switch mSuffix {
					case ".cardinality()":
						return bs.cardinality(), nil
					case ".toByteArray()":
						return bs.toByteArray(), nil
					case ".toLongArray()":
						return bs.toLongArray(), nil
					}
				}
				if bi, isBI := recVal.(*painlessBigInteger); isBI && bi != nil {
					switch mSuffix {
					case ".signum()":
						return int64(bi.val.Sign()), nil
					case ".negate()":
						return newPainlessBigInteger(new(big.Int).Neg(bi.val)), nil
					case ".not()":
						return newPainlessBigInteger(new(big.Int).Not(bi.val)), nil
					case ".bitLength()":
						return bi.bitLength(), nil
					case ".bitCount()":
						return bi.bitCount(), nil
					case ".getLowestSetBit()":
						return bi.getLowestSetBit(), nil
					case ".toByteArray()":
						return bi.toByteArray(), nil
					case ".toBigInteger()", ".toBigIntegerExact()", ".unscaledValue()":
						return newPainlessBigInteger(bi.val), nil
					}
				}
				if bd, ok := parsePainlessBigDecimal(recVal); ok {
					switch mSuffix {
					case ".stripTrailingZeros()":
						return bd.stripTrailingZeros(), nil
					case ".scale()":
						return int64(bd.scale), nil
					case ".precision()":
						return bd.precision(), nil
					case ".signum()":
						return int64(bd.unscaled.Sign()), nil
					case ".negate()":
						return newPainlessBigDecimal(new(big.Int).Neg(bd.unscaled), bd.scale), nil
					case ".plus()":
						return newPainlessBigDecimal(bd.unscaled, bd.scale), nil
					case ".toPlainString()":
						return bd.toPlainString(), nil
					case ".ulp()":
						return newPainlessBigDecimal(big.NewInt(1), bd.scale), nil
					case ".toEngineeringString()":
						return bd.toEngineeringString(), nil
					case ".toBigInteger()":
						return newPainlessBigInteger(bd.toBigInt()), nil
					case ".toBigIntegerExact()":
						bi, err := bd.bigIntExact()
						if err != nil {
							return nil, err
						}
						return newPainlessBigInteger(bi), nil
					case ".unscaledValue()":
						return newPainlessBigInteger(bd.unscaled), nil
					}
				}
				return recVal, nil
			case ".getAsInt()", ".getAsLong()":
				if f, ok := toFloat64(recVal); ok {
					return int64(f), nil
				}
				return recVal, nil
			case ".getAsDouble()":
				if f, ok := toFloat64(recVal); ok {
					return f, nil
				}
				return recVal, nil
			case ".getCount()", ".getSum()", ".getMin()", ".getMax()", ".getAverage()":
				if m, ok := recVal.(map[string]any); ok {
					switch mSuffix {
					case ".getCount()":
						return m["count"], nil
					case ".getSum()":
						return m["sum"], nil
					case ".getMin()":
						return m["min"], nil
					case ".getMax()":
						return m["max"], nil
					case ".getAverage()":
						return m["average"], nil
					}
				}
				return nil, nil
			case ".capacity()":
				if sb, ok := recVal.(*painlessStringBuilder); ok && sb != nil {
					return int64(len(sb.buf) + 16), nil
				}
				return int64(16), nil
			case ".trimToSize()":
				if sb, ok := recVal.(*painlessStringBuilder); ok && sb != nil {
					return sb, nil
				}
				return recVal, nil
			case ".reverse()":
				if sb, ok := recVal.(*painlessStringBuilder); ok && sb != nil {
					runes := []rune(sb.buf)
					for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
						runes[i], runes[j] = runes[j], runes[i]
					}
					sb.buf = string(runes)
					return sb, nil
				}
				return recVal, nil
			case ".toLowerCase()":
				return strings.ToLower(fmt.Sprintf("%v", recVal)), nil
			case ".toUpperCase()":
				return strings.ToUpper(fmt.Sprintf("%v", recVal)), nil
			case ".trim()", ".strip()":
				return strings.TrimSpace(fmt.Sprintf("%v", recVal)), nil
			case ".stripLeading()":
				return strings.TrimLeftFunc(fmt.Sprintf("%v", recVal), unicode.IsSpace), nil
			case ".stripTrailing()":
				return strings.TrimRightFunc(fmt.Sprintf("%v", recVal), unicode.IsSpace), nil
			case ".isBlank()":
				return strings.TrimSpace(fmt.Sprintf("%v", recVal)) == "", nil
			case ".toCharArray()":
				s := fmt.Sprintf("%v", recVal)
				runes := []rune(s)
				out := make([]any, len(runes))
				for i, r := range runes {
					out[i] = string(r)
				}
				return out, nil
			case ".lines()":
				return splitLinesPainless(fmt.Sprintf("%v", recVal)), nil
			case ".chars()", ".codePoints()":
				s := fmt.Sprintf("%v", recVal)
				runes := []rune(s)
				out := make([]any, len(runes))
				for i, r := range runes {
					out[i] = int64(r)
				}
				return out, nil
			case ".getBytes()":
				s := fmt.Sprintf("%v", recVal)
				out := make([]any, len(s))
				for i := 0; i < len(s); i++ {
					out[i] = int64(s[i])
				}
				return out, nil
			case ".withoutPadding()":
				if s, ok := recVal.(string); ok && strings.HasPrefix(s, "__base64_encoder:") {
					if !strings.HasSuffix(s, ":nopad") {
						return s + ":nopad", nil
					}
					return s, nil
				}
				return recVal, nil
			case ".intValue()", ".longValue()", ".shortValue()", ".byteValue()":
				if bd, isBD := recVal.(*painlessBigDecimal); isBD && bd != nil {
					switch mSuffix {
					case ".intValue()":
						return bd.intValue(), nil
					case ".shortValue()":
						return bd.shortValue(), nil
					case ".byteValue()":
						return bd.byteValue(), nil
					default:
						return bd.longValue(), nil
					}
				}
				if bi, isBI := recVal.(*painlessBigInteger); isBI && bi != nil {
					switch mSuffix {
					case ".intValue()":
						return bi.intValue(), nil
					case ".shortValue()":
						return bi.shortValue(), nil
					case ".byteValue()":
						return bi.byteValue(), nil
					default:
						return bi.longValue(), nil
					}
				}
				var iv int64
				var okNum bool
				switch tv := recVal.(type) {
				case int64:
					iv, okNum = tv, true
				case int:
					iv, okNum = int64(tv), true
				case json.Number:
					if parsed, pErr := tv.Int64(); pErr == nil {
						iv, okNum = parsed, true
					} else if fv, fErr := tv.Float64(); fErr == nil {
						iv, okNum = int64(fv), true
					}
				default:
					if fv, fOk := toFloat64(recVal); fOk {
						iv, okNum = int64(fv), true
					}
				}
				if !okNum {
					return int64(0), nil
				}
				switch mSuffix {
				case ".intValue()":
					return int64(int32(iv)), nil // #nosec G115 -- intentional Java 32-bit signed integer wrap
				case ".shortValue()":
					return int64(int16(iv)), nil // #nosec G115 -- intentional Java 16-bit signed short wrap
				case ".byteValue()":
					return int64(int8(iv)), nil // #nosec G115 -- intentional Java 8-bit signed byte wrap
				default:
					return iv, nil
				}
			case ".intValueExact()", ".longValueExact()", ".shortValueExact()", ".byteValueExact()":
				if bd, isBD := recVal.(*painlessBigDecimal); isBD && bd != nil {
					switch mSuffix {
					case ".intValueExact()":
						return bd.intValueExact()
					case ".shortValueExact()":
						return bd.shortValueExact()
					case ".byteValueExact()":
						return bd.byteValueExact()
					default:
						return bd.longValueExact()
					}
				}
				if bi, isBI := recVal.(*painlessBigInteger); isBI && bi != nil {
					switch mSuffix {
					case ".intValueExact()":
						return bi.intValueExact()
					case ".shortValueExact()":
						return bi.shortValueExact()
					case ".byteValueExact()":
						return bi.byteValueExact()
					default:
						return bi.longValueExact()
					}
				}
				if bd, ok := parsePainlessBigDecimal(recVal); ok {
					switch mSuffix {
					case ".intValueExact()":
						return bd.intValueExact()
					case ".shortValueExact()":
						return bd.shortValueExact()
					case ".byteValueExact()":
						return bd.byteValueExact()
					default:
						return bd.longValueExact()
					}
				}
				return int64(0), nil
			case ".doubleValue()", ".floatValue()":
				if fv, fOk := toFloat64(recVal); fOk {
					return fv, nil
				}
				return float64(0), nil
			case ".getMessage()":
				if m, ok := recVal.(map[string]any); ok {
					if msg, hasMsg := m["message"]; hasMsg {
						return fmt.Sprintf("%v", msg), nil
					}
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".toString()":
				if m, ok := recVal.(map[string]any); ok {
					if excType, hasExc := m["__exc_type"].(string); hasExc && excType != "" {
						msg, _ := m["message"].(string)
						if msg != "" {
							return excType + ": " + msg, nil
						}
						return excType, nil
					}
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".toInstant()":
				return recVal, nil
			case ".getYears()", ".getMonths()", ".getDays()", ".toTotalMonths()", ".normalized()":
				if per, ok := parsePainlessPeriod(recVal); ok {
					switch mSuffix {
					case ".getYears()":
						return int64(per.years), nil
					case ".getMonths()":
						return int64(per.months), nil
					case ".getDays()":
						return int64(per.days), nil
					case ".toTotalMonths()":
						return int64(per.years)*12 + int64(per.months), nil
					case ".normalized()":
						tm := per.years*12 + per.months
						return painlessPeriod{years: tm / 12, months: tm % 12, days: per.days}, nil
					}
				}
				return int64(0), nil
			case ".toDays()", ".toHours()", ".toMinutes()", ".toSeconds()", ".toMillis()", ".toNanos()", ".getSeconds()", ".isZero()", ".isNegative()", ".abs()", ".negated()":
				if mSuffix == ".abs()" {
					if bd, isBD := recVal.(*painlessBigDecimal); isBD && bd != nil {
						return newPainlessBigDecimal(new(big.Int).Abs(bd.unscaled), bd.scale), nil
					}
					if bi, isBI := recVal.(*painlessBigInteger); isBI && bi != nil {
						return newPainlessBigInteger(new(big.Int).Abs(bi.val)), nil
					}
				}
				if per, ok := recVal.(painlessPeriod); ok {
					switch mSuffix {
					case ".isZero()":
						return per.years == 0 && per.months == 0 && per.days == 0, nil
					case ".isNegative()":
						return per.years < 0 || per.months < 0 || per.days < 0, nil
					case ".negated()":
						return painlessPeriod{years: -per.years, months: -per.months, days: -per.days}, nil
					}
				}
				if dur, ok := parsePainlessDuration(recVal); ok {
					switch mSuffix {
					case ".toDays()":
						return int64(dur / (24 * time.Hour)), nil
					case ".toHours()":
						return int64(dur / time.Hour), nil
					case ".toMinutes()":
						return int64(dur / time.Minute), nil
					case ".toSeconds()":
						return int64(dur / time.Second), nil
					case ".getSeconds()":
						sec := int64(dur / time.Second)
						if dur%time.Second < 0 {
							sec--
						}
						return sec, nil
					case ".toMillis()":
						return dur.Milliseconds(), nil
					case ".toNanos()":
						return dur.Nanoseconds(), nil
					case ".isZero()":
						return dur == 0, nil
					case ".isNegative()":
						return dur < 0, nil
					case ".abs()":
						if dur < 0 {
							return -dur, nil
						}
						return dur, nil
					case ".negated()":
						return -dur, nil
					}
				}
				return nil, nil
			case ".getYear()", ".getMonthValue()", ".getMonthOfYear()", ".getMonth()", ".getDayOfMonth()", ".getDayOfYear()", ".getDate()", ".getHour()", ".getHourOfDay()", ".getMinute()", ".getMinuteOfHour()", ".getSecond()", ".getSecondOfMinute()", ".getNano()", ".getDayOfWeek()", ".getDayOfWeekEnum()", ".getMillis()", ".toEpochMilli()", ".getEpochSecond()", ".toEpochDay()", ".toLocalDate()", ".toLocalDateTime()", ".toLocalTime()", ".toSecondOfDay()", ".toNanoOfDay()", ".atStartOfDay()", ".lengthOfMonth()", ".lengthOfYear()", ".isLeapYear()", ".isLeap()", ".atEndOfMonth()":
				if mSuffix == ".getNano()" {
					if dur, ok := parsePainlessDuration(recVal); ok {
						rem := int64(dur % time.Second)
						if rem < 0 {
							rem += 1e9
						}
						return rem, nil
					}
				}
				if yr, ok := recVal.(painlessYear); ok {
					switch mSuffix {
					case ".getYear()":
						return yr.year, nil
					case ".isLeap()", ".isLeapYear()":
						return yr.isLeap(), nil
					case ".lengthOfYear()":
						return yr.length(), nil
					}
				}
				if md, ok := recVal.(painlessMonthDay); ok {
					switch mSuffix {
					case ".getMonth()":
						return md.getMonth(), nil
					case ".getMonthValue()", ".getMonthOfYear()":
						return md.getMonthValue(), nil
					case ".getDayOfMonth()":
						return md.getDayOfMonth(), nil
					}
				}
				if tm, ok := parsePainlessDateTime(recVal); ok {
					switch mSuffix {
					case ".getYear()":
						return int64(tm.Year()), nil
					case ".getMonthValue()", ".getMonthOfYear()":
						return int64(tm.Month()), nil
					case ".getMonth()":
						return strings.ToUpper(tm.Month().String()), nil
					case ".getDayOfMonth()", ".getDate()":
						return int64(tm.Day()), nil
					case ".getDayOfYear()":
						return int64(tm.YearDay()), nil
					case ".getHour()", ".getHourOfDay()":
						return int64(tm.Hour()), nil
					case ".getMinute()", ".getMinuteOfHour()":
						return int64(tm.Minute()), nil
					case ".getSecond()", ".getSecondOfMinute()":
						return int64(tm.Second()), nil
					case ".getNano()":
						return int64(tm.Nanosecond()), nil
					case ".getDayOfWeek()":
						dow := int64(tm.Weekday())
						if dow == 0 {
							dow = 7
						}
						return dow, nil
					case ".getDayOfWeekEnum()":
						return strings.ToUpper(tm.Weekday().String()), nil
					case ".getMillis()", ".toEpochMilli()":
						return tm.UnixMilli(), nil
					case ".getEpochSecond()":
						return tm.Unix(), nil
					case ".toEpochDay()":
						return time.Date(tm.Year(), tm.Month(), tm.Day(), 0, 0, 0, 0, time.UTC).Unix() / 86400, nil
					case ".toLocalDate()":
						return tm.Format("2006-01-02"), nil
					case ".toLocalDateTime()":
						if tm.Nanosecond() > 0 {
							return tm.Format("2006-01-02T15:04:05.999999999"), nil
						}
						return tm.Format("2006-01-02T15:04:05"), nil
					case ".toLocalTime()":
						return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), nil
					case ".toSecondOfDay()":
						return int64(tm.Hour()*3600 + tm.Minute()*60 + tm.Second()), nil
					case ".toNanoOfDay()":
						return int64(tm.Hour()*3600+tm.Minute()*60+tm.Second())*1_000_000_000 + int64(tm.Nanosecond()), nil
					case ".atStartOfDay()":
						return fmt.Sprintf("%04d-%02d-%02dT00:00", tm.Year(), int(tm.Month()), tm.Day()), nil
					case ".isLeapYear()", ".isLeap()":
						y := tm.Year()
						return y%4 == 0 && (y%100 != 0 || y%400 == 0), nil
					case ".lengthOfYear()":
						y := tm.Year()
						if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
							return int64(366), nil
						}
						return int64(365), nil
					case ".lengthOfMonth()":
						return int64(time.Date(tm.Year(), tm.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()), nil
					case ".atEndOfMonth()":
						lastDay := time.Date(tm.Year(), tm.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
						return fmt.Sprintf("%04d-%02d-%02d", tm.Year(), int(tm.Month()), lastDay), nil
					}
				}
				return nil, nil
			case ".keySet()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := visiblePainlessMapKeys(tv)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = k
					}
					return out, nil
				}
				return []any{}, nil
			case ".values()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := visiblePainlessMapKeys(tv)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = tv[k]
					}
					return out, nil
				}
				if tv, ok := recVal.([]any); ok {
					return tv, nil
				}
				return []any{}, nil
			case ".entrySet()":
				if tv, ok := recVal.(map[string]any); ok {
					keys := visiblePainlessMapKeys(tv)
					out := make([]any, len(keys))
					for i, k := range keys {
						out[i] = map[string]any{"key": k, "value": tv[k], "__parent_map": tv}
					}
					return out, nil
				}
				return []any{}, nil
			case ".getKey()":
				if tv, ok := recVal.(map[string]any); ok {
					return tv["key"], nil
				}
				return nil, nil
			case ".getValue()":
				if yr, ok := recVal.(painlessYear); ok {
					return yr.getValue(), nil
				}
				if tv, ok := recVal.(map[string]any); ok {
					return tv["value"], nil
				}
				if f, ok := toFloat64(recVal); ok {
					return int64(f), nil
				}
				if s, ok := recVal.(string); ok {
					switch strings.ToUpper(strings.TrimSpace(s)) {
					case "MONDAY", "JANUARY":
						return int64(1), nil
					case "TUESDAY", "FEBRUARY":
						return int64(2), nil
					case "WEDNESDAY", "MARCH":
						return int64(3), nil
					case "THURSDAY", "APRIL":
						return int64(4), nil
					case "FRIDAY", "MAY":
						return int64(5), nil
					case "SATURDAY", "JUNE":
						return int64(6), nil
					case "SUNDAY", "JULY":
						return int64(7), nil
					case "AUGUST":
						return int64(8), nil
					case "SEPTEMBER":
						return int64(9), nil
					case "OCTOBER":
						return int64(10), nil
					case "NOVEMBER":
						return int64(11), nil
					case "DECEMBER":
						return int64(12), nil
					}
				}
				return nil, nil
			case ".length()", ".size()":
				switch tv := recVal.(type) {
				case *painlessBitSet:
					if mSuffix == ".size()" {
						return tv.size(), nil
					}
					return tv.length(), nil
				case *painlessStringJoiner:
					return tv.length(), nil
				case painlessYear:
					return tv.length(), nil
				case *painlessStringBuilder:
					if tv == nil {
						return int64(0), nil
					}
					return int64(utf8.RuneCountInString(tv.buf)), nil
				case string:
					return int64(utf8.RuneCountInString(tv)), nil
				case []any:
					return int64(len(tv)), nil
				case map[string]any:
					return int64(visiblePainlessMapLen(tv)), nil
				}
			case ".pattern()":
				if pp, ok := recVal.(*painlessPattern); ok && pp != nil {
					return pp.raw, nil
				}
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && pm.re != nil {
					return pm.re.String(), nil
				}
				pat := fmt.Sprintf("%v", recVal)
				if isRawRegexLiteralPainless(pat) && len(pat) >= 2 && pat[0] == '/' && pat[len(pat)-1] == '/' {
					pat = strings.ReplaceAll(pat[1:len(pat)-1], `\/`, `/`)
				}
				return pat, nil
			case ".flags()":
				if pp, ok := recVal.(*painlessPattern); ok && pp != nil {
					return int64(pp.flags), nil
				}
				return int64(0), nil
			case ".clone()":
				switch tv := recVal.(type) {
				case *painlessBitSet:
					return tv.clone(), nil
				case []any:
					out := make([]any, len(tv))
					copy(out, tv)
					return out, nil
				case map[string]any:
					out := make(map[string]any, len(tv))
					for k, v := range tv {
						if !isInternalPainlessMapKey(tv, k) {
							out[k] = v
						}
					}
					return out, nil
				default:
					return recVal, nil
				}
			case ".getClass()":
				return painlessClassForValuePainless(recVal), nil
			case ".getName()", ".getCanonicalName()", ".getTypeName()":
				if cls, ok := recVal.(painlessClassObject); ok {
					return cls.fullName, nil
				}
				if m, ok := recVal.(map[string]any); ok {
					if v, exists := m["name"]; exists {
						return v, nil
					}
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".getSimpleName()":
				if cls, ok := recVal.(painlessClassObject); ok {
					return cls.simpleName, nil
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".name()":
				if cf, ok := recVal.(painlessChronoField); ok {
					return string(cf), nil
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".find()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					regStart := 0
					regEnd := len(pm.input)
					if pm.hasRegion {
						regStart = pm.regionStart
						regEnd = pm.regionEnd
					}
					if pm.curPos < regStart {
						pm.curPos = regStart
					}
					if pm.re == nil || pm.curPos > regEnd {
						pm.lastMatch = nil
						return false, nil
					}
					shifted := findSubmatchIndexFromPosPainless(pm.re, pm.input[:regEnd], pm.curPos)
					if shifted == nil {
						pm.lastMatch = nil
						pm.curPos = regEnd + 1
						return false, nil
					}
					pm.lastMatch = shifted
					if shifted[0] == shifted[1] {
						pm.curPos = shifted[1]
						if pm.curPos < regEnd {
							_, w := utf8.DecodeRuneInString(pm.input[pm.curPos:regEnd])
							if w <= 0 {
								w = 1
							}
							pm.curPos += w
						} else {
							pm.curPos++
						}
					} else {
						pm.curPos = shifted[1]
					}
					return true, nil
				}
				return false, nil
			case ".matches()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if pm.re == nil {
						return false, nil
					}
					regStart := 0
					regEnd := len(pm.input)
					if pm.hasRegion {
						regStart = pm.regionStart
						regEnd = pm.regionEnd
					}
					fullRe, err := regexp.Compile("^(?:" + pm.re.String() + ")$")
					if err != nil {
						return false, nil
					}
					loc := fullRe.FindStringSubmatchIndex(pm.input[regStart:regEnd])
					if loc == nil {
						pm.lastMatch = nil
						return false, nil
					}
					if regStart > 0 {
						for i := range loc {
							if loc[i] >= 0 {
								loc[i] += regStart
							}
						}
					}
					pm.lastMatch = loc
					pm.curPos = regEnd
					return true, nil
				}
				return false, nil
			case ".lookingAt()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if pm.re == nil {
						return false, nil
					}
					regStart := 0
					regEnd := len(pm.input)
					if pm.hasRegion {
						regStart = pm.regionStart
						regEnd = pm.regionEnd
					}
					prefixRe, err := regexp.Compile("^(?:" + pm.re.String() + ")")
					if err != nil {
						return false, nil
					}
					loc := prefixRe.FindStringSubmatchIndex(pm.input[regStart:regEnd])
					if loc == nil {
						pm.lastMatch = nil
						return false, nil
					}
					if regStart > 0 {
						for i := range loc {
							if loc[i] >= 0 {
								loc[i] += regStart
							}
						}
					}
					pm.lastMatch = loc
					pm.curPos = loc[1]
					return true, nil
				}
				return false, nil
			case ".group()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if len(pm.lastMatch) >= 2 && pm.lastMatch[0] >= 0 && pm.lastMatch[1] >= 0 {
						return pm.input[pm.lastMatch[0]:pm.lastMatch[1]], nil
					}
				}
				return nil, nil
			case ".groupCount()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && pm.re != nil {
					return int64(pm.re.NumSubexp()), nil
				}
				return int64(0), nil
			case ".start()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && len(pm.lastMatch) >= 2 && pm.lastMatch[0] >= 0 {
					return int64(utf8.RuneCountInString(pm.input[:pm.lastMatch[0]])), nil
				}
				return int64(-1), nil
			case ".end()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && len(pm.lastMatch) >= 2 && pm.lastMatch[1] >= 0 {
					return int64(utf8.RuneCountInString(pm.input[:pm.lastMatch[1]])), nil
				}
				return int64(-1), nil
			case ".regionStart()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if !pm.hasRegion {
						return int64(0), nil
					}
					return int64(utf8.RuneCountInString(pm.input[:pm.regionStart])), nil
				}
				return int64(0), nil
			case ".regionEnd()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if !pm.hasRegion {
						return int64(utf8.RuneCountInString(pm.input)), nil
					}
					return int64(utf8.RuneCountInString(pm.input[:pm.regionEnd])), nil
				}
				return int64(0), nil
			case ".reset()":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					pm.curPos = 0
					pm.lastMatch = nil
					pm.appendPos = 0
					pm.hasRegion = false
					pm.regionStart = 0
					pm.regionEnd = len(pm.input)
					return pm, nil
				}
				return recVal, nil
			}
		}
	}

	if strings.HasSuffix(rhs, ".isEmpty()") {
		recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(".isEmpty()")], "?"))
		if (strings.HasPrefix(recExpr, "doc.") || strings.HasPrefix(recExpr, "doc?.")) &&
			!strings.HasSuffix(recExpr, ".value") && !strings.Contains(recExpr, ".values.") {
			docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recExpr, "doc?."), "doc."), ".values")
			return len(resolveDocValuesSlice(sourceMap, docPath)) == 0, nil
		}
		var recVal any
		var err error
		if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
			recVal = sourceMap
		} else {
			recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		}
		if err != nil {
			return false, err
		}
		if recVal == painlessEmptyOptional {
			return true, nil
		}
		if recVal == nil {
			if !strings.HasSuffix(rhs, "?.isEmpty()") {
				if strings.HasPrefix(recExpr, "Optional.") {
					return true, nil
				}
				if params != nil && reIdentOnly.MatchString(recExpr) {
					if sl, ok := params["__script_locals"].(map[string]bool); ok && sl[recExpr] {
						return true, nil
					}
				}
			}
			return false, nil
		}
		switch tv := recVal.(type) {
		case *painlessUserObject:
			if tv != nil && tv.class != nil && tv.class.methods["isEmpty"] != nil {
				return evalUserObjectMethodPainless(tv, "isEmpty", "", sourceMap, params, depth+1)
			}
		case *painlessBitSet:
			return tv == nil || tv.length() == 0, nil
		case *painlessStringBuilder:
			return tv == nil || len(tv.buf) == 0, nil
		case string:
			return len(tv) == 0, nil
		case []any:
			return len(tv) == 0, nil
		case map[string]any:
			return visiblePainlessMapLen(tv) == 0, nil
		}
		return false, nil
	}

	for _, mName := range []string{
		".startsWith(", ".endsWith(", ".regionMatches(", ".containsAll(", ".removeAll(", ".retainAll(", ".removeIf(", ".forEach(", ".compute(", ".computeIfAbsent(", ".computeIfPresent(", ".merge(", ".contains(", ".containsKey(", ".containsValue(", ".getOrDefault(", ".getLong(", ".get(",
		".indexOf(", ".lastIndexOf(", ".charAt(", ".codePointAt(", ".getBytes(", ".repeat(", ".matches(", ".matcher(", ".find(", ".reset(", ".group(", ".start(", ".end(", ".replaceAll(", ".replaceFirst(",
		".appendReplacement(", ".appendTail(", ".region(",
		".append(", ".insert(", ".deleteCharAt(", ".delete(", ".setLength(", ".setCharAt(", ".subSequence(", ".ensureCapacity(",
		".encodeToString(", ".encode(", ".decode(",
		".splitOnToken(", ".split(", ".replace(", ".substring(", ".subList(", ".join(", ".format(",
		".equals(", ".equalsIgnoreCase(", ".compareTo(", ".compareToIgnoreCase(", ".concat(", ".remove(", ".setValue(", ".set(", ".addAll(", ".add(", ".putAll(", ".putIfAbsent(", ".put(", ".sort(",
		".plusYears(", ".minusYears(", ".plusMonths(", ".minusMonths(", ".plusWeeks(", ".minusWeeks(", ".plusDays(", ".minusDays(",
		".plusHours(", ".minusHours(", ".plusMinutes(", ".minusMinutes(", ".plusSeconds(", ".minusSeconds(", ".plusMillis(", ".minusMillis(", ".plusNanos(", ".minusNanos(",
		".plus(", ".minus(", ".multipliedBy(", ".atDay(", ".atMonthDay(", ".atMonth(", ".atYear(", ".atDate(", ".atTime(", ".atStartOfDay(", ".isValidYear(", ".isSupported(",
		".subtract(", ".multiply(", ".divide(", ".remainder(", ".pow(", ".setScale(", ".min(", ".max(",
		".withYear(", ".withMonth(", ".withDayOfMonth(", ".withHour(", ".withMinute(", ".withSecond(", ".withNano(", ".truncatedTo(",
		".withZoneSameInstant(", ".withZoneSameLocal(", ".withZone(", ".withLocale(", ".with(",
		".isAfter(", ".isBefore(", ".isEqual(",
		".orElse(", ".orElseGet(", ".orElseThrow(", ".ifPresent(", ".ifPresentOrElse(", ".or(", ".filter(", ".map(", ".flatMap(",
		".withPrefix(", ".withSuffix(", ".withDelimiter(", ".formatHex(", ".parseHex(", ".toHexDigits(", ".fromHexDigits(", ".fromHexDigitsToLong(", ".isHexDigit(", ".fromHexDigit(",
		".contentEquals(", ".formatted(",
		".floorKey(", ".ceilingKey(", ".lowerKey(", ".higherKey(", ".floorEntry(", ".ceilingEntry(", ".lowerEntry(", ".higherEntry(", ".headMap(", ".tailMap(", ".subMap(",
		".floor(", ".ceiling(", ".lower(", ".higher(", ".headSet(", ".tailSet(", ".subSet(",
		".offerFirst(", ".offerLast(", ".offer(", ".addFirst(", ".addLast(", ".push(", ".removeFirstOccurrence(", ".removeLastOccurrence(",
		".movePointLeft(", ".movePointRight(", ".scaleByPowerOfTen(", ".divideToIntegralValue(", ".divideAndRemainder(", ".round(", ".abs(", ".negate(",
		".mod(", ".modPow(", ".modInverse(", ".gcd(", ".and(", ".xor(", ".andNot(", ".shiftLeft(", ".shiftRight(",
		".testBit(", ".setBit(", ".clearBit(", ".flipBit(", ".isProbablePrime(", ".toString(",
		".clear(", ".flip(", ".nextSetBit(", ".nextClearBit(", ".previousSetBit(", ".previousClearBit(", ".intersects(",
		".setEmptyValue(",
		".until(", ".datesUntil(", ".between(",
		".thenComparing(", ".thenComparingInt(", ".thenComparingLong(", ".thenComparingDouble(", ".compare(",
	} {
		if recExpr, argExpr, ok := matchTrailingMethodCallPainless(rhs, mName); ok {
			if (mName == ".equals(" && (recExpr == "Objects" || recExpr == "Arrays")) ||
				(mName == ".compare(" && (recExpr == "Integer" || recExpr == "Long" || recExpr == "Short" || recExpr == "Byte" || recExpr == "Double" || recExpr == "Float" || recExpr == "Boolean" || recExpr == "Character" || recExpr == "Arrays" || recExpr == "Objects")) ||
				(mName == ".toString(" && (recExpr == "Arrays" || recExpr == "Objects" || recExpr == "Integer" || recExpr == "Long" || recExpr == "Short" || recExpr == "Byte" || recExpr == "Double" || recExpr == "Float" || recExpr == "Boolean" || recExpr == "Character")) ||
				(mName == ".codePointAt(" && recExpr == "Character") ||
				(mName == ".between(" && (recExpr == "Duration" || recExpr == "Period" || strings.HasPrefix(recExpr, "ChronoUnit.") || strings.HasPrefix(recExpr, "java.time.temporal.ChronoUnit."))) ||
				((mName == ".abs(" || mName == ".round(") && (recExpr == "Math" || recExpr == "StrictMath")) ||
				(mName == ".replaceAll(" && recExpr == "Collections") ||
				(mName == ".matches(" && recExpr == "Pattern") ||
				(mName == ".format(" && recExpr == "String") ||
				(mName == ".join(" && recExpr == "String") ||
				(mName == ".concat(" && (recExpr == "Stream" || recExpr == "IntStream" || recExpr == "LongStream" || recExpr == "DoubleStream")) ||
				((mName == ".decode(" || mName == ".encode(") && (recExpr == "Integer" || recExpr == "Long" || recExpr == "Short" || recExpr == "Byte" || recExpr == "URLDecoder" || recExpr == "URLEncoder")) ||
				((mName == ".fromHexDigits(" || mName == ".fromHexDigitsToLong(" || mName == ".isHexDigit(" || mName == ".fromHexDigit(") && (recExpr == "HexFormat" || recExpr == "java.util.HexFormat")) ||
				((mName == ".min(" || mName == ".max(" || mName == ".pow(" || mName == ".floor(") && (recExpr == "Math" || recExpr == "StrictMath" || recExpr == "Collections" || recExpr == "Integer" || recExpr == "Long" || recExpr == "Double" || recExpr == "Float")) {
				continue
			}
			if b := getOrInitEvalBudget(params); b != nil && len(b.userClasses) > 0 {
				mBare := strings.TrimSuffix(strings.TrimPrefix(mName, "."), "(")
				if uVal, uErr := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); uErr == nil {
					if uo, isUO := uVal.(*painlessUserObject); isUO && uo != nil && uo.class != nil && uo.class.methods[mBare] != nil {
						return evalUserObjectMethodPainless(uo, mBare, argExpr, sourceMap, params, depth+1)
					}
				}
			}
			_, hasRawSrcRec := rawSourceFromSourceMapPainless(sourceMap)
			if !hasRawSrcRec {
				if recExpr == "params._source" || recExpr == "params?._source" || recExpr == "params._source?" || recExpr == "params?._source?" {
					recExpr = "ctx._source"
				} else {
					for _, pfx := range []string{"params?._source?.", "params?._source.", "params._source?.", "params._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							recExpr = "ctx._source." + strings.TrimPrefix(recExpr, pfx)
							break
						}
					}
				}
			}
			if mName == ".forEach(" {
				if err := execPainlessForEach(recExpr, argExpr, sourceMap, params, depth+1); err != nil {
					return nil, err
				}
				return nil, nil
			}
			if mName == ".replaceAll(" && (findNextUnquotedSubstr(argExpr, "->", 0) > 0 || findTopLevelSubstrPainless(argExpr, "::") > 0) && len(splitTopLevelCommaPainless(argExpr)) == 1 {
				if handled, err := execPainlessListReplaceAll(recExpr, argExpr, sourceMap, params, depth+1); err != nil {
					return nil, err
				} else if handled {
					return nil, nil
				}
			}
			if mName == ".compute(" || mName == ".computeIfAbsent(" || mName == ".computeIfPresent(" || mName == ".merge(" {
				if mName == ".merge(" && len(splitTopLevelCommaPainless(argExpr)) == 1 {
					if recVal, rErr := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); rErr == nil {
						if sj, isSJ := recVal.(*painlessStringJoiner); isSJ && sj != nil {
							otherVal, oErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
							if oErr != nil {
								return nil, oErr
							}
							if otherSJ, isOSJ := otherVal.(*painlessStringJoiner); isOSJ && otherSJ != nil {
								if len(otherSJ.parts) > 0 {
									sj.parts = append(sj.parts, strings.Join(otherSJ.parts, otherSJ.delim))
									sj.hasValue = true
								}
							}
							return sj, nil
						}
					}
				}
				return evalPainlessMapCompute(mName, recExpr, argExpr, sourceMap, params, depth+1)
			}
			if mName == ".removeIf(" {
				argExpr = normalizeMethodReferenceToLambdaPainless(argExpr, 1)
				arrowIdx := strings.Index(argExpr, "->")
				if arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
					if len(pNames) == 0 {
						return false, nil
					}
					paramName := pNames[0]
					condExpr := strings.TrimSpace(argExpr[arrowIdx+2:])
					if !strings.Contains(recExpr, "(") {
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								arrPath := strings.Split(relPath, ".")
								changed, err := removeIfCondFromSlice(sourceMap, sourceMap, arrPath, paramName, condExpr, params)
								if err != nil {
									return nil, err
								}
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								return changed, nil
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
						if len(arrPath) > 0 {
							rootVar := decodeBracketSeg(arrPath[0])
							if _, exists := params[rootVar]; exists {
								changed, err := removeIfCondFromSlice(sourceMap, params, arrPath, paramName, condExpr, params)
								if err != nil {
									return nil, err
								}
								syncLocalVarAlias(sourceMap, params, rootVar)
								return changed, nil
							}
						}
					}
					if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
						if arr, ok := recVal.([]any); ok {
							tmpMap := map[string]any{"_arr": arr}
							changed, err := removeIfCondFromSlice(sourceMap, tmpMap, []string{"_arr"}, paramName, condExpr, params)
							if err != nil {
								return nil, err
							}
							if changed && writeBack != nil {
								if updated, okUp := tmpMap["_arr"].([]any); okUp {
									writeBack(updated)
								}
							}
							return changed, nil
						}
					}
				}
				return false, nil
			}
			if mName == ".removeAll(" || mName == ".retainAll(" {
				isRetain := mName == ".retainAll("
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if !strings.Contains(recExpr, "(") {
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							arrPath := strings.Split(relPath, ".")
							changed := mutateSliceRemoveOrRetainAtPath(sourceMap, arrPath, argVal, isRetain)
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return changed, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							changed := mutateSliceRemoveOrRetainAtPath(params, arrPath, argVal, isRetain)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return changed, nil
						}
					}
				}
				if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
					if arr, ok := recVal.([]any); ok {
						tmpMap := map[string]any{"_arr": arr}
						changed := mutateSliceRemoveOrRetainAtPath(tmpMap, []string{"_arr"}, argVal, isRetain)
						if changed && writeBack != nil {
							if updated, okUp := tmpMap["_arr"].([]any); okUp {
								writeBack(updated)
							}
						}
						return changed, nil
					}
				}
			}
			if mName == ".remove(" {
				if remArgs := splitTopLevelCommaPainless(argExpr); len(remArgs) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[0]), params, depth+1)
					vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[1]), params, depth+1)
					if !strings.Contains(recExpr, "(") {
						if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil && kVal != nil {
							keyStr := fmt.Sprintf("%v", kVal)
							switch keyStr {
							case "_id", "_index", "_routing", "_version":
								metaKey, err := checkCtxMetaLHS([]string{"ctx", keyStr}, sourceMap, params)
								if err != nil {
									return nil, err
								}
								if valuesEqual(params[metaKey], vVal) {
									_, err := mutateCtxDirectMapKey(keyStr, nil, true, false, sourceMap, params)
									return err == nil, err
								}
								return false, nil
							case "op":
								cur := params["_ctx_op"]
								if cur == nil {
									cur = "index"
								}
								if valuesEqual(cur, vVal) {
									_, err := mutateCtxDirectMapKey("op", nil, true, false, sourceMap, params)
									return err == nil, err
								}
								return false, nil
							default:
								return removeKeyValueAtPath(sourceMap, nil, kVal, vVal), nil
							}
						}
						if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
							return removeKeyValueAtPath(sourceMap, nil, kVal, vVal), nil
						}
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								parentPath := strings.Split(relPath, ".")
								removed := removeKeyValueAtPath(sourceMap, parentPath, kVal, vVal)
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								return removed, nil
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						rawPath := strings.Split(cleanRec, ".")
						parentPath := normalizeLocalLHSPath(rawPath, params)
						if len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
							removed := removeKeyValueAtPath(params, nil, kVal, vVal)
							if removed && kVal != nil {
								unmarkExplicitParamsKey(params, fmt.Sprintf("%v", kVal))
							}
							return removed, nil
						}
						if len(parentPath) > 0 {
							rootVar := decodeBracketSeg(parentPath[0])
							if _, exists := params[rootVar]; exists {
								removed := removeKeyValueAtPath(params, parentPath, kVal, vVal)
								syncLocalVarAlias(sourceMap, params, rootVar)
								return removed, nil
							}
						}
					}
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok && m != nil {
							return removeKeyValueAtPath(m, nil, kVal, vVal), nil
						}
					}
					return false, nil
				}
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if !strings.Contains(recExpr, "(") {
					if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil && argVal != nil {
						return mutateCtxDirectMapKey(fmt.Sprintf("%v", argVal), nil, true, false, sourceMap, params)
					}
					if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
						return removeKeyOrIndexAtPath(sourceMap, nil, argVal), nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							parentPath := strings.Split(relPath, ".")
							removed := removeKeyOrIndexAtPath(sourceMap, parentPath, argVal)
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return removed, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					rawPath := strings.Split(cleanRec, ".")
					parentPath := normalizeLocalLHSPath(rawPath, params)
					if len(parentPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
						removed := removeKeyOrIndexAtPath(params, nil, argVal)
						if argVal != nil {
							unmarkExplicitParamsKey(params, fmt.Sprintf("%v", argVal))
						}
						return removed, nil
					}
					if len(parentPath) > 0 {
						rootVar := decodeBracketSeg(parentPath[0])
						if _, exists := params[rootVar]; exists {
							removed := removeKeyOrIndexAtPath(params, parentPath, argVal)
							syncLocalVarAlias(sourceMap, params, rootVar)
							return removed, nil
						}
					}
				}
				if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
					switch tv := recVal.(type) {
					case map[string]any:
						return removeKeyOrIndexAtPath(tv, nil, argVal), nil
					case []any:
						tmpMap := map[string]any{"_arr": tv}
						removed := removeKeyOrIndexAtPath(tmpMap, []string{"_arr"}, argVal)
						if writeBack != nil {
							if updated, okUp := tmpMap["_arr"].([]any); okUp {
								writeBack(updated)
							}
						}
						return removed, nil
					}
				}
				return nil, nil
			}
			if mName == ".set(" {
				setArgs := splitTopLevelCommaPainless(argExpr)
				if recVal, rErr := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); rErr == nil {
					if bs, isBS := recVal.(*painlessBitSet); isBS && bs != nil {
						if len(setArgs) == 1 {
							v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[0]), params, depth+1)
							if err0 != nil {
								return nil, err0
							}
							idx, _ := toInt64Painless(v0)
							return nil, bs.set(int(idx))
						} else if len(setArgs) == 2 {
							v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[0]), params, depth+1)
							if err0 != nil {
								return nil, err0
							}
							v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[1]), params, depth+1)
							if err1 != nil {
								return nil, err1
							}
							idx0, _ := toInt64Painless(v0)
							if bVal, isBool := v1.(bool); isBool {
								if bVal {
									return nil, bs.set(int(idx0))
								}
								return nil, bs.clearBit(int(idx0))
							}
							idx1, _ := toInt64Painless(v1)
							return nil, bs.setRange(int(idx0), int(idx1), true)
						} else if len(setArgs) >= 3 {
							v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[0]), params, depth+1)
							if err0 != nil {
								return nil, err0
							}
							v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[1]), params, depth+1)
							if err1 != nil {
								return nil, err1
							}
							v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[2]), params, depth+1)
							if err2 != nil {
								return nil, err2
							}
							idx0, _ := toInt64Painless(v0)
							idx1, _ := toInt64Painless(v1)
							bVal, _ := v2.(bool)
							return nil, bs.setRange(int(idx0), int(idx1), bVal)
						}
						return nil, nil
					}
				}
				if len(setArgs) == 2 {
					idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[0]), params, depth+1)
					newVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(setArgs[1]), params, depth+1)
					if !strings.Contains(recExpr, "(") {
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								arrPath := strings.Split(relPath, ".")
								prev := setSliceElementAtPath(sourceMap, arrPath, idxVal, newVal)
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								return prev, nil
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
						if len(arrPath) > 0 {
							rootVar := decodeBracketSeg(arrPath[0])
							if _, exists := params[rootVar]; exists {
								prev := setSliceElementAtPath(params, arrPath, idxVal, newVal)
								syncLocalVarAlias(sourceMap, params, rootVar)
								return prev, nil
							}
						}
					}
					if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
						if arr, ok := recVal.([]any); ok {
							tmpMap := map[string]any{"_arr": arr}
							prev := setSliceElementAtPath(tmpMap, []string{"_arr"}, idxVal, newVal)
							if writeBack != nil {
								if updated, okUp := tmpMap["_arr"].([]any); okUp {
									writeBack(updated)
								}
							}
							return prev, nil
						}
					}
				}
			}
			if mName == ".addAll(" {
				if addAllArgs := splitTopLevelCommaPainless(argExpr); len(addAllArgs) == 2 {
					idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addAllArgs[0]), params, depth+1)
					argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addAllArgs[1]), params, depth+1)
					items, _ := argVal.([]any)
					budget := getOrInitEvalBudget(params)
					if !strings.Contains(recExpr, "(") {
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								arrPath := strings.Split(relPath, ".")
								changed, err := insertAllIntoSliceAtPath(sourceMap, arrPath, idxVal, items, budget)
								if err != nil {
									return nil, err
								}
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								return changed, nil
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
						if len(arrPath) > 0 {
							rootVar := decodeBracketSeg(arrPath[0])
							if _, exists := params[rootVar]; exists {
								changed, err := insertAllIntoSliceAtPath(params, arrPath, idxVal, items, budget)
								if err != nil {
									return nil, err
								}
								syncLocalVarAlias(sourceMap, params, rootVar)
								return changed, nil
							}
						}
					}
					if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
						if arr, ok := recVal.([]any); ok {
							tmpMap := map[string]any{"_arr": arr}
							changed, err := insertAllIntoSliceAtPath(tmpMap, []string{"_arr"}, idxVal, items, budget)
							if err != nil {
								return nil, err
							}
							if changed && writeBack != nil {
								if updated, okUp := tmpMap["_arr"].([]any); okUp {
									writeBack(updated)
								}
							}
							return changed, nil
						}
					}
					return false, nil
				}
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				items, _ := argVal.([]any)
				if !strings.Contains(recExpr, "(") {
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							arrPath := strings.Split(relPath, ".")
							changed := false
							for _, item := range append([]any(nil), items...) {
								if err := appendToSlice(sourceMap, arrPath, item); err != nil {
									return nil, err
								}
								changed = true
							}
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return changed, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							changed := false
							for _, item := range append([]any(nil), items...) {
								if err := appendToSlice(params, arrPath, item); err != nil {
									return nil, err
								}
								changed = true
							}
							syncLocalVarAlias(sourceMap, params, rootVar)
							return changed, nil
						}
					}
				}
				if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
					if arr, ok := recVal.([]any); ok {
						tmpMap := map[string]any{"_arr": arr}
						changed := false
						for _, item := range append([]any(nil), items...) {
							if err := appendToSlice(tmpMap, []string{"_arr"}, item); err != nil {
								return nil, err
							}
							changed = true
						}
						if changed && writeBack != nil {
							if updated, okUp := tmpMap["_arr"].([]any); okUp {
								writeBack(updated)
							}
						}
						return changed, nil
					}
				}
				return false, nil
			}
			if mName == ".add(" {
				addArgs := splitTopLevelCommaPainless(argExpr)
				if bdRec, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
					if bd, isBD := bdRec.(*painlessBigDecimal); isBD && bd != nil {
						if len(addArgs) == 0 {
							return bd, nil
						}
						augVal, aErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
						if aErr != nil {
							return nil, aErr
						}
						if bd2, ok2 := parsePainlessBigDecimal(augVal); ok2 {
							ua, ub, sc := alignBigDecimalsPainless(bd, bd2)
							resBD := &painlessBigDecimal{unscaled: new(big.Int).Add(ua, ub), scale: sc}
							if len(addArgs) >= 2 {
								mcVal, mcErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
								if mcErr != nil {
									return nil, mcErr
								}
								if mc, isMC := mcVal.(painlessMathContext); isMC {
									return applyMathContextPainless(resBD, mc)
								}
							}
							return resBD, nil
						}
						return bd, nil
					}
					if bi, isBI := bdRec.(*painlessBigInteger); isBI && bi != nil {
						augVal, aErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if aErr != nil {
							return nil, aErr
						}
						if bi2, ok2 := parsePainlessBigInteger(augVal); ok2 {
							return newPainlessBigInteger(new(big.Int).Add(bi.val, bi2.val)), nil
						}
						return bi, nil
					}
					if sj, isSJ := bdRec.(*painlessStringJoiner); isSJ && sj != nil {
						elVal, eErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if eErr != nil {
							return nil, eErr
						}
						if elVal == nil {
							sj.parts = append(sj.parts, "null")
						} else {
							sj.parts = append(sj.parts, fmt.Sprintf("%v", elVal))
						}
						sj.hasValue = true
						return sj, nil
					}
				}
				if !strings.Contains(recExpr, "(") {
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							arrPath := strings.Split(relPath, ".")
							if len(addArgs) == 2 {
								idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
								valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
								if err := insertIntoSliceAtPath(sourceMap, arrPath, idxVal, valToAdd); err != nil {
									return nil, err
								}
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								return true, nil
							}
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
							if err := appendToSlice(sourceMap, arrPath, valToAdd); err != nil {
								return nil, err
							}
							syncSourceAliasToLocalVars(sourceMap, params, relPath)
							return true, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
					if len(arrPath) > 0 {
						rootVar := decodeBracketSeg(arrPath[0])
						if _, exists := params[rootVar]; exists {
							if len(addArgs) == 2 {
								idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
								valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
								if err := insertIntoSliceAtPath(params, arrPath, idxVal, valToAdd); err != nil {
									return nil, err
								}
								syncLocalVarAlias(sourceMap, params, rootVar)
								return true, nil
							}
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
							if err := appendToSlice(params, arrPath, valToAdd); err != nil {
								return nil, err
							}
							syncLocalVarAlias(sourceMap, params, rootVar)
							return true, nil
						}
					}
				}
				if recVal, writeBack, err := resolveMutableReceiverPainless(sourceMap, recExpr, params, depth+1); err == nil {
					if arr, ok := recVal.([]any); ok {
						tmpMap := map[string]any{"_arr": arr}
						if len(addArgs) == 2 {
							idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[0]), params, depth+1)
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(addArgs[1]), params, depth+1)
							if err := insertIntoSliceAtPath(tmpMap, []string{"_arr"}, idxVal, valToAdd); err != nil {
								return nil, err
							}
						} else {
							valToAdd, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
							if err := appendToSlice(tmpMap, []string{"_arr"}, valToAdd); err != nil {
								return nil, err
							}
						}
						if writeBack != nil {
							if updated, okUp := tmpMap["_arr"].([]any); okUp {
								writeBack(updated)
							}
						}
						return true, nil
					}
				}
				return true, nil
			}
			if mName == ".putAll(" {
				argVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				subMap, isSubMap := argVal.(map[string]any)
				if !strings.Contains(recExpr, "(") {
					if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
						if isSubMap {
							for k, v := range subMap {
								if _, err := mutateCtxDirectMapKey(k, v, false, false, sourceMap, params); err != nil {
									return nil, err
								}
							}
						}
						return nil, nil
					}
					if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
						if isSubMap {
							putAllAtPath(sourceMap, nil, subMap)
							for k := range subMap {
								syncSourceAliasToLocalVars(sourceMap, params, k)
							}
						}
						return nil, nil
					}
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(recExpr, pfx) {
							relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
							targetPath := strings.Split(relPath, ".")
							if isSubMap {
								putAllAtPath(sourceMap, targetPath, subMap)
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								for k := range subMap {
									syncSourceAliasToLocalVars(sourceMap, params, relPath+"."+k)
								}
							}
							return nil, nil
						}
					}
					cleanRec := strings.TrimSuffix(recExpr, "?")
					rawPath := strings.Split(cleanRec, ".")
					targetPath := normalizeLocalLHSPath(rawPath, params)
					if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
						if isSubMap {
							putAllAtPath(params, nil, subMap)
							for k := range subMap {
								markExplicitParamsKey(params, k)
							}
						}
						return nil, nil
					}
					if len(targetPath) > 0 {
						rootVar := decodeBracketSeg(targetPath[0])
						if _, exists := params[rootVar]; exists {
							if isSubMap {
								putAllAtPath(params, targetPath, subMap)
								syncLocalVarAlias(sourceMap, params, rootVar)
							}
							return nil, nil
						}
					}
				}
				if isSubMap {
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok && m != nil {
							putAllAtPath(m, nil, subMap)
						}
					}
				}
				return nil, nil
			}
			if mName == ".put(" {
				putArgs := splitTopLevelCommaPainless(argExpr)
				if len(putArgs) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[0]), params, depth+1)
					vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[1]), params, depth+1)
					keyStr := fmt.Sprintf("%v", kVal)
					encKey := encodeBracketKey(keyStr)
					if !strings.Contains(recExpr, "(") {
						if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
							return mutateCtxDirectMapKey(keyStr, vVal, false, false, sourceMap, params)
						}
						if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
							prev := resolveParamPath(sourceMap, []string{encKey})
							setValueAtPath(sourceMap, []string{encKey}, vVal)
							syncSourceAliasToLocalVars(sourceMap, params, keyStr)
							return prev, nil
						}
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								targetPath := strings.Split(relPath, ".")
								fullKeyPath := append(targetPath, encKey)
								var prev any
								if tm, ok := resolveParamPath(sourceMap, targetPath).(map[string]any); ok && tm != nil {
									prev = tm[keyStr]
									tm[keyStr] = vVal
								} else {
									prev = resolveParamPath(sourceMap, fullKeyPath)
									setValueAtPath(sourceMap, fullKeyPath, vVal)
								}
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
								return prev, nil
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						rawPath := strings.Split(cleanRec, ".")
						targetPath := normalizeLocalLHSPath(rawPath, params)
						if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
							prev := params[keyStr]
							params[keyStr] = vVal
							markExplicitParamsKey(params, keyStr)
							return prev, nil
						}
						if len(targetPath) > 0 {
							rootVar := decodeBracketSeg(targetPath[0])
							if _, exists := params[rootVar]; exists {
								fullKeyPath := append(targetPath, encKey)
								var prev any
								if tm, ok := resolveParamPath(params, targetPath).(map[string]any); ok && tm != nil {
									prev = tm[keyStr]
									tm[keyStr] = vVal
								} else {
									prev = resolveParamPath(params, fullKeyPath)
									setValueAtPath(params, fullKeyPath, vVal)
								}
								syncLocalVarAlias(sourceMap, params, rootVar)
								return prev, nil
							}
						}
					}
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok && m != nil {
							prev := m[keyStr]
							m[keyStr] = vVal
							return prev, nil
						}
					}
				}
				return nil, nil
			}
			if mName == ".putIfAbsent(" {
				putArgs := splitTopLevelCommaPainless(argExpr)
				if len(putArgs) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[0]), params, depth+1)
					vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(putArgs[1]), params, depth+1)
					keyStr := fmt.Sprintf("%v", kVal)
					encKey := encodeBracketKey(keyStr)
					if !strings.Contains(recExpr, "(") {
						if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
							return mutateCtxDirectMapKey(keyStr, vVal, false, true, sourceMap, params)
						}
						if recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
							prev := resolveParamPath(sourceMap, []string{encKey})
							if prev == nil {
								setValueAtPath(sourceMap, []string{encKey}, vVal)
								syncSourceAliasToLocalVars(sourceMap, params, keyStr)
							}
							return prev, nil
						}
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								targetPath := strings.Split(relPath, ".")
								fullKeyPath := append(targetPath, encKey)
								var prev any
								if tm, ok := resolveParamPath(sourceMap, targetPath).(map[string]any); ok && tm != nil {
									prev = tm[keyStr]
									if prev == nil {
										tm[keyStr] = vVal
										syncSourceAliasToLocalVars(sourceMap, params, relPath)
										syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
									}
								} else {
									prev = resolveParamPath(sourceMap, fullKeyPath)
									if prev == nil {
										setValueAtPath(sourceMap, fullKeyPath, vVal)
										syncSourceAliasToLocalVars(sourceMap, params, relPath)
										syncSourceAliasToLocalVars(sourceMap, params, strings.Join(fullKeyPath, "."))
									}
								}
								return prev, nil
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						rawPath := strings.Split(cleanRec, ".")
						targetPath := normalizeLocalLHSPath(rawPath, params)
						if len(targetPath) == 0 && len(rawPath) == 1 && decodeBracketSeg(rawPath[0]) == "params" {
							prev := params[keyStr]
							if prev == nil {
								params[keyStr] = vVal
								markExplicitParamsKey(params, keyStr)
							}
							return prev, nil
						}
						if len(targetPath) > 0 {
							rootVar := decodeBracketSeg(targetPath[0])
							if _, exists := params[rootVar]; exists {
								fullKeyPath := append(targetPath, encKey)
								var prev any
								if tm, ok := resolveParamPath(params, targetPath).(map[string]any); ok && tm != nil {
									prev = tm[keyStr]
									if prev == nil {
										tm[keyStr] = vVal
										syncLocalVarAlias(sourceMap, params, rootVar)
									}
								} else {
									prev = resolveParamPath(params, fullKeyPath)
									if prev == nil {
										setValueAtPath(params, fullKeyPath, vVal)
										syncLocalVarAlias(sourceMap, params, rootVar)
									}
								}
								return prev, nil
							}
						}
					}
					if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
						if m, ok := recVal.(map[string]any); ok {
							prev := m[keyStr]
							if prev == nil {
								m[keyStr] = vVal
							}
							return prev, nil
						}
					}
				}
				return nil, nil
			}
			if mName == ".sort(" {
				if recExpr == "Collections" || recExpr == "Arrays" {
					continue
				}
				if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil {
					if arr, ok := recVal.([]any); ok {
						if err := sortPainlessSliceInPlace(arr, argExpr, sourceMap, params, depth+1); err != nil {
							return nil, err
						}
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								break
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
						if len(arrPath) > 0 {
							rootVar := decodeBracketSeg(arrPath[0])
							if _, exists := params[rootVar]; exists {
								syncLocalVarAlias(sourceMap, params, rootVar)
							}
						}
						return nil, nil
					}
				}
				return nil, nil
			}
			if mName == ".containsKey(" && (recExpr == "doc" || recExpr == "doc?") {
				argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
				if argVal == nil {
					return false, nil
				}
				fieldPath := fmt.Sprintf("%v", argVal)
				if len(resolveDocValuesSlice(sourceMap, fieldPath)) > 0 {
					return true, nil
				}
				cleanPath := strings.TrimSuffix(fieldPath, ".keyword")
				return resolveParamPath(sourceMap, strings.Split(cleanPath, ".")) != nil, nil
			}
			var recVal any
			var err error
			if (mName == ".containsAll(" || mName == ".contains(" || mName == ".indexOf(" || mName == ".lastIndexOf(" || mName == ".get(" || mName == ".subList(" || mName == ".join(") &&
				(strings.HasPrefix(recExpr, "doc.") || strings.HasPrefix(recExpr, "doc?.")) &&
				!strings.HasSuffix(recExpr, ".value") && !strings.Contains(recExpr, ".value.") && !strings.Contains(recExpr, ".values.") && !strings.Contains(recExpr, "(") {
				docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(recExpr, "doc?."), "doc."), ".values")
				recVal = resolveDocValuesSlice(sourceMap, docPath)
			} else if (mName == ".containsValue(" || mName == ".replace(" || mName == ".replaceAll(") &&
				(recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
				recVal = sourceMap
			} else {
				recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			}
			if err != nil {
				if mName == ".startsWith(" || mName == ".endsWith(" || mName == ".regionMatches(" || mName == ".containsAll(" || mName == ".removeAll(" || mName == ".retainAll(" || mName == ".contains(" || mName == ".containsKey(" || mName == ".containsValue(" || mName == ".matches(" || mName == ".find(" || mName == ".equals(" || mName == ".equalsIgnoreCase(" || mName == ".isAfter(" || mName == ".isBefore(" || mName == ".isEqual(" || mName == ".isSupported(" || mName == ".isValidYear(" || mName == ".contentEquals(" || mName == ".testBit(" || mName == ".isProbablePrime(" || mName == ".intersects(" {
					return false, err
				}
				return nil, err
			}
			if mName == ".get(" && strings.TrimSpace(argExpr) == "" && isEmptyOptionalOrNilPainless(recVal) {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
			}
			if isEmptyOptionalOrNilPainless(recVal) && mName != ".orElse(" && mName != ".orElseGet(" && mName != ".orElseThrow(" && mName != ".ifPresent(" && mName != ".ifPresentOrElse(" && mName != ".or(" && mName != ".filter(" && mName != ".map(" && mName != ".flatMap(" {
				if mName == ".startsWith(" || mName == ".endsWith(" || mName == ".regionMatches(" || mName == ".containsAll(" || mName == ".removeAll(" || mName == ".retainAll(" || mName == ".contains(" || mName == ".containsKey(" || mName == ".containsValue(" || mName == ".matches(" || mName == ".find(" || mName == ".equals(" || mName == ".equalsIgnoreCase(" || mName == ".isAfter(" || mName == ".isBefore(" || mName == ".isEqual(" || mName == ".isSupported(" || mName == ".isValidYear(" || mName == ".contentEquals(" || mName == ".testBit(" || mName == ".isProbablePrime(" || mName == ".intersects(" {
					return false, nil
				}
				return nil, nil
			}
			switch mName {
			case ".subList(":
				args := splitTopLevelCommaPainless(argExpr)
				if tv, ok := recVal.([]any); ok && len(args) >= 2 {
					sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					eVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					sf, sOk := toFloat64(sVal)
					ef, eOk := toFloat64(eVal)
					if sOk && eOk {
						start, end := int(sf), int(ef)
						if start < 0 {
							start = 0
						}
						if start > len(tv) {
							start = len(tv)
						}
						if end < start {
							end = start
						}
						if end > len(tv) {
							end = len(tv)
						}
						sub := make([]any, end-start)
						copy(sub, tv[start:end])
						return sub, nil
					}
				}
				return []any{}, nil
			case ".getOrDefault(":
				args := splitTopLevelCommaPainless(argExpr)
				if len(args) == 2 {
					kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					defVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
						if kVal != nil {
							if v, exists := lookupCtxMapKeyPainless(fmt.Sprintf("%v", kVal), sourceMap, params); exists && v != nil {
								return v, nil
							}
						}
						return defVal, nil
					}
					if tv, ok := recVal.(map[string]any); ok {
						if kVal != nil {
							kStr := fmt.Sprintf("%v", kVal)
							if !isInternalPainlessMapKey(tv, kStr) {
								if v, exists := tv[kStr]; exists && v != nil {
									return v, nil
								}
							}
						}
						return defVal, nil
					}
				}
				return nil, nil
			case ".regionMatches(":
				args := splitTopLevelCommaPainless(argExpr)
				if s, ok := recVal.(string); ok && (len(args) == 4 || len(args) == 5) {
					ignoreCase := false
					offsetIdx := 0
					if len(args) == 5 {
						icVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if b, bOk := icVal.(bool); bOk {
							ignoreCase = b
						} else if icVal != nil {
							ignoreCase = strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", icVal)), "true")
						}
						offsetIdx = 1
					}
					toffVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[offsetIdx]), params, depth+1)
					otherVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[offsetIdx+1]), params, depth+1)
					ooffVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[offsetIdx+2]), params, depth+1)
					lenVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[offsetIdx+3]), params, depth+1)
					tf, tOk := toFloat64(toffVal)
					of, oOk := toFloat64(ooffVal)
					lf, lOk := toFloat64(lenVal)
					if !tOk || !oOk || !lOk || otherVal == nil {
						return false, nil
					}
					toff, ooff, rlen := int(tf), int(of), int(lf)
					sRunes := []rune(s)
					oRunes := []rune(fmt.Sprintf("%v", otherVal))
					if toff < 0 || ooff < 0 || rlen < 0 || toff+rlen > len(sRunes) || ooff+rlen > len(oRunes) {
						return false, nil
					}
					sub1 := string(sRunes[toff : toff+rlen])
					sub2 := string(oRunes[ooff : ooff+rlen])
					if ignoreCase {
						return strings.EqualFold(sub1, sub2), nil
					}
					return sub1 == sub2, nil
				}
				return false, nil
			case ".replace(":
				args := splitTopLevelCommaPainless(argExpr)
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					if len(args) == 3 {
						sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						eVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						replVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
						sf, sOk := toFloat64(sVal)
						ef, eOk := toFloat64(eVal)
						if sOk && eOk {
							runes := []rune(sb.buf)
							start, end := int(sf), int(ef)
							if start < 0 {
								start = 0
							}
							if start > len(runes) {
								start = len(runes)
							}
							if end < start {
								end = start
							}
							if end > len(runes) {
								end = len(runes)
							}
							replStr := "null"
							if replVal != nil {
								replStr = fmt.Sprintf("%v", replVal)
							}
							next := string(runes[:start]) + replStr + string(runes[end:])
							if len(next) > MaxPainlessStringBytes {
								next = next[:MaxPainlessStringBytes]
							}
							sb.buf = next
						}
					}
					return sb, nil
				}
				if recMap, isMap := recVal.(map[string]any); isMap && recMap != nil {
					syncReplacedMap := func(keyStr string) {
						if ((recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil) ||
							recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
							syncSourceAliasToLocalVars(sourceMap, params, keyStr)
							return
						}
						for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
							if strings.HasPrefix(recExpr, pfx) {
								relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
								syncSourceAliasToLocalVars(sourceMap, params, relPath)
								if keyStr != "" {
									syncSourceAliasToLocalVars(sourceMap, params, relPath+"."+keyStr)
								}
								return
							}
						}
						cleanRec := strings.TrimSuffix(recExpr, "?")
						rawPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
						if len(rawPath) > 0 {
							syncLocalVarAlias(sourceMap, params, decodeBracketSeg(rawPath[0]))
						}
					}
					if len(args) == 2 {
						kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						newVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						keyStr := fmt.Sprintf("%v", kVal)
						if !isInternalPainlessMapKey(recMap, keyStr) {
							if cur, exists := recMap[keyStr]; exists {
								recMap[keyStr] = newVal
								syncReplacedMap(keyStr)
								return cur, nil
							}
						}
						return nil, nil
					}
					if len(args) == 3 {
						kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						oldVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						newVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
						if err != nil {
							return nil, err
						}
						keyStr := fmt.Sprintf("%v", kVal)
						if !isInternalPainlessMapKey(recMap, keyStr) {
							if cur, exists := recMap[keyStr]; exists && valuesEqual(cur, oldVal) {
								recMap[keyStr] = newVal
								syncReplacedMap(keyStr)
								return true, nil
							}
						}
						return false, nil
					}
					return nil, nil
				}
				if len(args) == 2 {
					oldVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					newVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if s, ok := recVal.(string); ok && oldVal != nil && newVal != nil {
						return strings.ReplaceAll(s, fmt.Sprintf("%v", oldVal), fmt.Sprintf("%v", newVal)), nil
					}
				}
				return recVal, nil
			case ".replaceAll(", ".replaceFirst(":
				args := splitTopLevelCommaPainless(argExpr)
				if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil && len(args) == 1 {
					regStart := 0
					regEnd := len(pm.input)
					if pm.hasRegion {
						regStart = pm.regionStart
						regEnd = pm.regionEnd
					}
					pm.curPos = 0
					pm.lastMatch = nil
					pm.appendPos = 0
					if arrowIdx := findNextUnquotedSubstr(args[0], "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(args[0][:arrowIdx])
						if len(pNames) > 0 && pm.re != nil {
							pName := pNames[0]
							body := args[0][arrowIdx+2:]
							var locs [][]int
							if mName == ".replaceFirst(" {
								if loc := pm.re.FindStringSubmatchIndex(pm.input[regStart:regEnd]); loc != nil {
									locs = [][]int{loc}
								}
							} else {
								locs = pm.re.FindAllStringSubmatchIndex(pm.input[regStart:regEnd], -1)
							}
							if len(locs) == 0 {
								return pm.input, nil
							}
							prev, hadPrev := params[pName]
							var out strings.Builder
							lastPos := 0
							for _, loc := range locs {
								shifted := make([]int, len(loc))
								for i, v := range loc {
									if v >= 0 {
										shifted[i] = v + regStart
									} else {
										shifted[i] = -1
									}
								}
								out.WriteString(pm.input[lastPos:shifted[0]])
								params[pName] = &painlessMatcher{
									re:          pm.re,
									input:       pm.input,
									curPos:      shifted[1],
									lastMatch:   shifted,
									hasRegion:   pm.hasRegion,
									regionStart: pm.regionStart,
									regionEnd:   pm.regionEnd,
								}
								mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
								if err != nil {
									if hadPrev {
										params[pName] = prev
									} else {
										delete(params, pName)
									}
									return nil, err
								}
								replStr := ""
								if mv != nil {
									replStr = fmt.Sprintf("%v", mv)
								}
								expanded := pm.re.ExpandString(nil, normalizeJavaRegexReplacement(replStr), pm.input, shifted)
								out.Write(expanded)
								lastPos = shifted[1]
							}
							out.WriteString(pm.input[lastPos:])
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return out.String(), nil
						}
						return pm.input, nil
					}
					replVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					if replVal != nil && pm.re != nil {
						goRepl := normalizeJavaRegexReplacement(fmt.Sprintf("%v", replVal))
						if mName == ".replaceFirst(" {
							if loc := pm.re.FindStringSubmatchIndex(pm.input[regStart:regEnd]); loc != nil {
								expanded := pm.re.ExpandString(nil, goRepl, pm.input[regStart:regEnd], loc)
								return pm.input[:regStart+loc[0]] + string(expanded) + pm.input[regStart+loc[1]:], nil
							}
							return pm.input, nil
						}
						return pm.input[:regStart] + pm.re.ReplaceAllString(pm.input[regStart:regEnd], goRepl) + pm.input[regEnd:], nil
					}
					return pm.input, nil
				}
				if len(args) == 2 {
					rawPatExpr := strings.TrimSpace(args[0])
					patVal, _ := evalRHSExprDepth(sourceMap, rawPatExpr, params, depth+1)
					replVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if s, ok := recVal.(string); ok && patVal != nil && replVal != nil {
						patStr := fmt.Sprintf("%v", patVal)
						if !isQuotedStringExprPainless(rawPatExpr) && isRawRegexLiteralPainless(patStr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
							patStr = strings.ReplaceAll(patStr[1:len(patStr)-1], `\/`, `/`)
						}
						replStr := fmt.Sprintf("%v", replVal)
						if re, err := compilePainlessRegexp(patStr); err == nil {
							goRepl := normalizeJavaRegexReplacement(replStr)
							if mName == ".replaceFirst(" {
								if loc := re.FindStringSubmatchIndex(s); loc != nil {
									expanded := re.ExpandString(nil, goRepl, s, loc)
									return s[:loc[0]] + string(expanded) + s[loc[1]:], nil
								}
								return s, nil
							}
							return re.ReplaceAllString(s, goRepl), nil
						}
						if mName == ".replaceFirst(" {
							return strings.Replace(s, patStr, replStr, 1), nil
						}
						return strings.ReplaceAll(s, patStr, replStr), nil
					}
				}
				return recVal, nil
			case ".substring(", ".subSequence(":
				args := splitTopLevelCommaPainless(argExpr)
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					recVal = sb.buf
				}
				if s, ok := recVal.(string); ok && len(args) >= 1 {
					startVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
					sf, sOk := toFloat64(startVal)
					if !sOk {
						return s, nil
					}
					runes := []rune(s)
					start := int(sf)
					if start < 0 {
						start = 0
					}
					if start > len(runes) {
						start = len(runes)
					}
					end := len(runes)
					if len(args) >= 2 {
						endVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if ef, eOk := toFloat64(endVal); eOk {
							end = int(ef)
							if end < start {
								end = start
							}
							if end > len(runes) {
								end = len(runes)
							}
						}
					}
					return string(runes[start:end]), nil
				}
				return recVal, nil
			case ".setCharAt(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						chVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if f, ok := toFloat64(idxVal); ok {
							idx := int(f)
							runes := []rune(sb.buf)
							if idx >= 0 && idx < len(runes) {
								var chRune rune
								if cf, cOk := toFloat64(chVal); cOk && cf >= 0 && cf <= 0x10FFFF {
									chRune = rune(int32(cf)) // #nosec G115 -- bounds-checked Unicode code point
								} else if chVal != nil {
									cr := []rune(fmt.Sprintf("%v", chVal))
									if len(cr) > 0 {
										chRune = cr[0]
									}
								}
								runes[idx] = chRune
								sb.buf = string(runes)
							}
						}
					}
					return sb, nil
				}
				return recVal, nil
			case ".ensureCapacity(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					return sb, nil
				}
				return recVal, nil
			case ".appendReplacement(":
				if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						sbVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						replVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						if sb, isSB := sbVal.(*painlessStringBuilder); isSB && sb != nil && len(pm.lastMatch) >= 2 && pm.lastMatch[0] >= 0 {
							startPos := pm.appendPos
							if pm.hasRegion && startPos < pm.regionStart {
								startPos = pm.regionStart
							}
							if startPos <= pm.lastMatch[0] {
								sb.buf += pm.input[startPos:pm.lastMatch[0]]
							}
							replStr := ""
							if replVal != nil {
								replStr = fmt.Sprintf("%v", replVal)
							}
							if pm.re != nil {
								expanded := pm.re.ExpandString(nil, normalizeJavaRegexReplacement(replStr), pm.input, pm.lastMatch)
								sb.buf += string(expanded)
							} else {
								sb.buf += replStr
							}
							if len(sb.buf) > MaxPainlessStringBytes {
								sb.buf = sb.buf[:MaxPainlessStringBytes]
							}
							pm.appendPos = pm.lastMatch[1]
						}
					}
					return pm, nil
				}
				return recVal, nil
			case ".appendTail(":
				if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil {
					sbVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if sb, isSB := sbVal.(*painlessStringBuilder); isSB && sb != nil {
						startPos := pm.appendPos
						if pm.hasRegion && startPos < pm.regionStart {
							startPos = pm.regionStart
						}
						if startPos >= 0 && startPos <= len(pm.input) {
							sb.buf += pm.input[startPos:]
						}
						if len(sb.buf) > MaxPainlessStringBytes {
							sb.buf = sb.buf[:MaxPainlessStringBytes]
						}
						return sb, nil
					}
					return sbVal, nil
				}
				return recVal, nil
			case ".region(":
				if pm, isMatcher := recVal.(*painlessMatcher); isMatcher && pm != nil {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						eVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						sf, sOk := toFloat64(sVal)
						ef, eOk := toFloat64(eVal)
						if sOk && eOk {
							runes := []rune(pm.input)
							st, en := int(sf), int(ef)
							if st < 0 {
								st = 0
							}
							if st > len(runes) {
								st = len(runes)
							}
							if en < st {
								en = st
							}
							if en > len(runes) {
								en = len(runes)
							}
							sByte := len(string(runes[:st]))
							eByte := len(string(runes[:en]))
							pm.hasRegion = true
							pm.regionStart = sByte
							pm.regionEnd = eByte
							pm.curPos = sByte
							pm.lastMatch = nil
							pm.appendPos = 0
						}
					}
					return pm, nil
				}
				return recVal, nil
			case ".atDay(":
				if yr, ok := recVal.(painlessYear); ok {
					dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if df, dOk := toFloat64(dVal); dOk {
						return yr.atDay(int(df)), nil
					}
					return nil, nil
				}
				if tm, ok := parsePainlessDateTime(recVal); ok {
					dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if df, dOk := toFloat64(dVal); dOk {
						day := int(df)
						maxDay := time.Date(tm.Year(), tm.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
						if day < 1 {
							day = 1
						} else if day > maxDay {
							day = maxDay
						}
						return fmt.Sprintf("%04d-%02d-%02d", tm.Year(), int(tm.Month()), day), nil
					}
				}
				return nil, nil
			case ".atMonth(":
				if yr, ok := recVal.(painlessYear); ok {
					mVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if m, mOk := parseMonthNumberPainless(mVal); mOk {
						return yr.atMonth(m), nil
					}
				}
				return nil, nil
			case ".atMonthDay(":
				if yr, ok := recVal.(painlessYear); ok {
					mdVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if md, mdOk := mdVal.(painlessMonthDay); mdOk {
						return yr.atMonthDay(md), nil
					}
				}
				return nil, nil
			case ".atYear(":
				if md, ok := recVal.(painlessMonthDay); ok {
					yVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if yf, yOk := toFloat64(yVal); yOk {
						return md.atYear(int(yf)), nil
					}
				}
				return nil, nil
			case ".isValidYear(":
				if md, ok := recVal.(painlessMonthDay); ok {
					yVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return false, err
					}
					if yf, yOk := toFloat64(yVal); yOk {
						return md.isValidYear(int(yf)), nil
					}
				}
				return false, nil
			case ".getLong(":
				cfVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if err != nil {
					return nil, err
				}
				if cf, ok := parseChronoFieldArgPainless(cfVal); ok {
					return evalGetChronoFieldPainless(recVal, cf)
				}
				return nil, nil
			case ".isSupported(":
				cfVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if err != nil {
					return false, err
				}
				if cf, ok := parseChronoFieldArgPainless(cfVal); ok {
					return evalIsSupportedChronoFieldPainless(recVal, cf), nil
				}
				return false, nil
			case ".with(":
				wArgs := splitTopLevelCommaPainless(argExpr)
				if len(wArgs) == 2 {
					cfVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(wArgs[0]), params, depth+1)
					if err != nil {
						return nil, err
					}
					newVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(wArgs[1]), params, depth+1)
					if err != nil {
						return nil, err
					}
					if cf, ok := parseChronoFieldArgPainless(cfVal); ok {
						if nf, nOk := toFloat64(newVal); nOk {
							return evalWithChronoFieldPainless(recVal, cf, int64(nf))
						}
					}
				} else if len(wArgs) == 1 {
					adjVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(wArgs[0]), params, depth+1)
					if err != nil {
						return nil, err
					}
					return evalWithTemporalAdjusterPainless(recVal, adjVal)
				}
				return recVal, nil
			case ".until(":
				uArgs := splitTopLevelCommaPainless(argExpr)
				if len(uArgs) == 1 {
					endVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(uArgs[0]), params, depth+1)
					if err != nil {
						return nil, err
					}
					return evalLocalDateUntilPeriodPainless(recVal, endVal), nil
				} else if len(uArgs) >= 2 {
					endVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(uArgs[0]), params, depth+1)
					if err != nil {
						return nil, err
					}
					unitVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(uArgs[1]), params, depth+1)
					if err != nil {
						return nil, err
					}
					return evalTemporalBetweenUnitPainless(unitVal, recVal, endVal), nil
				}
				return int64(0), nil
			case ".datesUntil(":
				dArgs := splitTopLevelCommaPainless(argExpr)
				if len(dArgs) >= 1 {
					endVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(dArgs[0]), params, depth+1)
					if err != nil {
						return nil, err
					}
					var stepVal any
					if len(dArgs) >= 2 {
						stepVal, err = evalRHSExprDepth(sourceMap, strings.TrimSpace(dArgs[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
					}
					return evalLocalDateDatesUntilPainless(recVal, endVal, stepVal)
				}
				return []any{}, nil
			case ".between(":
				bArgs := splitTopLevelCommaPainless(argExpr)
				if len(bArgs) >= 2 {
					v1, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(bArgs[0]), params, depth+1)
					if err != nil {
						return nil, err
					}
					v2, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(bArgs[1]), params, depth+1)
					if err != nil {
						return nil, err
					}
					return evalTemporalBetweenUnitPainless(recVal, v1, v2), nil
				}
				return int64(0), nil
			case ".atDate(":
				if tm, ok := parsePainlessDateTime(recVal); ok {
					dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					if dt, okD := parsePainlessDateTime(dVal); okD {
						tStr := formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond())
						return fmt.Sprintf("%04d-%02d-%02dT%s", dt.Year(), int(dt.Month()), dt.Day(), tStr), nil
					}
				}
				return nil, nil
			case ".atTime(":
				if dt, ok := parsePainlessDateTime(recVal); ok {
					tArgs := splitTopLevelCommaPainless(argExpr)
					if len(tArgs) == 1 {
						tVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(tArgs[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						if tm, okT := parsePainlessDateTime(tVal); okT {
							tStr := formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond())
							return fmt.Sprintf("%04d-%02d-%02dT%s", dt.Year(), int(dt.Month()), dt.Day(), tStr), nil
						}
					} else if len(tArgs) >= 2 {
						hVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(tArgs[0]), params, depth+1)
						mVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(tArgs[1]), params, depth+1)
						hf, _ := toFloat64(hVal)
						mf, _ := toFloat64(mVal)
						sec, nano := 0, 0
						if len(tArgs) >= 3 {
							sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(tArgs[2]), params, depth+1)
							sf, _ := toFloat64(sVal)
							sec = int(sf)
						}
						if len(tArgs) >= 4 {
							nVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(tArgs[3]), params, depth+1)
							nf, _ := toFloat64(nVal)
							nano = int(nf)
						}
						tStr := formatLocalTimePainless(int(hf), int(mf), sec, nano)
						return fmt.Sprintf("%04d-%02d-%02dT%s", dt.Year(), int(dt.Month()), dt.Day(), tStr), nil
					}
				}
				return nil, nil
			case ".atStartOfDay(":
				if dt, ok := parsePainlessDateTime(recVal); ok {
					if strings.TrimSpace(argExpr) == "" {
						return fmt.Sprintf("%04d-%02d-%02dT00:00", dt.Year(), int(dt.Month()), dt.Day()), nil
					}
					zVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if err != nil {
						return nil, err
					}
					loc := parseZoneLocationPainless(zVal)
					return time.Date(dt.Year(), dt.Month(), dt.Day(), 0, 0, 0, 0, loc).Format(time.RFC3339Nano), nil
				}
				return nil, nil
			case ".subtract(", ".multiply(", ".divide(", ".remainder(", ".pow(", ".setScale(", ".min(", ".max(",
				".movePointLeft(", ".movePointRight(", ".scaleByPowerOfTen(", ".divideToIntegralValue(", ".divideAndRemainder(", ".round(", ".abs(", ".negate(",
				".mod(", ".modPow(", ".modInverse(", ".gcd(", ".and(", ".xor(", ".andNot(", ".shiftLeft(", ".shiftRight(",
				".testBit(", ".setBit(", ".clearBit(", ".flipBit(", ".isProbablePrime(", ".toString(",
				".clear(", ".flip(", ".nextSetBit(", ".nextClearBit(", ".previousSetBit(", ".previousClearBit(", ".intersects(",
				".setEmptyValue(",
				".thenComparing(", ".thenComparingInt(", ".thenComparingLong(", ".thenComparingDouble(", ".compare(":
				return evalNumericBitSetJoinerComparatorMethodPainless(mName, recVal, argExpr, sourceMap, params, depth+1)
			case ".orElse(":
				if !isEmptyOptionalOrNilPainless(recVal) {
					return recVal, nil
				}
				return evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
			case ".orElseGet(", ".or(":
				if mName == ".or(" {
					if bs, isBS := recVal.(*painlessBitSet); isBS && bs != nil {
						otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if err != nil {
							return nil, err
						}
						if otherBS, okO := otherVal.(*painlessBitSet); okO {
							bs.or(otherBS)
						}
						return nil, nil
					}
					if bi, isBI := recVal.(*painlessBigInteger); isBI && bi != nil {
						otherVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
						if err != nil {
							return nil, err
						}
						if bi2, ok2 := parsePainlessBigInteger(otherVal); ok2 {
							return newPainlessBigInteger(new(big.Int).Or(bi.val, bi2.val)), nil
						}
						return bi, nil
					}
				}
				if !isEmptyOptionalOrNilPainless(recVal) {
					return recVal, nil
				}
				normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 0)
				if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
					return evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
				}
				return painlessEmptyOptional, nil
			case ".orElseThrow(":
				if !isEmptyOptionalOrNilPainless(recVal) {
					return recVal, nil
				}
				return evalOptionalOrElseThrowSupplierPainless(argExpr, sourceMap, params, depth+1)
			case ".ifPresent(":
				if !isEmptyOptionalOrNilPainless(recVal) {
					normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 1)
					if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
						if len(pNames) > 0 {
							pName := pNames[0]
							prev, hadPrev := params[pName]
							params[pName] = recVal
							_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
					}
				}
				return nil, nil
			case ".ifPresentOrElse(":
				ieArgs := splitTopLevelCommaPainless(argExpr)
				if !isEmptyOptionalOrNilPainless(recVal) {
					if len(ieArgs) >= 1 {
						normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(ieArgs[0]), 1)
						if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
							pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
							if len(pNames) > 0 {
								pName := pNames[0]
								prev, hadPrev := params[pName]
								params[pName] = recVal
								_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
								if hadPrev {
									params[pName] = prev
								} else {
									delete(params, pName)
								}
								return nil, err
							}
						}
					}
				} else if len(ieArgs) >= 2 {
					normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(ieArgs[1]), 0)
					if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
						_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
						return nil, err
					}
				}
				return nil, nil
			case ".filter(":
				if isEmptyOptionalOrNilPainless(recVal) {
					return painlessEmptyOptional, nil
				}
				normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 1)
				if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
					if len(pNames) > 0 {
						pName := pNames[0]
						prev, hadPrev := params[pName]
						params[pName] = recVal
						matched, err := evalPainlessPredicateLambda(normArg[arrowIdx+2:], sourceMap, params, depth+1)
						if hadPrev {
							params[pName] = prev
						} else {
							delete(params, pName)
						}
						if err != nil {
							return nil, err
						}
						if !matched {
							return painlessEmptyOptional, nil
						}
						return recVal, nil
					}
				}
				return recVal, nil
			case ".map(", ".flatMap(":
				if isEmptyOptionalOrNilPainless(recVal) {
					return painlessEmptyOptional, nil
				}
				normArg := normalizeMethodReferenceToLambdaPainless(argExpr, 1)
				if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
					if len(pNames) > 0 {
						pName := pNames[0]
						prev, hadPrev := params[pName]
						params[pName] = recVal
						mv, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
						if hadPrev {
							params[pName] = prev
						} else {
							delete(params, pName)
						}
						if err != nil {
							return nil, err
						}
						if isEmptyOptionalOrNilPainless(mv) {
							return painlessEmptyOptional, nil
						}
						return mv, nil
					}
				}
				return recVal, nil
			case ".withPrefix(", ".withSuffix(", ".withDelimiter(", ".formatHex(", ".parseHex(", ".toHexDigits(", ".fromHexDigits(", ".fromHexDigitsToLong(", ".isHexDigit(", ".fromHexDigit(":
				return evalHexFormatMethodPainless(mName, recVal, argExpr, sourceMap, params, depth+1)
			case ".contentEquals(":
				cv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
				if err != nil {
					return false, err
				}
				if cv == nil {
					return false, nil
				}
				if sb, ok := cv.(*painlessStringBuilder); ok {
					if sb == nil {
						return false, nil
					}
					return fmt.Sprintf("%v", recVal) == sb.buf, nil
				}
				return fmt.Sprintf("%v", recVal) == fmt.Sprintf("%v", cv), nil
			case ".formatted(":
				fmtStr := fmt.Sprintf("%v", recVal)
				if strings.TrimSpace(argExpr) == "" {
					return fmtStr, nil
				}
				fArgs := splitTopLevelCommaPainless(argExpr)
				fmtArgs := make([]any, 0, len(fArgs))
				for _, a := range fArgs {
					av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
					if err != nil {
						return "", err
					}
					if jn, isJN := av.(json.Number); isJN {
						if iv, err := jn.Int64(); err == nil {
							av = iv
						} else if fv, err := jn.Float64(); err == nil {
							av = fv
						}
					}
					fmtArgs = append(fmtArgs, av)
				}
				return fmt.Sprintf(fmtStr, fmtArgs...), nil
			case ".floorKey(", ".ceilingKey(", ".lowerKey(", ".higherKey(", ".floorEntry(", ".ceilingEntry(", ".lowerEntry(", ".higherEntry(", ".headMap(", ".tailMap(", ".subMap(",
				".floor(", ".ceiling(", ".lower(", ".higher(", ".headSet(", ".tailSet(", ".subSet(",
				".offerFirst(", ".offerLast(", ".offer(", ".addFirst(", ".addLast(", ".push(", ".removeFirstOccurrence(", ".removeLastOccurrence(":
				return evalNavigableOrDequeMethodPainless(mName, recExpr, recVal, argExpr, sourceMap, params, depth+1)
			case ".append(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 1 {
						v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						addStr := "null"
						if v0 != nil {
							addStr = fmt.Sprintf("%v", v0)
						}
						if len(args) >= 3 {
							sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
							eVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
							sf, sOk := toFloat64(sVal)
							ef, eOk := toFloat64(eVal)
							if sOk && eOk {
								r := []rune(addStr)
								st, en := int(sf), int(ef)
								if st < 0 {
									st = 0
								}
								if st > len(r) {
									st = len(r)
								}
								if en < st {
									en = st
								}
								if en > len(r) {
									en = len(r)
								}
								addStr = string(r[st:en])
							}
						}
						next := sb.buf + addStr
						if len(next) > MaxPainlessStringBytes {
							next = next[:MaxPainlessStringBytes]
						}
						sb.buf = next
					}
					return sb, nil
				}
				return recVal, nil
			case ".insert(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						offVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						insVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						if of, ok := toFloat64(offVal); ok {
							runes := []rune(sb.buf)
							idx := int(of)
							if idx < 0 {
								idx = 0
							}
							if idx > len(runes) {
								idx = len(runes)
							}
							insStr := "null"
							if insVal != nil {
								insStr = fmt.Sprintf("%v", insVal)
							}
							next := string(runes[:idx]) + insStr + string(runes[idx:])
							if len(next) > MaxPainlessStringBytes {
								next = next[:MaxPainlessStringBytes]
							}
							sb.buf = next
						}
					}
					return sb, nil
				}
				return recVal, nil
			case ".delete(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						sVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						eVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						sf, sOk := toFloat64(sVal)
						ef, eOk := toFloat64(eVal)
						if sOk && eOk {
							runes := []rune(sb.buf)
							start, end := int(sf), int(ef)
							if start < 0 {
								start = 0
							}
							if start > len(runes) {
								start = len(runes)
							}
							if end < start {
								end = start
							}
							if end > len(runes) {
								end = len(runes)
							}
							sb.buf = string(runes[:start]) + string(runes[end:])
						}
					}
					return sb, nil
				}
				return recVal, nil
			case ".deleteCharAt(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					idxVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if f, ok := toFloat64(idxVal); ok {
						runes := []rune(sb.buf)
						idx := int(f)
						if idx >= 0 && idx < len(runes) {
							sb.buf = string(runes[:idx]) + string(runes[idx+1:])
						}
					}
					return sb, nil
				}
				return recVal, nil
			case ".setLength(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					lenVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(argExpr), params, depth+1)
					if f, ok := toFloat64(lenVal); ok {
						newLen := int(f)
						if newLen < 0 {
							newLen = 0
						}
						if newLen > MaxPainlessStringBytes {
							newLen = MaxPainlessStringBytes
						}
						runes := []rune(sb.buf)
						if newLen <= len(runes) {
							sb.buf = string(runes[:newLen])
						} else {
							sb.buf = sb.buf + strings.Repeat("\x00", newLen-len(runes))
						}
					}
					return sb, nil
				}
				return recVal, nil
			}
			argVal, _ := evalRHSExprDepth(sourceMap, argExpr, params, depth+1)
			switch mName {
			case ".matcher(":
				inStr := ""
				if argVal != nil {
					inStr = fmt.Sprintf("%v", argVal)
				}
				if pp, ok := recVal.(*painlessPattern); ok && pp != nil {
					return &painlessMatcher{re: pp.re, input: inStr}, nil
				}
				patStr := fmt.Sprintf("%v", recVal)
				if !isQuotedStringExprPainless(recExpr) && isRawRegexLiteralPainless(patStr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
					patStr = strings.ReplaceAll(patStr[1:len(patStr)-1], `\/`, `/`)
				}
				re, _ := compilePainlessRegexp(patStr)
				return &painlessMatcher{re: re, input: inStr}, nil
			case ".find(":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && argVal != nil {
					if f, fOk := toFloat64(argVal); fOk {
						runeStart := int(f)
						runes := []rune(pm.input)
						pm.hasRegion = false
						pm.regionStart = 0
						pm.regionEnd = len(pm.input)
						pm.appendPos = 0
						if pm.re == nil || runeStart < 0 || runeStart > len(runes) {
							pm.lastMatch = nil
							return false, nil
						}
						bytePos := len(string(runes[:runeStart]))
						pm.curPos = bytePos
						shifted := findSubmatchIndexFromPosPainless(pm.re, pm.input, pm.curPos)
						if shifted == nil {
							pm.lastMatch = nil
							pm.curPos = len(pm.input) + 1
							return false, nil
						}
						pm.lastMatch = shifted
						if shifted[0] == shifted[1] {
							if shifted[1] < len(pm.input) {
								_, w := utf8.DecodeRuneInString(pm.input[shifted[1]:])
								if w <= 0 {
									w = 1
								}
								pm.curPos = shifted[1] + w
							} else {
								pm.curPos = len(pm.input) + 1
							}
						} else {
							pm.curPos = shifted[1]
						}
						return true, nil
					}
				}
				return false, nil
			case ".reset(":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil {
					if argVal != nil {
						pm.input = fmt.Sprintf("%v", argVal)
					} else {
						pm.input = ""
					}
					pm.curPos = 0
					pm.lastMatch = nil
					pm.appendPos = 0
					pm.hasRegion = false
					pm.regionStart = 0
					pm.regionEnd = len(pm.input)
					return pm, nil
				}
				return recVal, nil
			case ".getBytes(":
				s := fmt.Sprintf("%v", recVal)
				out := make([]any, len(s))
				for i := 0; i < len(s); i++ {
					out[i] = int64(s[i])
				}
				return out, nil
			case ".encodeToString(", ".encode(":
				if s, ok := recVal.(string); ok && strings.HasPrefix(s, "__base64_encoder:") {
					rawBytes := toBytesPainless(argVal)
					switch s {
					case "__base64_encoder:url":
						return base64.URLEncoding.EncodeToString(rawBytes), nil
					case "__base64_encoder:url:nopad":
						return base64.RawURLEncoding.EncodeToString(rawBytes), nil
					case "__base64_encoder:std:nopad":
						return base64.RawStdEncoding.EncodeToString(rawBytes), nil
					default:
						return base64.StdEncoding.EncodeToString(rawBytes), nil
					}
				}
				return "", nil
			case ".decode(":
				if s, ok := recVal.(string); ok && strings.HasPrefix(s, "__base64_decoder:") {
					var inStr string
					if _, isArr := argVal.([]any); isArr {
						inStr = strings.TrimSpace(string(toBytesPainless(argVal)))
					} else {
						inStr = strings.TrimSpace(fmt.Sprintf("%v", argVal))
					}
					if strings.HasPrefix(s, "__base64_decoder:mime") {
						inStr = strings.NewReplacer("\r", "", "\n", "").Replace(inStr)
					}
					if s == "__base64_decoder:url" {
						if dec, err := base64.URLEncoding.DecodeString(inStr); err == nil {
							return string(dec), nil
						}
						if dec, err := base64.RawURLEncoding.DecodeString(inStr); err == nil {
							return string(dec), nil
						}
						return "", &painlessExceptionError{exType: "IllegalArgumentException", message: "Illegal base64 character"}
					}
					if dec, err := base64.StdEncoding.DecodeString(inStr); err == nil {
						return string(dec), nil
					}
					if dec, err := base64.RawStdEncoding.DecodeString(inStr); err == nil {
						return string(dec), nil
					}
					return "", &painlessExceptionError{exType: "IllegalArgumentException", message: "Illegal base64 character"}
				}
				return "", nil
			case ".format(":
				if isGoDateTimeLayoutPainless(recVal, recExpr) {
					if tm, ok := parsePainlessDateTime(argVal); ok {
						layout, loc := splitFormatterAndZonePainless(recVal)
						if loc != nil {
							tm = tm.In(loc)
						}
						return tm.Format(layout), nil
					}
				}
				if tm, ok := parsePainlessDateTime(recVal); ok {
					layout, loc := splitFormatterAndZonePainless(argVal)
					if loc != nil {
						tm = tm.In(loc)
					}
					return tm.Format(layout), nil
				}
				if tm, ok := parsePainlessDateTime(argVal); ok {
					layout, loc := splitFormatterAndZonePainless(recVal)
					if loc != nil {
						tm = tm.In(loc)
					}
					return tm.Format(layout), nil
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".withZone(":
				return attachZoneToFormatterPainless(recVal, argVal), nil
			case ".withLocale(":
				return recVal, nil
			case ".withZoneSameInstant(", ".withZoneSameLocal(":
				if tm, ok := parsePainlessDateTime(recVal); ok {
					loc := parseZoneLocationPainless(argVal)
					if mName == ".withZoneSameInstant(" {
						tm = tm.In(loc)
					} else {
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), loc)
					}
					return tm.Format(time.RFC3339Nano), nil
				}
				return recVal, nil
			case ".group(":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && argVal != nil {
					if gName, isStr := argVal.(string); isStr {
						if pm.re != nil {
							idx := pm.re.SubexpIndex(gName)
							if idx >= 0 && 2*idx+1 < len(pm.lastMatch) {
								sIdx, eIdx := pm.lastMatch[2*idx], pm.lastMatch[2*idx+1]
								if sIdx >= 0 && eIdx >= 0 {
									return pm.input[sIdx:eIdx], nil
								}
							}
						}
						return nil, nil
					}
					if f, fOk := toFloat64(argVal); fOk {
						idx := int(f)
						if idx >= 0 && 2*idx+1 < len(pm.lastMatch) {
							sIdx, eIdx := pm.lastMatch[2*idx], pm.lastMatch[2*idx+1]
							if sIdx >= 0 && eIdx >= 0 {
								return pm.input[sIdx:eIdx], nil
							}
						}
						return nil, nil
					}
				}
				return nil, nil
			case ".start(", ".end(":
				if pm, ok := recVal.(*painlessMatcher); ok && pm != nil && argVal != nil {
					idx := -1
					if gName, isStr := argVal.(string); isStr {
						if pm.re != nil {
							idx = pm.re.SubexpIndex(gName)
						}
					} else if f, fOk := toFloat64(argVal); fOk {
						idx = int(f)
					}
					if idx >= 0 && 2*idx+1 < len(pm.lastMatch) {
						pos := pm.lastMatch[2*idx]
						if mName == ".end(" {
							pos = pm.lastMatch[2*idx+1]
						}
						if pos >= 0 {
							return int64(utf8.RuneCountInString(pm.input[:pos])), nil
						}
					}
				}
				return int64(-1), nil
			case ".startsWith(":
				if s, ok := recVal.(string); ok {
					swArgs := splitTopLevelCommaPainless(argExpr)
					if len(swArgs) >= 2 {
						pVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(swArgs[0]), params, depth+1)
						if err != nil || pVal == nil {
							return false, err
						}
						offVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(swArgs[1]), params, depth+1)
						if err != nil {
							return false, err
						}
						toff, okOff := toInt64Painless(offVal)
						if !okOff {
							return false, nil
						}
						runes := []rune(s)
						if toff < 0 || int(toff) > len(runes) {
							return false, nil
						}
						return strings.HasPrefix(string(runes[int(toff):]), fmt.Sprintf("%v", pVal)), nil
					}
					if argVal != nil {
						return strings.HasPrefix(s, fmt.Sprintf("%v", argVal)), nil
					}
				}
				return false, nil
			case ".setValue(":
				if m, ok := recVal.(map[string]any); ok {
					oldVal := m["value"]
					m["value"] = argVal
					if pm, ok := m["__parent_map"].(map[string]any); ok {
						pm[fmt.Sprintf("%v", m["key"])] = argVal
					}
					return oldVal, nil
				}
				return nil, nil
			case ".endsWith(":
				if s, ok := recVal.(string); ok && argVal != nil {
					return strings.HasSuffix(s, fmt.Sprintf("%v", argVal)), nil
				}
				return false, nil
			case ".matches(":
				return evalRegexMatchPainless(recVal, argVal, isRawRegexLiteralPainless(argExpr), true), nil
			case ".charAt(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					recVal = sb.buf
				}
				if s, ok := recVal.(string); ok && argVal != nil {
					if f, ok := toFloat64(argVal); ok {
						idx := int(f)
						runes := []rune(s)
						if idx >= 0 && idx < len(runes) {
							return string(runes[idx]), nil
						}
					}
				}
				return nil, nil
			case ".codePointAt(":
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					recVal = sb.buf
				}
				if s, ok := recVal.(string); ok && argVal != nil {
					if f, ok := toFloat64(argVal); ok {
						idx := int(f)
						runes := []rune(s)
						if idx >= 0 && idx < len(runes) {
							return int64(runes[idx]), nil
						}
					}
				}
				return int64(-1), nil
			case ".repeat(":
				if s, ok := recVal.(string); ok && argVal != nil {
					if f, ok := toFloat64(argVal); ok {
						n := int(f)
						if n <= 0 || s == "" {
							return "", nil
						}
						if len(s)*n > MaxPainlessSliceItems*64 {
							n = (MaxPainlessSliceItems * 64) / len(s)
						}
						return strings.Repeat(s, n), nil
					}
				}
				return "", nil
			case ".containsAll(":
				if tv, ok := recVal.([]any); ok {
					if needles, ok2 := argVal.([]any); ok2 {
						for _, needle := range needles {
							found := false
							for _, item := range tv {
								if painlessValuesEqual(item, needle) {
									found = true
									break
								}
							}
							if !found {
								return false, nil
							}
						}
						return true, nil
					}
				}
				return false, nil
			case ".removeAll(", ".retainAll(":
				if tv, ok := recVal.([]any); ok {
					if needles, ok2 := argVal.([]any); ok2 {
						isRetain := mName == ".retainAll("
						changed := false
						for _, item := range tv {
							inNeedles := false
							for _, needle := range needles {
								if painlessValuesEqual(item, needle) {
									inNeedles = true
									break
								}
							}
							if (isRetain && !inNeedles) || (!isRetain && inNeedles) {
								changed = true
								break
							}
						}
						return changed, nil
					}
				}
				return false, nil
			case ".join(":
				if recExpr == "String" {
					args := splitTopLevelCommaPainless(argExpr)
					if len(args) >= 2 {
						delimVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						delim := fmt.Sprintf("%v", delimVal)
						if len(args) == 2 {
							secondVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
							if arr, ok := secondVal.([]any); ok {
								parts := make([]string, len(arr))
								for i, item := range arr {
									parts[i] = fmt.Sprintf("%v", item)
								}
								return strings.Join(parts, delim), nil
							}
						}
						parts := make([]string, 0, len(args)-1)
						for _, a := range args[1:] {
							v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
							parts = append(parts, fmt.Sprintf("%v", v))
						}
						return strings.Join(parts, delim), nil
					}
				}
				if tv, ok := recVal.([]any); ok {
					sep := ""
					if argVal != nil {
						sep = fmt.Sprintf("%v", argVal)
					}
					parts := make([]string, len(tv))
					for i, item := range tv {
						parts[i] = fmt.Sprintf("%v", item)
					}
					return strings.Join(parts, sep), nil
				}
				return fmt.Sprintf("%v", recVal), nil
			case ".contains(":
				switch tv := recVal.(type) {
				case []any:
					for _, item := range tv {
						if painlessValuesEqual(item, argVal) {
							return true, nil
						}
					}
				case string:
					if argVal != nil {
						return strings.Contains(tv, fmt.Sprintf("%v", argVal)), nil
					}
				}
				return false, nil
			case ".containsKey(":
				if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil && argVal != nil {
					_, exists := lookupCtxMapKeyPainless(fmt.Sprintf("%v", argVal), sourceMap, params)
					return exists, nil
				}
				if m, ok := recVal.(map[string]any); ok && argVal != nil {
					k := fmt.Sprintf("%v", argVal)
					if isInternalPainlessMapKey(m, k) {
						return false, nil
					}
					_, exists := m[k]
					return exists, nil
				}
				return false, nil
			case ".containsValue(":
				if m, ok := recVal.(map[string]any); ok {
					for k, v := range m {
						if isInternalPainlessMapKey(m, k) {
							continue
						}
						if painlessValuesEqual(v, argVal) {
							return true, nil
						}
					}
				}
				return false, nil
			case ".get(":
				if strings.TrimSpace(argExpr) == "" {
					return recVal, nil
				}
				if cf, ok := parseChronoFieldArgPainless(argVal); ok {
					return evalGetChronoFieldPainless(recVal, cf)
				}
				if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil && argVal != nil {
					v, _ := lookupCtxMapKeyPainless(fmt.Sprintf("%v", argVal), sourceMap, params)
					return v, nil
				}
				switch tv := recVal.(type) {
				case *painlessBitSet:
					gArgs := splitTopLevelCommaPainless(argExpr)
					if len(gArgs) >= 2 {
						v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(gArgs[0]), params, depth+1)
						if err0 != nil {
							return nil, err0
						}
						v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(gArgs[1]), params, depth+1)
						if err1 != nil {
							return nil, err1
						}
						i0, _ := toInt64Painless(v0)
						i1, _ := toInt64Painless(v1)
						return tv.getRange(int(i0), int(i1))
					}
					idx, _ := toInt64Painless(argVal)
					return tv.get(int(idx))
				case map[string]any:
					if argVal != nil {
						kStr := fmt.Sprintf("%v", argVal)
						if isInternalPainlessMapKey(tv, kStr) {
							return nil, nil
						}
						return tv[kStr], nil
					}
				case []any:
					if argVal != nil {
						if f, ok := toFloat64(argVal); ok {
							if idx, okIdx := parseSliceIndex(strconv.Itoa(int(f)), len(tv)); okIdx {
								return tv[idx], nil
							}
						}
					}
				}
				return nil, nil
			case ".indexOf(":
				args := splitTopLevelCommaPainless(argExpr)
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					recVal = sb.buf
				}
				switch tv := recVal.(type) {
				case string:
					runes := []rune(tv)
					if len(args) >= 2 {
						subVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						fromVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if subVal != nil {
							needle, okNeedle := resolveStringSearchNeedlePainless(subVal)
							if !okNeedle {
								return int64(-1), nil
							}
							fromIdx := 0
							if ff, ok := toFloat64(fromVal); ok {
								fromIdx = int(ff)
							}
							if fromIdx < 0 {
								fromIdx = 0
							}
							if fromIdx > len(runes) {
								return int64(-1), nil
							}
							tailStr := string(runes[fromIdx:])
							byteIdx := strings.Index(tailStr, needle)
							if byteIdx < 0 {
								return int64(-1), nil
							}
							return int64(fromIdx + utf8.RuneCountInString(tailStr[:byteIdx])), nil
						}
					} else if argVal != nil {
						needle, okNeedle := resolveStringSearchNeedlePainless(argVal)
						if !okNeedle {
							return int64(-1), nil
						}
						byteIdx := strings.Index(tv, needle)
						if byteIdx < 0 {
							return int64(-1), nil
						}
						return int64(utf8.RuneCountInString(tv[:byteIdx])), nil
					}
				case []any:
					for idx, item := range tv {
						if painlessValuesEqual(item, argVal) {
							return int64(idx), nil
						}
					}
				}
				return int64(-1), nil
			case ".lastIndexOf(":
				args := splitTopLevelCommaPainless(argExpr)
				if sb, isSB := recVal.(*painlessStringBuilder); isSB && sb != nil {
					recVal = sb.buf
				}
				switch tv := recVal.(type) {
				case string:
					runes := []rune(tv)
					if len(args) >= 2 {
						subVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						fromVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if subVal != nil {
							needle, okNeedle := resolveStringSearchNeedlePainless(subVal)
							if !okNeedle {
								return int64(-1), nil
							}
							fromIdx := len(runes)
							if ff, ok := toFloat64(fromVal); ok {
								fromIdx = int(ff)
							}
							if fromIdx < 0 {
								return int64(-1), nil
							}
							subRunes := []rune(needle)
							maxEnd := fromIdx + len(subRunes)
							if maxEnd > len(runes) {
								maxEnd = len(runes)
							}
							headStr := string(runes[:maxEnd])
							byteIdx := strings.LastIndex(headStr, string(subRunes))
							if byteIdx < 0 {
								return int64(-1), nil
							}
							return int64(utf8.RuneCountInString(headStr[:byteIdx])), nil
						}
					} else if argVal != nil {
						needle, okNeedle := resolveStringSearchNeedlePainless(argVal)
						if !okNeedle {
							return int64(-1), nil
						}
						byteIdx := strings.LastIndex(tv, needle)
						if byteIdx < 0 {
							return int64(-1), nil
						}
						return int64(utf8.RuneCountInString(tv[:byteIdx])), nil
					}
				case []any:
					for idx := len(tv) - 1; idx >= 0; idx-- {
						if painlessValuesEqual(tv[idx], argVal) {
							return int64(idx), nil
						}
					}
				}
				return int64(-1), nil
			case ".splitOnToken(":
				if s, ok := recVal.(string); ok && argVal != nil {
					tokenStr := fmt.Sprintf("%v", argVal)
					if tokenStr == "" {
						return []any{}, nil
					}
					parts := strings.Split(s, tokenStr)
					out := make([]any, 0, len(parts))
					for _, p := range parts {
						out = append(out, p)
					}
					return out, nil
				}
				return []any{}, nil
			case ".split(":
				if pp, ok := recVal.(*painlessPattern); ok && pp != nil {
					splitArgs := splitTopLevelCommaPainless(argExpr)
					inStr := ""
					if len(splitArgs) >= 1 {
						v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(splitArgs[0]), params, depth+1)
						if err != nil {
							return nil, err
						}
						if v0 != nil {
							inStr = fmt.Sprintf("%v", v0)
						}
					}
					limit := 0
					if len(splitArgs) >= 2 {
						v1, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(splitArgs[1]), params, depth+1)
						if err != nil {
							return nil, err
						}
						if lf, lOk := toFloat64(v1); lOk {
							limit = int(lf)
						}
					}
					if pp.re == nil {
						return []any{inStr}, nil
					}
					if limit == 1 {
						return []any{inStr}, nil
					}
					nSplit := -1
					if limit > 0 {
						nSplit = limit
					}
					parts := pp.re.Split(inStr, nSplit)
					if limit == 0 {
						for len(parts) > 0 && parts[len(parts)-1] == "" {
							parts = parts[:len(parts)-1]
						}
						if len(parts) == 0 {
							return []any{}, nil
						}
					}
					res := make([]any, len(parts))
					for i, p := range parts {
						res[i] = p
					}
					return res, nil
				}
				if s, ok := recVal.(string); ok {
					args := splitTopLevelCommaPainless(argExpr)
					rawSepExpr := argExpr
					sepVal := argVal
					limit := 0
					if len(args) >= 2 {
						rawSepExpr = strings.TrimSpace(args[0])
						sepVal, _ = evalRHSExprDepth(sourceMap, rawSepExpr, params, depth+1)
						limVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
						if lf, lOk := toFloat64(limVal); lOk {
							limit = int(lf)
						}
					}
					if !isQuotedStringExprPainless(recExpr) && isRawRegexLiteralPainless(s) && len(s) >= 2 && s[0] == '/' && s[len(s)-1] == '/' {
						patStr := strings.ReplaceAll(s[1:len(s)-1], `\/`, `/`)
						inputStr := ""
						if sepVal != nil {
							inputStr = fmt.Sprintf("%v", sepVal)
						}
						if inputStr == "" {
							return []any{""}, nil
						}
						splitLim := -1
						if limit > 0 {
							splitLim = limit
						}
						var parts []string
						if re, err := compilePainlessRegexp(patStr); err == nil {
							parts = re.Split(inputStr, splitLim)
						} else if splitLim > 0 {
							parts = strings.SplitN(inputStr, patStr, splitLim)
						} else {
							parts = strings.Split(inputStr, patStr)
						}
						if limit == 0 && len(parts) > 1 {
							for len(parts) > 0 && parts[len(parts)-1] == "" {
								parts = parts[:len(parts)-1]
							}
						}
						out := make([]any, len(parts))
						for i, p := range parts {
							out[i] = p
						}
						return out, nil
					}
					if sepVal != nil {
						if s == "" {
							return []any{""}, nil
						}
						sepStr := fmt.Sprintf("%v", sepVal)
						isRegexLit := isRawRegexLiteralPainless(rawSepExpr) || (!isQuotedStringExprPainless(rawSepExpr) && isRawRegexLiteralPainless(sepStr))
						if isRegexLit && len(sepStr) >= 3 && sepStr[0] == '/' && sepStr[len(sepStr)-1] == '/' {
							sepStr = strings.ReplaceAll(sepStr[1:len(sepStr)-1], `\/`, `/`)
						}
						splitLim := -1
						if limit > 0 {
							splitLim = limit
						}
						var parts []string
						if re, err := regexp.Compile(sepStr); err == nil && (isRegexLit || (sepStr != "." && sepStr != "|" && sepStr != "" && sepStr != "$" && sepStr != "^")) {
							parts = re.Split(s, splitLim)
						} else if splitLim > 0 {
							parts = strings.SplitN(s, sepStr, splitLim)
						} else {
							parts = strings.Split(s, sepStr)
						}
						if limit == 0 && len(parts) > 1 {
							for len(parts) > 0 && parts[len(parts)-1] == "" {
								parts = parts[:len(parts)-1]
							}
						}
						out := make([]any, len(parts))
						for i, p := range parts {
							out[i] = p
						}
						return out, nil
					}
				}
				return []any{}, nil
			case ".equals(":
				return painlessValuesEqual(recVal, argVal), nil
			case ".equalsIgnoreCase(":
				if argVal == nil {
					return false, nil
				}
				return strings.EqualFold(fmt.Sprintf("%v", recVal), fmt.Sprintf("%v", argVal)), nil
			case ".compareTo(":
				if yr1, ok1 := recVal.(painlessYear); ok1 {
					if yr2, ok2 := argVal.(painlessYear); ok2 {
						if yr1.year < yr2.year {
							return int64(-1), nil
						} else if yr1.year > yr2.year {
							return int64(1), nil
						}
						return int64(0), nil
					}
				}
				if md1, ok1 := recVal.(painlessMonthDay); ok1 {
					if md2, ok2 := argVal.(painlessMonthDay); ok2 {
						if md1.month != md2.month {
							return int64(md1.month - md2.month), nil
						}
						return int64(md1.day - md2.day), nil
					}
				}
				if bd1, isBD1 := recVal.(*painlessBigDecimal); isBD1 && bd1 != nil {
					if bd2, ok2 := parsePainlessBigDecimal(argVal); ok2 {
						return int64(compareBigDecimalPainless(bd1, bd2)), nil
					}
				}
				if bi1, isBI1 := recVal.(*painlessBigInteger); isBI1 && bi1 != nil {
					if bi2, ok2 := parsePainlessBigInteger(argVal); ok2 {
						return int64(bi1.val.Cmp(bi2.val)), nil
					}
				}
				if fa, ok1 := toFloat64(recVal); ok1 {
					if fb, ok2 := toFloat64(argVal); ok2 {
						if fa < fb {
							return int64(-1), nil
						}
						if fa > fb {
							return int64(1), nil
						}
						return int64(0), nil
					}
				}
				return int64(strings.Compare(fmt.Sprintf("%v", recVal), fmt.Sprintf("%v", argVal))), nil
			case ".compareToIgnoreCase(":
				if argVal == nil {
					return int64(1), nil
				}
				return int64(strings.Compare(strings.ToLower(fmt.Sprintf("%v", recVal)), strings.ToLower(fmt.Sprintf("%v", argVal)))), nil
			case ".concat(":
				if arr, ok := recVal.([]any); ok {
					return applyArithmetic(arr, argVal, true), nil
				}
				if argVal == nil {
					return applyArithmetic(fmt.Sprintf("%v", recVal), "", true), nil
				}
				return applyArithmetic(fmt.Sprintf("%v", recVal), fmt.Sprintf("%v", argVal), true), nil
			case ".remove(":
				if m, ok := recVal.(map[string]any); ok {
					if remArgs := splitTopLevelCommaPainless(argExpr); len(remArgs) == 2 {
						kVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[0]), params, depth+1)
						vVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(remArgs[1]), params, depth+1)
						if kVal == nil {
							return false, nil
						}
						k := fmt.Sprintf("%v", kVal)
						cur, exists := m[k]
						if exists && painlessValuesEqual(cur, vVal) {
							delete(m, k)
							return true, nil
						}
						return false, nil
					}
					if argVal != nil {
						k := fmt.Sprintf("%v", argVal)
						old := m[k]
						delete(m, k)
						return old, nil
					}
				}
				if arr, ok := recVal.([]any); ok {
					tmp := map[string]any{"_arr": arr}
					return removeKeyOrIndexAtPath(tmp, []string{"_arr"}, argVal), nil
				}
				return nil, nil
			case ".plusYears(", ".minusYears(", ".plusMonths(", ".minusMonths(", ".plusWeeks(", ".minusWeeks(", ".plusDays(", ".minusDays(",
				".plusHours(", ".minusHours(", ".plusMinutes(", ".minusMinutes(", ".plusSeconds(", ".minusSeconds(", ".plusMillis(", ".minusMillis(", ".plusNanos(", ".minusNanos(",
				".plus(", ".minus(", ".multipliedBy(",
				".withYear(", ".withMonth(", ".withDayOfMonth(", ".withHour(", ".withMinute(", ".withSecond(", ".withNano(", ".truncatedTo(":
				if mName == ".plus(" {
					if bd, isBD := recVal.(*painlessBigDecimal); isBD && bd != nil {
						if mc, isMC := argVal.(painlessMathContext); isMC {
							return applyMathContextPainless(newPainlessBigDecimal(bd.unscaled, bd.scale), mc)
						}
						return newPainlessBigDecimal(bd.unscaled, bd.scale), nil
					}
				}
				if yr, isYr := recVal.(painlessYear); isYr {
					sign := int64(1)
					if mName == ".minusYears(" || mName == ".minus(" {
						sign = -1
					}
					if mName == ".plusYears(" || mName == ".minusYears(" {
						f, _ := toFloat64(argVal)
						return painlessYear{year: yr.year + sign*int64(f)}, nil
					}
					if mName == ".withYear(" {
						f, _ := toFloat64(argVal)
						return painlessYear{year: int64(f)}, nil
					}
					if mName == ".plus(" || mName == ".minus(" {
						args := splitTopLevelCommaPainless(argExpr)
						if len(args) >= 2 {
							amtVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
							if err != nil {
								return nil, err
							}
							uVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
							if err != nil {
								return nil, err
							}
							af, _ := toFloat64(amtVal)
							amt := int64(af)
							switch strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", uVal))) {
							case "YEARS":
								return painlessYear{year: yr.year + sign*amt}, nil
							case "DECADES":
								return painlessYear{year: yr.year + sign*amt*10}, nil
							case "CENTURIES":
								return painlessYear{year: yr.year + sign*amt*100}, nil
							case "MILLENNIA":
								return painlessYear{year: yr.year + sign*amt*1000}, nil
							}
						}
						if p, isPeriod := argVal.(painlessPeriod); isPeriod {
							return painlessYear{year: yr.year + sign*int64(p.years)}, nil
						}
						return yr, nil
					}
				}
				if md, isMD := recVal.(painlessMonthDay); isMD {
					if mName == ".withMonth(" {
						if mNum, okM := parseMonthNumberPainless(argVal); okM {
							return md.withMonth(mNum), nil
						}
						f, _ := toFloat64(argVal)
						return md.withMonth(int(f)), nil
					}
					if mName == ".withDayOfMonth(" {
						f, _ := toFloat64(argVal)
						return md.withDayOfMonth(int(f)), nil
					}
				}
				if mName == ".plus(" || mName == ".minus(" {
					if dow := parseDayOfWeekIndexPainless(recVal); dow >= 1 {
						if f, fOk := toFloat64(argVal); fOk {
							n := int(f)
							if mName == ".minus(" {
								n = -n
							}
							idx := ((dow-1+n)%7+7)%7 + 1
							return dayOfWeekNamePainless(idx), nil
						}
						return recVal, nil
					}
					if mo := parseMonthIndexPainless(recVal); mo >= 1 {
						if f, fOk := toFloat64(argVal); fOk {
							n := int(f)
							if mName == ".minus(" {
								n = -n
							}
							idx := ((mo-1+n)%12+12)%12 + 1
							return monthNamePainless(idx), nil
						}
						return recVal, nil
					}
				}
				if p, isPeriod := recVal.(painlessPeriod); isPeriod {
					if mName == ".plus(" || mName == ".minus(" {
						if p2, ok := parsePainlessPeriod(argVal); ok {
							if mName == ".minus(" {
								return painlessPeriod{years: p.years - p2.years, months: p.months - p2.months, days: p.days - p2.days}, nil
							}
							return painlessPeriod{years: p.years + p2.years, months: p.months + p2.months, days: p.days + p2.days}, nil
						}
						return p, nil
					}
					f, fOk := toFloat64(argVal)
					if !fOk {
						return p, nil
					}
					n := int(f)
					if strings.HasPrefix(mName, ".minus") {
						n = -n
					}
					switch mName {
					case ".plusYears(", ".minusYears(":
						p.years += n
					case ".plusMonths(", ".minusMonths(":
						p.months += n
					case ".plusDays(", ".minusDays(":
						p.days += n
					case ".multipliedBy(":
						p.years *= n
						p.months *= n
						p.days *= n
					}
					return p, nil
				}
				if dur, ok := parsePainlessDuration(recVal); ok {
					if mName == ".plus(" || mName == ".minus(" {
						pArgs := splitTopLevelCommaPainless(argExpr)
						sign := time.Duration(1)
						if mName == ".minus(" {
							sign = -1
						}
						if len(pArgs) >= 2 {
							nVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(pArgs[0]), params, depth+1)
							uVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(pArgs[1]), params, depth+1)
							if nf, nOk := toFloat64(nVal); nOk {
								n := time.Duration(int64(nf)) * sign
								unitStr := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", uVal))), "CHRONOUNIT.")
								switch unitStr {
								case "DAYS", "DAY":
									return dur + n*24*time.Hour, nil
								case "HOURS", "HOUR":
									return dur + n*time.Hour, nil
								case "MINUTES", "MINUTE":
									return dur + n*time.Minute, nil
								case "SECONDS", "SECOND":
									return dur + n*time.Second, nil
								case "MILLIS", "MILLISECONDS":
									return dur + n*time.Millisecond, nil
								case "MICROS", "MICROSECONDS":
									return dur + n*time.Microsecond, nil
								case "NANOS", "NANOSECONDS":
									return dur + n*time.Nanosecond, nil
								}
							}
							return dur, nil
						}
						if d2, ok2 := parsePainlessDuration(argVal); ok2 {
							return dur + sign*d2, nil
						}
						return dur, nil
					}
					f, fOk := toFloat64(argVal)
					if !fOk {
						return dur, nil
					}
					n := int64(f)
					if strings.HasPrefix(mName, ".minus") {
						n = -n
					}
					switch mName {
					case ".plusDays(", ".minusDays(":
						return dur + time.Duration(n)*24*time.Hour, nil
					case ".plusHours(", ".minusHours(":
						return dur + time.Duration(n)*time.Hour, nil
					case ".plusMinutes(", ".minusMinutes(":
						return dur + time.Duration(n)*time.Minute, nil
					case ".plusSeconds(", ".minusSeconds(":
						return dur + time.Duration(n)*time.Second, nil
					case ".plusMillis(", ".minusMillis(":
						return dur + time.Duration(n)*time.Millisecond, nil
					case ".plusNanos(", ".minusNanos(":
						return dur + time.Duration(n)*time.Nanosecond, nil
					case ".multipliedBy(":
						return dur * time.Duration(n), nil
					}
					return dur, nil
				}
				if tm, ok := parsePainlessDateTime(recVal); ok {
					rawRecStr := strings.TrimSpace(fmt.Sprintf("%v", recVal))
					isLocalDateOnly := len(rawRecStr) == 10 && rawRecStr[4] == '-' && rawRecStr[7] == '-'
					isYearMonthOnly := len(rawRecStr) == 7 && rawRecStr[4] == '-'
					isLocalTimeOnly := isLocalTimeOnlyStringPainless(recVal)
					if mName == ".truncatedTo(" {
						unitStr := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", argVal)))
						unitStr = strings.TrimPrefix(unitStr, "CHRONOUNIT.")
						switch unitStr {
						case "DAYS", "DAY":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), 0, 0, 0, 0, tm.Location())
						case "HOURS", "HOUR":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), 0, 0, 0, tm.Location())
						case "MINUTES", "MINUTE":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), 0, 0, tm.Location())
						case "SECONDS", "SECOND":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), 0, tm.Location())
						case "MILLIS", "MILLISECONDS":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), (tm.Nanosecond()/1e6)*1e6, tm.Location())
						case "MICROS", "MICROSECONDS":
							tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), (tm.Nanosecond()/1e3)*1e3, tm.Location())
						}
						if isLocalTimeOnly {
							return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), nil
						}
						return tm.Format(time.RFC3339Nano), nil
					}
					if mName == ".plus(" || mName == ".minus(" {
						pArgs := splitTopLevelCommaPainless(argExpr)
						sign := 1
						if mName == ".minus(" {
							sign = -1
						}
						if len(pArgs) >= 2 {
							nVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(pArgs[0]), params, depth+1)
							uVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(pArgs[1]), params, depth+1)
							if nf, nOk := toFloat64(nVal); nOk {
								n := int64(nf) * int64(sign)
								unitStr := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", uVal))), "CHRONOUNIT.")
								switch unitStr {
								case "YEARS", "YEAR":
									tm = addMonthsClampedPainless(tm, int(n)*12)
								case "MONTHS", "MONTH":
									tm = addMonthsClampedPainless(tm, int(n))
								case "WEEKS", "WEEK":
									tm = tm.AddDate(0, 0, int(n)*7)
									isYearMonthOnly = false
								case "DAYS", "DAY":
									tm = tm.AddDate(0, 0, int(n))
									isYearMonthOnly = false
								case "HOURS", "HOUR":
									tm = tm.Add(time.Duration(n) * time.Hour)
									isLocalDateOnly = false
									isYearMonthOnly = false
								case "MINUTES", "MINUTE":
									tm = tm.Add(time.Duration(n) * time.Minute)
									isLocalDateOnly = false
									isYearMonthOnly = false
								case "SECONDS", "SECOND":
									tm = tm.Add(time.Duration(n) * time.Second)
									isLocalDateOnly = false
									isYearMonthOnly = false
								case "MILLIS", "MILLISECONDS":
									tm = tm.Add(time.Duration(n) * time.Millisecond)
									isLocalDateOnly = false
									isYearMonthOnly = false
								case "MICROS", "MICROSECONDS":
									tm = tm.Add(time.Duration(n) * time.Microsecond)
									isLocalDateOnly = false
									isYearMonthOnly = false
								case "NANOS", "NANOSECONDS":
									tm = tm.Add(time.Duration(n) * time.Nanosecond)
									isLocalDateOnly = false
									isYearMonthOnly = false
								}
							}
						} else if p, okP := parsePainlessPeriod(argVal); okP {
							tm = addMonthsClampedPainless(tm, sign*(p.years*12+p.months))
							tm = tm.AddDate(0, 0, sign*p.days)
							if p.days != 0 {
								isYearMonthOnly = false
							}
						} else if d, okD := parsePainlessDuration(argVal); okD {
							tm = tm.Add(time.Duration(sign) * d)
							isLocalDateOnly = false
							isYearMonthOnly = false
						}
						if isLocalTimeOnly {
							return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), nil
						}
						if isYearMonthOnly {
							return tm.Format("2006-01"), nil
						}
						if isLocalDateOnly {
							return tm.Format("2006-01-02"), nil
						}
						return tm.Format(time.RFC3339Nano), nil
					}
					f, fOk := toFloat64(argVal)
					if !fOk {
						return recVal, nil
					}
					n := int64(f)
					if strings.HasPrefix(mName, ".minus") {
						n = -n
					}
					switch mName {
					case ".plusYears(", ".minusYears(":
						tm = addMonthsClampedPainless(tm, int(n)*12)
					case ".plusMonths(", ".minusMonths(":
						tm = addMonthsClampedPainless(tm, int(n))
					case ".plusWeeks(", ".minusWeeks(":
						tm = tm.AddDate(0, 0, int(n)*7)
						isYearMonthOnly = false
					case ".plusDays(", ".minusDays(":
						tm = tm.AddDate(0, 0, int(n))
						isYearMonthOnly = false
					case ".plusHours(", ".minusHours(":
						tm = tm.Add(time.Duration(n) * time.Hour)
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".plusMinutes(", ".minusMinutes(":
						tm = tm.Add(time.Duration(n) * time.Minute)
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".plusSeconds(", ".minusSeconds(":
						tm = tm.Add(time.Duration(n) * time.Second)
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".plusMillis(", ".minusMillis(":
						tm = tm.Add(time.Duration(n) * time.Millisecond)
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".plusNanos(", ".minusNanos(":
						tm = tm.Add(time.Duration(n) * time.Nanosecond)
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".withYear(":
						tm = time.Date(int(n), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withMonth(":
						tm = time.Date(tm.Year(), time.Month(int(n)), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
					case ".withDayOfMonth(":
						tm = time.Date(tm.Year(), tm.Month(), int(n), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
						isYearMonthOnly = false
					case ".withHour(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), int(n), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".withMinute(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), int(n), tm.Second(), tm.Nanosecond(), tm.Location())
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".withSecond(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), int(n), tm.Nanosecond(), tm.Location())
						isLocalDateOnly = false
						isYearMonthOnly = false
					case ".withNano(":
						tm = time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), int(n), tm.Location())
						isLocalDateOnly = false
						isYearMonthOnly = false
					}
					if isLocalTimeOnly {
						return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), nil
					}
					if isYearMonthOnly {
						return tm.Format("2006-01"), nil
					}
					if isLocalDateOnly {
						return tm.Format("2006-01-02"), nil
					}
					return tm.Format(time.RFC3339Nano), nil
				}
				return nil, nil
			case ".isAfter(", ".isBefore(", ".isEqual(":
				if yr1, ok1 := recVal.(painlessYear); ok1 {
					if yr2, ok2 := argVal.(painlessYear); ok2 {
						switch mName {
						case ".isAfter(":
							return yr1.year > yr2.year, nil
						case ".isBefore(":
							return yr1.year < yr2.year, nil
						case ".isEqual(":
							return yr1.year == yr2.year, nil
						}
					}
					return false, nil
				}
				if md1, ok1 := recVal.(painlessMonthDay); ok1 {
					if md2, ok2 := argVal.(painlessMonthDay); ok2 {
						switch mName {
						case ".isAfter(":
							return md1.month > md2.month || (md1.month == md2.month && md1.day > md2.day), nil
						case ".isBefore(":
							return md1.month < md2.month || (md1.month == md2.month && md1.day < md2.day), nil
						case ".isEqual(":
							return md1.month == md2.month && md1.day == md2.day, nil
						}
					}
					return false, nil
				}
				if tm1, ok1 := parsePainlessDateTime(recVal); ok1 {
					if tm2, ok2 := parsePainlessDateTime(argVal); ok2 {
						switch mName {
						case ".isAfter(":
							return tm1.After(tm2), nil
						case ".isBefore(":
							return tm1.Before(tm2), nil
						case ".isEqual(":
							return tm1.Equal(tm2), nil
						}
					}
				}
				return false, nil
			}
		}
	}

	if uVal, uHandled, uErr := evalTrailingUserObjectMethodCallPainless(sourceMap, rhs, params, depth+1); uHandled {
		return uVal, uErr
	}

	if staticVal, handled, err := evalStaticCallPainless(sourceMap, rhs, params, depth+1); handled {
		return staticVal, err
	}

	if callExpr, tailPath, ok := splitPostCallPropertyAccess(rhs); ok {
		callVal, err := evalRHSExprDepth(sourceMap, callExpr, params, depth+1)
		if err != nil || callVal == nil {
			return nil, err
		}
		return resolveParamPath(map[string]any{"_v": callVal}, append([]string{"_v"}, strings.Split(tailPath, ".")...)), nil
	}

	if strings.HasPrefix(rhs, "ctx.") || strings.HasPrefix(rhs, "ctx?.") {
		metaKey := decodeBracketSeg(strings.TrimPrefix(strings.TrimPrefix(rhs, "ctx?."), "ctx."))
		switch metaKey {
		case "op":
			if v, ok := params["_ctx_op"]; ok {
				return v, nil
			}
			return "index", nil
		case "_id":
			if v, ok := params["_ctx_id"]; ok {
				return v, nil
			}
			if v, ok := sourceMap["_id"]; ok {
				return v, nil
			}
			return nil, nil
		case "_index":
			if v, ok := params["_ctx_index"]; ok {
				return v, nil
			}
			if v, ok := sourceMap["_index"]; ok {
				return v, nil
			}
			return nil, nil
		case "_routing":
			if v, ok := params["_ctx_routing"]; ok {
				return v, nil
			}
			if v, ok := sourceMap["_routing"]; ok {
				return v, nil
			}
			return nil, nil
		case "_version":
			if v, ok := params["_ctx_version"]; ok {
				return v, nil
			}
			return nil, nil
		case "_source":
			if params["ctx"] == nil {
				return sourceMap, nil
			}
		case "_now":
			if v, ok := params["_now"]; ok && v != nil {
				if f, fOk := toFloat64(v); fOk {
					return int64(f), nil
				}
				return v, nil
			}
			return getOrInitEvalBudget(params).nowMillis, nil
		}
	}
	if rhs == "ctx" {
		nowVal := any(getOrInitEvalBudget(params).nowMillis)
		if v, ok := params["_now"]; ok && v != nil {
			if f, fOk := toFloat64(v); fOk {
				nowVal = int64(f)
			} else {
				nowVal = v
			}
		}
		ctxMap := map[string]any{
			"_source": sourceMap,
			"op":      "index",
			"_now":    nowVal,
		}
		if v, ok := params["_ctx_op"]; ok {
			ctxMap["op"] = v
		}
		if v, ok := params["_ctx_id"]; ok {
			ctxMap["_id"] = v
		} else if v, ok := sourceMap["__reindex_id"]; ok {
			ctxMap["_id"] = v
		} else if v, ok := sourceMap["_id"]; ok {
			ctxMap["_id"] = v
		}
		if v, ok := params["_ctx_index"]; ok {
			ctxMap["_index"] = v
		} else if v, ok := sourceMap["__reindex_index"]; ok {
			ctxMap["_index"] = v
		} else if v, ok := sourceMap["_index"]; ok {
			ctxMap["_index"] = v
		}
		if v, ok := params["_ctx_version"]; ok {
			ctxMap["_version"] = v
		} else if v, ok := sourceMap["__reindex_version"]; ok {
			ctxMap["_version"] = v
		}
		if v, ok := params["_ctx_routing"]; ok {
			ctxMap["_routing"] = v
		} else if v, ok := sourceMap["_routing"]; ok {
			ctxMap["_routing"] = v
		}
		return ctxMap, nil
	}
	if strings.HasPrefix(rhs, "emit(") && findMatchingDelimiter(rhs, 4, '(', ')') == len(rhs)-1 {
		argInner := strings.TrimSpace(rhs[5 : len(rhs)-1])
		args := splitTopLevelCommaPainless(argInner)
		if len(args) == 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, err
			}
			if v != nil {
				b := getOrInitEvalBudget(params)
				b.emittedVals = append(b.emittedVals, v)
			}
			return v, nil
		} else if len(args) == 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return nil, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err2 != nil {
				return nil, err2
			}
			if v1 != nil && v2 != nil {
				combined := fmt.Sprintf("%v,%v", v1, v2)
				b := getOrInitEvalBudget(params)
				b.emittedVals = append(b.emittedVals, combined)
				return combined, nil
			}
		}
		return nil, nil
	}
	if rhs == "ctx._source" || rhs == "ctx?._source" || rhs == "ctx._source?" || rhs == "ctx?._source?" {
		return sourceMap, nil
	}
	if strings.HasPrefix(rhs, "ctx._source.") || strings.HasPrefix(rhs, "ctx._source?.") ||
		strings.HasPrefix(rhs, "ctx?._source.") || strings.HasPrefix(rhs, "ctx?._source?.") {
		trimmed := rhs
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(trimmed, pfx) {
				trimmed = strings.TrimPrefix(trimmed, pfx)
				break
			}
		}
		path := strings.Split(trimmed, ".")
		if len(path) > 0 && strings.HasPrefix(decodeBracketSeg(path[0]), "__") {
			return nil, nil
		}
		return resolveParamPath(sourceMap, path), nil
	}
	if (strings.HasPrefix(rhs, "ctx.") || strings.HasPrefix(rhs, "ctx?.")) && params["ctx"] == nil {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(rhs, "ctx?."), "ctx.")
		path := strings.Split(trimmed, ".")
		if len(path) > 0 && strings.HasPrefix(decodeBracketSeg(path[0]), "__") {
			return nil, nil
		}
		return resolveParamPath(sourceMap, path), nil
	}
	for _, dProp := range []string{
		".year", ".monthValue", ".monthOfYear", ".month", ".dayOfMonth", ".dayOfYear", ".date",
		".hour", ".hourOfDay", ".minute", ".minuteOfHour", ".second", ".secondOfMinute",
		".nano", ".dayOfWeek", ".dayOfWeekEnum", ".millis",
	} {
		if strings.HasSuffix(rhs, dProp) {
			recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(dProp)], "?"))
			if recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1); err == nil && recVal != nil {
				if tm, ok := parsePainlessDateTime(recVal); ok {
					switch dProp {
					case ".year":
						return int64(tm.Year()), nil
					case ".monthValue", ".monthOfYear":
						return int64(tm.Month()), nil
					case ".month":
						return strings.ToUpper(tm.Month().String()), nil
					case ".dayOfMonth", ".date":
						return int64(tm.Day()), nil
					case ".dayOfYear":
						return int64(tm.YearDay()), nil
					case ".hour", ".hourOfDay":
						return int64(tm.Hour()), nil
					case ".minute", ".minuteOfHour":
						return int64(tm.Minute()), nil
					case ".second", ".secondOfMinute":
						return int64(tm.Second()), nil
					case ".nano":
						return int64(tm.Nanosecond()), nil
					case ".dayOfWeek":
						dow := int64(tm.Weekday())
						if dow == 0 {
							dow = 7
						}
						return dow, nil
					case ".dayOfWeekEnum":
						return strings.ToUpper(tm.Weekday().String()), nil
					case ".millis":
						return tm.UnixMilli(), nil
					}
				}
			}
		}
	}
	if strings.HasPrefix(rhs, "doc.") || strings.HasPrefix(rhs, "doc?.") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(rhs, "doc?."), "doc.")
		if strings.HasSuffix(trimmed, ".empty") {
			base := strings.TrimSuffix(trimmed, ".empty")
			if strings.HasSuffix(base, ".value") {
				val, err := evalRHSExprDepth(sourceMap, "doc."+base, params, depth+1)
				if err != nil || val == nil {
					return true, err
				}
				return fmt.Sprintf("%v", val) == "", nil
			}
			dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(base, ".values"))
			return len(dv) == 0, nil
		}
		if strings.HasSuffix(trimmed, ".length") {
			base := strings.TrimSuffix(trimmed, ".length")
			if strings.HasSuffix(base, ".value") {
				val, err := evalRHSExprDepth(sourceMap, "doc."+base, params, depth+1)
				if err != nil || val == nil {
					return int64(0), err
				}
				return int64(utf8.RuneCountInString(fmt.Sprintf("%v", val))), nil
			}
			dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(base, ".values"))
			return int64(len(dv)), nil
		}
		if strings.HasSuffix(trimmed, ".values") {
			return resolveDocValuesSlice(sourceMap, strings.TrimSuffix(trimmed, ".values")), nil
		}
		// Check `.values.<idx>` or `.<idx>` after bracket expansion (`doc['tags'].values[0]` or `doc['tags'][0]`)
		if idx := strings.LastIndex(trimmed, ".values."); idx > 0 {
			dv := resolveDocValuesSlice(sourceMap, trimmed[:idx])
			tailSeg := decodeBracketSeg(trimmed[idx+len(".values."):])
			if sIdx, ok := parseSliceIndex(tailSeg, len(dv)); ok {
				return dv[sIdx], nil
			}
			return nil, nil
		}
		if lastDot := strings.LastIndexByte(trimmed, '.'); lastDot > 0 {
			tailSeg := decodeBracketSeg(trimmed[lastDot+1:])
			if isIntegerLiteral(tailSeg) {
				dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(trimmed[:lastDot], ".values"))
				if sIdx, ok := parseSliceIndex(tailSeg, len(dv)); ok {
					return dv[sIdx], nil
				}
				return nil, nil
			}
		}
		dv := resolveDocValuesSlice(sourceMap, strings.TrimSuffix(trimmed, ".value"))
		if len(dv) == 0 {
			return nil, nil
		}
		return dv[0], nil
	}
	if strings.HasSuffix(rhs, ".empty") || strings.HasSuffix(rhs, ".length") {
		isLen := strings.HasSuffix(rhs, ".length")
		suf := ".empty"
		if isLen {
			suf = ".length"
		}
		recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:len(rhs)-len(suf)], "?"))
		var recVal any
		var err error
		if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
			recVal = sourceMap
		} else {
			recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		}
		if err == nil && recVal != nil {
			switch tv := recVal.(type) {
			case string:
				if isLen {
					return int64(utf8.RuneCountInString(tv)), nil
				}
				return len(tv) == 0, nil
			case []any:
				if isLen {
					return int64(len(tv)), nil
				}
				return len(tv) == 0, nil
			case map[string]any:
				if _, hasProp := tv[strings.TrimPrefix(suf, ".")]; !hasProp {
					if isLen {
						return int64(visiblePainlessMapLen(tv)), nil
					}
					return visiblePainlessMapLen(tv) == 0, nil
				}
			}
		}
	}
	if rhs == "params" {
		return params, nil
	}
	if rhs == "params._source" || rhs == "params?._source" {
		if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok {
			return rawSrc, nil
		}
		return sourceMap, nil
	}
	if strings.HasPrefix(rhs, "params._source.") || strings.HasPrefix(rhs, "params?._source.") ||
		strings.HasPrefix(rhs, "params._source?.") || strings.HasPrefix(rhs, "params?._source?.") {
		trimmed := rhs
		for _, pfx := range []string{"params?._source?.", "params?._source.", "params._source?.", "params._source."} {
			if strings.HasPrefix(trimmed, pfx) {
				trimmed = strings.TrimPrefix(trimmed, pfx)
				break
			}
		}
		path := strings.Split(trimmed, ".")
		if len(path) > 0 && strings.HasPrefix(decodeBracketSeg(path[0]), "__") {
			return nil, nil
		}
		if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok {
			return resolveParamPath(rawSrc, path), nil
		}
		return resolveParamPath(sourceMap, path), nil
	}
	if strings.HasPrefix(rhs, "params.") || strings.HasPrefix(rhs, "params?.") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(rhs, "params?."), "params.")
		paramPath := strings.Split(trimmed, ".")
		if len(paramPath) > 0 && isInternalPainlessMapKey(params, decodeBracketSeg(paramPath[0])) {
			return nil, nil
		}
		return resolveParamPath(params, paramPath), nil
	}
	if val, ok := params[decodeBracketSeg(rhs)]; ok {
		return val, nil
	}
	if dotIdx := strings.IndexByte(rhs, '.'); dotIdx > 0 {
		firstSeg := decodeBracketSeg(rhs[:dotIdx])
		if _, ok := params[firstSeg]; ok {
			return resolveParamPath(params, strings.Split(rhs, ".")), nil
		}
	}
	if rhs == "null" {
		return nil, nil
	}
	constRhs := rhs
	for _, pkgPfx := range []string{"java.time.format.", "java.time.temporal.", "java.time.", "java.math.", "java.lang.", "java.util.regex.", "java.nio.charset."} {
		if strings.HasPrefix(constRhs, pkgPfx) {
			constRhs = strings.TrimPrefix(constRhs, pkgPfx)
			break
		}
	}
	switch constRhs {
	case "[]", "new ArrayList()", "new LinkedList()", "new ArrayDeque()", "new PriorityQueue()", "new HashSet()", "new LinkedHashSet()", "new TreeSet()":
		return []any{}, nil
	case "[:]", "{}", "new HashMap()", "new LinkedHashMap()", "new TreeMap()":
		return map[string]any{}, nil
	case "new StringBuilder()", "new StringBuffer()":
		return &painlessStringBuilder{}, nil
	case "new BitSet()":
		return &painlessBitSet{}, nil
	case "Year.MIN_VALUE":
		return int64(-999999999), nil
	case "Year.MAX_VALUE":
		return int64(999999999), nil
	case "Period.ZERO":
		return painlessPeriod{}, nil
	case "Duration.ZERO":
		return time.Duration(0), nil
	case "LocalTime.MIN", "LocalTime.MIDNIGHT":
		return "00:00", nil
	case "LocalTime.NOON":
		return "12:00", nil
	case "LocalTime.MAX":
		return "23:59:59.999999999", nil
	case "BigDecimal.ZERO":
		return newPainlessBigDecimal(big.NewInt(0), 0), nil
	case "BigDecimal.ONE":
		return newPainlessBigDecimal(big.NewInt(1), 0), nil
	case "BigDecimal.TWO":
		return newPainlessBigDecimal(big.NewInt(2), 0), nil
	case "BigDecimal.TEN":
		return newPainlessBigDecimal(big.NewInt(10), 0), nil
	case "BigInteger.ZERO":
		return newPainlessBigInteger(big.NewInt(0)), nil
	case "BigInteger.ONE":
		return newPainlessBigInteger(big.NewInt(1)), nil
	case "BigInteger.TWO":
		return newPainlessBigInteger(big.NewInt(2)), nil
	case "BigInteger.TEN":
		return newPainlessBigInteger(big.NewInt(10)), nil
	case "MathContext.UNLIMITED":
		return painlessMathContext{precision: 0, roundingMode: "HALF_UP"}, nil
	case "MathContext.DECIMAL32":
		return painlessMathContext{precision: 7, roundingMode: "HALF_EVEN"}, nil
	case "MathContext.DECIMAL64":
		return painlessMathContext{precision: 16, roundingMode: "HALF_EVEN"}, nil
	case "MathContext.DECIMAL128":
		return painlessMathContext{precision: 34, roundingMode: "HALF_EVEN"}, nil
	case "String.CASE_INSENSITIVE_ORDER":
		return &painlessComparator{kind: "caseInsensitive"}, nil
	case "RoundingMode.UP", "BigDecimal.ROUND_UP":
		return "UP", nil
	case "RoundingMode.DOWN", "BigDecimal.ROUND_DOWN":
		return "DOWN", nil
	case "RoundingMode.CEILING", "BigDecimal.ROUND_CEILING":
		return "CEILING", nil
	case "RoundingMode.FLOOR", "BigDecimal.ROUND_FLOOR":
		return "FLOOR", nil
	case "RoundingMode.HALF_UP", "BigDecimal.ROUND_HALF_UP":
		return "HALF_UP", nil
	case "RoundingMode.HALF_DOWN", "BigDecimal.ROUND_HALF_DOWN":
		return "HALF_DOWN", nil
	case "RoundingMode.HALF_EVEN", "BigDecimal.ROUND_HALF_EVEN":
		return "HALF_EVEN", nil
	case "RoundingMode.UNNECESSARY", "BigDecimal.ROUND_UNNECESSARY":
		return "UNNECESSARY", nil
	case "ChronoUnit.YEARS":
		return "YEARS", nil
	case "ChronoUnit.MONTHS":
		return "MONTHS", nil
	case "ChronoUnit.WEEKS":
		return "WEEKS", nil
	case "ChronoUnit.DAYS":
		return "DAYS", nil
	case "ChronoUnit.HOURS":
		return "HOURS", nil
	case "ChronoUnit.MINUTES":
		return "MINUTES", nil
	case "ChronoUnit.SECONDS":
		return "SECONDS", nil
	case "ChronoUnit.MILLIS":
		return "MILLIS", nil
	case "ChronoUnit.MICROS":
		return "MICROS", nil
	case "ChronoUnit.NANOS":
		return "NANOS", nil
	case "Math.PI", "StrictMath.PI":
		return math.Pi, nil
	case "Math.E", "StrictMath.E":
		return math.E, nil
	case "Integer.MAX_VALUE":
		return int64(math.MaxInt32), nil
	case "Integer.MIN_VALUE":
		return int64(math.MinInt32), nil
	case "Long.MAX_VALUE":
		return int64(math.MaxInt64), nil
	case "Long.MIN_VALUE":
		return int64(math.MinInt64), nil
	case "Short.MAX_VALUE":
		return int64(math.MaxInt16), nil
	case "Short.MIN_VALUE":
		return int64(math.MinInt16), nil
	case "Byte.MAX_VALUE":
		return int64(math.MaxInt8), nil
	case "Byte.MIN_VALUE":
		return int64(math.MinInt8), nil
	case "Double.MAX_VALUE":
		return math.MaxFloat64, nil
	case "Double.MIN_VALUE":
		return math.SmallestNonzeroFloat64, nil
	case "Float.MAX_VALUE":
		return float64(math.MaxFloat32), nil
	case "Float.MIN_VALUE":
		return float64(math.SmallestNonzeroFloat32), nil
	case "Double.NaN", "Float.NaN":
		return math.NaN(), nil
	case "Double.POSITIVE_INFINITY", "Float.POSITIVE_INFINITY":
		return math.Inf(1), nil
	case "Double.NEGATIVE_INFINITY", "Float.NEGATIVE_INFINITY":
		return math.Inf(-1), nil
	case "Integer.SIZE", "Float.SIZE":
		return int64(32), nil
	case "Long.SIZE", "Double.SIZE":
		return int64(64), nil
	case "Short.SIZE", "Character.SIZE":
		return int64(16), nil
	case "Byte.SIZE":
		return int64(8), nil
	case "Integer.BYTES", "Float.BYTES":
		return int64(4), nil
	case "Long.BYTES", "Double.BYTES":
		return int64(8), nil
	case "Short.BYTES", "Character.BYTES":
		return int64(2), nil
	case "Byte.BYTES":
		return int64(1), nil
	case "Character.MIN_RADIX":
		return int64(2), nil
	case "Character.MAX_RADIX":
		return int64(36), nil
	case "Character.MIN_CODE_POINT", "Character.MIN_VALUE":
		return int64(0), nil
	case "Character.MAX_CODE_POINT":
		return int64(0x10FFFF), nil
	case "Character.MIN_SUPPLEMENTARY_CODE_POINT":
		return int64(0x010000), nil
	case "Character.MIN_HIGH_SURROGATE":
		return int64(0xD800), nil
	case "Character.MAX_HIGH_SURROGATE":
		return int64(0xDBFF), nil
	case "Character.MIN_LOW_SURROGATE":
		return int64(0xDC00), nil
	case "Character.MAX_LOW_SURROGATE", "Character.MAX_SURROGATE":
		return int64(0xDFFF), nil
	case "Character.MIN_SURROGATE":
		return int64(0xD800), nil
	case "Character.MAX_VALUE":
		return int64(0xFFFF), nil
	case "Pattern.UNIX_LINES":
		return int64(1), nil
	case "Pattern.CASE_INSENSITIVE":
		return int64(2), nil
	case "Pattern.COMMENTS":
		return int64(4), nil
	case "Pattern.MULTILINE":
		return int64(8), nil
	case "Pattern.LITERAL":
		return int64(16), nil
	case "Pattern.DOTALL":
		return int64(32), nil
	case "Pattern.UNICODE_CASE":
		return int64(64), nil
	case "Pattern.CANON_EQ":
		return int64(128), nil
	case "Pattern.UNICODE_CHARACTER_CLASS":
		return int64(256), nil
	case "DateTimeFormatter.ISO_LOCAL_DATE", "DateTimeFormatter.ISO_DATE":
		return "2006-01-02", nil
	case "DateTimeFormatter.BASIC_ISO_DATE":
		return "20060102", nil
	case "DateTimeFormatter.ISO_LOCAL_TIME", "DateTimeFormatter.ISO_TIME":
		return "15:04:05.999999999", nil
	case "DateTimeFormatter.ISO_LOCAL_DATE_TIME":
		return "2006-01-02T15:04:05", nil
	case "DateTimeFormatter.ISO_OFFSET_DATE_TIME", "DateTimeFormatter.ISO_ZONED_DATE_TIME", "DateTimeFormatter.ISO_INSTANT", "DateTimeFormatter.ISO_DATE_TIME":
		return time.RFC3339Nano, nil
	case "ZoneOffset.UTC":
		return "UTC", nil
	case "DayOfWeek.MONDAY", "DayOfWeek.TUESDAY", "DayOfWeek.WEDNESDAY", "DayOfWeek.THURSDAY", "DayOfWeek.FRIDAY", "DayOfWeek.SATURDAY", "DayOfWeek.SUNDAY":
		return strings.TrimPrefix(constRhs, "DayOfWeek."), nil
	case "Month.JANUARY", "Month.FEBRUARY", "Month.MARCH", "Month.APRIL", "Month.MAY", "Month.JUNE", "Month.JULY", "Month.AUGUST", "Month.SEPTEMBER", "Month.OCTOBER", "Month.NOVEMBER", "Month.DECEMBER":
		return strings.TrimPrefix(constRhs, "Month."), nil
	case "StandardCharsets.UTF_8":
		return "UTF-8", nil
	case "StandardCharsets.US_ASCII":
		return "US-ASCII", nil
	case "StandardCharsets.ISO_8859_1":
		return "ISO-8859-1", nil
	case "StandardCharsets.UTF_16":
		return "UTF-16", nil
	case "StandardCharsets.UTF_16BE":
		return "UTF-16BE", nil
	case "StandardCharsets.UTF_16LE":
		return "UTF-16LE", nil
	}
	if strings.HasPrefix(constRhs, "ChronoField.") {
		return painlessChronoField(strings.TrimPrefix(constRhs, "ChronoField.")), nil
	}
	if strings.HasPrefix(rhs, "[") && strings.HasSuffix(rhs, "]") && findMatchingDelimiter(rhs, 0, '[', ']') == len(rhs)-1 {
		inner := strings.TrimSpace(rhs[1 : len(rhs)-1])
		if inner == ":" {
			return map[string]any{}, nil
		}
		if inner != "" {
			items := splitTopLevelCommaPainless(inner)
			firstColon := -1
			firstQ := -1
			if len(items) > 0 {
				firstColon = findTopLevelOpPainless(items[0], ":")
				firstQ = findTopLevelOpPainless(items[0], "?")
			}
			if firstColon > 0 && (firstQ < 0 || firstQ > firstColon) {
				mOut := make(map[string]any, len(items))
				for _, entry := range items {
					cIdx := findTopLevelOpPainless(entry, ":")
					if cIdx <= 0 {
						continue
					}
					kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(entry[:cIdx]), params, depth+1)
					if err != nil {
						return nil, err
					}
					vVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(entry[cIdx+1:]), params, depth+1)
					if err != nil {
						return nil, err
					}
					mOut[fmt.Sprintf("%v", kVal)] = vVal
				}
				return mOut, nil
			}
			listOut := make([]any, 0, len(items))
			for _, itemExpr := range items {
				vVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(itemExpr), params, depth+1)
				if err != nil {
					return nil, err
				}
				listOut = append(listOut, vVal)
			}
			return listOut, nil
		}
	}
	if (strings.HasPrefix(rhs, "'") && strings.HasSuffix(rhs, "'")) ||
		(strings.HasPrefix(rhs, `"`) && strings.HasSuffix(rhs, `"`)) {
		if len(rhs) >= 2 {
			return unescapePainlessString(rhs[1 : len(rhs)-1]), nil
		}
	}
	numStr := stripNumericUnderscoresPainless(rhs)
	if v, ok := parseHexOrBinaryIntLiteralPainless(numStr); ok {
		return v, nil
	}
	if reNumericLiteralSuffix.MatchString(numStr) {
		numStr = numStr[:len(numStr)-1]
	}
	if strings.HasPrefix(numStr, ".") && len(numStr) > 1 && numStr[1] >= '0' && numStr[1] <= '9' {
		numStr = "0" + numStr
	} else if strings.HasPrefix(numStr, "-.") && len(numStr) > 2 && numStr[2] >= '0' && numStr[2] <= '9' {
		numStr = "-0." + numStr[2:]
	}
	dec := json.NewDecoder(strings.NewReader(numStr))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err == nil && strings.TrimSpace(numStr[dec.InputOffset():]) == "" {
		if jn, ok := parsed.(json.Number); ok {
			if iv, err := jn.Int64(); err == nil {
				return iv, nil
			}
			if fv, err := jn.Float64(); err == nil {
				return fv, nil
			}
		}
		return parsed, nil
	}
	return rhs, nil
}

func matchTrailingMethodCallPainless(s, mName string) (recExpr, argExpr string, ok bool) {
	if !strings.HasSuffix(s, ")") || len(s) <= len(mName) {
		return "", "", false
	}
	openParenIdx := -1
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		ch := s[i]
		if ch == '(' || ch == '[' {
			if depth == 0 && ch == '(' {
				openParenIdx = i
			}
			depth++
			continue
		}
		if ch == ')' || ch == ']' {
			depth--
			if depth == 0 && i < len(s)-1 {
				openParenIdx = -1
			}
		}
	}
	if depth != 0 || openParenIdx <= 0 {
		return "", "", false
	}
	prefix := s[:openParenIdx+1]
	if !strings.HasSuffix(prefix, mName) {
		return "", "", false
	}
	idx := len(prefix) - len(mName)
	if idx <= 0 {
		return "", "", false
	}
	recExpr = strings.TrimSpace(strings.TrimSuffix(s[:idx], "?"))
	argExpr = strings.TrimSpace(s[openParenIdx+1 : len(s)-1])
	return recExpr, argExpr, recExpr != ""
}

func splitTopLevelCommaPainless(s string) []string {
	var parts []string
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastStart := 0
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[lastStart:i])
				lastStart = i + 1
			}
		}
	}
	if strings.TrimSpace(s[lastStart:]) != "" {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func unescapePainlessString(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case '\'':
				sb.WriteByte('\'')
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			default:
				sb.WriteByte('\\')
				sb.WriteByte(s[i])
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func isHexDigitBytePainless(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func stripNumericUnderscoresPainless(s string) string {
	if !strings.Contains(s, "_") {
		return s
	}
	t := strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+")
	if len(t) == 0 || ((t[0] < '0' || t[0] > '9') && t[0] != '.') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			if i > 0 && i+1 < len(s) && isHexDigitBytePainless(s[i-1]) && isHexDigitBytePainless(s[i+1]) {
				continue
			}
			return s
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func stripConstructorGenericsPainless(s string) string {
	if !strings.Contains(s, "new ") || !strings.Contains(s, "<") {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			out.WriteByte(s[i])
			continue
		}
		if strings.HasPrefix(s[i:], "new ") && (i == 0 || !isIdentByte(s[i-1])) {
			j := i + 4
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			clsStart := j
			for j < len(s) && (isIdentByte(s[j]) || s[j] == '.') {
				j++
			}
			if j > clsStart {
				k := j
				for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
					k++
				}
				if k < len(s) && s[k] == '<' {
					closeAngle := findMatchingDelimiter(s, k, '<', '>')
					if closeAngle > k {
						afterAngle := strings.TrimSpace(s[closeAngle+1:])
						if strings.HasPrefix(afterAngle, "(") {
							out.WriteString(s[i:j])
							i = closeAngle
							continue
						}
					}
				}
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func evalCollectionConstructorPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	if strings.HasPrefix(rhs, "(new ") {
		closeOuter := findMatchingDelimiter(rhs, 0, '(', ')')
		if closeOuter > 0 {
			outerTail := strings.TrimSpace(rhs[closeOuter+1:])
			if outerTail == "" || strings.HasPrefix(outerTail, ".") || strings.HasPrefix(outerTail, "?.") || strings.HasPrefix(outerTail, "[") {
				innerVal, ok, err := evalCollectionConstructorPainless(sourceMap, strings.TrimSpace(rhs[1:closeOuter]), params, depth+1)
				if err != nil || !ok {
					return innerVal, ok, err
				}
				if outerTail == "" {
					return innerVal, true, nil
				}
				tmpKey := fmt.Sprintf("__painless_new_tmp_%d", depth)
				prevTmp, hadTmp := params[tmpKey]
				params[tmpKey] = innerVal
				val, err := evalRHSExprDepth(sourceMap, expandDynamicBrackets(tmpKey+outerTail, sourceMap, params, depth+1), params, depth+1)
				if hadTmp {
					params[tmpKey] = prevTmp
				} else {
					delete(params, tmpKey)
				}
				return val, true, err
			}
		}
	}
	if !strings.HasPrefix(rhs, "new ") {
		return nil, false, nil
	}
	rest := strings.TrimSpace(rhs[4:])
	idx := 0
	for idx < len(rest) && (isIdentByte(rest[idx]) || rest[idx] == '.') {
		idx++
	}
	if idx == 0 {
		return nil, false, nil
	}
	clsName := rest[:idx]
	if lastDot := strings.LastIndexByte(clsName, '.'); lastDot >= 0 {
		clsName = clsName[lastDot+1:]
	}
	remAfterType := strings.TrimSpace(rest[idx:])
	if strings.HasPrefix(remAfterType, "<") {
		closeAngle := findMatchingDelimiter(remAfterType, 0, '<', '>')
		if closeAngle >= 0 {
			remAfterType = strings.TrimSpace(remAfterType[closeAngle+1:])
		}
	}
	if strings.HasPrefix(remAfterType, "[") {
		return evalNewArrayConstructorPainless(sourceMap, clsName, remAfterType, params, depth)
	}
	isList := false
	isSet := false
	isMap := false
	isStringBuilder := false
	isString := false
	isBigDecimal := false
	isBigInteger := false
	isMathContext := false
	isBitSet := false
	isStringJoiner := false
	isUUID := false
	var userCls *painlessUserClass
	switch clsName {
	case "ArrayList", "LinkedList", "ArrayDeque", "PriorityQueue":
		isList = true
	case "HashSet", "LinkedHashSet", "TreeSet":
		isSet = true
	case "HashMap", "LinkedHashMap", "TreeMap":
		isMap = true
	case "StringBuilder", "StringBuffer":
		isStringBuilder = true
	case "String":
		isString = true
	case "BigDecimal":
		isBigDecimal = true
	case "BigInteger":
		isBigInteger = true
	case "MathContext":
		isMathContext = true
	case "BitSet":
		isBitSet = true
	case "StringJoiner":
		isStringJoiner = true
	case "UUID":
		isUUID = true
	default:
		if b := getOrInitEvalBudget(params); b != nil && b.userClasses != nil {
			userCls = b.userClasses[clsName]
		}
		if userCls == nil {
			return nil, false, nil
		}
	}
	rem := remAfterType
	if !strings.HasPrefix(rem, "(") {
		return nil, false, nil
	}
	closeParen := findMatchingDelimiter(rem, 0, '(', ')')
	if closeParen < 0 {
		return nil, false, nil
	}
	argStr := strings.TrimSpace(rem[1:closeParen])
	tail := strings.TrimSpace(rem[closeParen+1:])
	if tail != "" && !strings.HasPrefix(tail, ".") && !strings.HasPrefix(tail, "?.") {
		return nil, false, nil
	}

	var ctorVal any
	if isString {
		if argStr == "" {
			ctorVal = ""
		} else {
			cArgs := splitTopLevelCommaPainless(argStr)
			arg0Val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if len(cArgs) == 1 {
				switch tv := arg0Val.(type) {
				case nil:
					ctorVal = ""
				case *painlessStringBuilder:
					if tv == nil {
						ctorVal = ""
					} else {
						ctorVal = tv.buf
					}
				case string:
					ctorVal = tv
				case []any:
					allStrings := len(tv) > 0
					for _, el := range tv {
						if _, okS := el.(string); !okS {
							allStrings = false
							break
						}
					}
					if allStrings {
						var sb strings.Builder
						for _, el := range tv {
							sb.WriteString(el.(string))
						}
						ctorVal = sb.String()
					} else {
						ctorVal = string(toBytesPainless(tv))
					}
				default:
					ctorVal = fmt.Sprintf("%v", tv)
				}
			} else if len(cArgs) == 2 {
				if _, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1); err != nil {
					return nil, true, err
				}
				ctorVal = string(toBytesPainless(arg0Val))
			} else {
				offVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				lenVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[2]), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				if len(cArgs) >= 4 {
					if _, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[3]), params, depth+1); err != nil {
						return nil, true, err
					}
				}
				offF, _ := toFloat64(offVal)
				lenF, _ := toFloat64(lenVal)
				off, ln := int(offF), int(lenF)
				if arr, isArr := arg0Val.([]any); isArr && len(arr) > 0 {
					allStrings := true
					for _, el := range arr {
						if _, okS := el.(string); !okS {
							allStrings = false
							break
						}
					}
					if allStrings {
						if off < 0 {
							off = 0
						}
						if off > len(arr) {
							off = len(arr)
						}
						end := off + ln
						if end < off {
							end = off
						}
						if end > len(arr) {
							end = len(arr)
						}
						var sb strings.Builder
						for _, el := range arr[off:end] {
							sb.WriteString(el.(string))
						}
						ctorVal = sb.String()
					}
				}
				if ctorVal == nil {
					rawBytes := toBytesPainless(arg0Val)
					if off < 0 {
						off = 0
					}
					if off > len(rawBytes) {
						off = len(rawBytes)
					}
					end := off + ln
					if end < off {
						end = off
					}
					if end > len(rawBytes) {
						end = len(rawBytes)
					}
					ctorVal = string(rawBytes[off:end])
				}
			}
		}
	} else if isStringBuilder {
		sb := &painlessStringBuilder{}
		if argStr != "" {
			argVal, err := evalRHSExprDepth(sourceMap, argStr, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if !isNumericValuePainless(argVal) && argVal != nil {
				s := fmt.Sprintf("%v", argVal)
				if len(s) > MaxPainlessStringBytes {
					s = s[:MaxPainlessStringBytes]
				}
				sb.buf = s
			}
		}
		ctorVal = sb
	} else if isList || isSet {
		outSlice := []any{}
		if argStr != "" {
			cArgs := splitTopLevelCommaPainless(argStr)
			if len(cArgs) == 1 {
				var argVal any
				expArg := strings.TrimSpace(expandDynamicBrackets(argStr, sourceMap, params, depth+1))
				if (strings.HasPrefix(expArg, "doc.") || strings.HasPrefix(expArg, "doc?.")) &&
					!strings.HasSuffix(expArg, ".value") && !strings.Contains(expArg, ".value.") && !strings.Contains(expArg, ".values.") && !strings.Contains(expArg, "(") {
					docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expArg, "doc?."), "doc."), ".values")
					argVal = resolveDocValuesSlice(sourceMap, docPath)
				} else {
					var err error
					argVal, err = evalRHSExprDepth(sourceMap, argStr, params, depth+1)
					if err != nil {
						return nil, true, err
					}
				}
				if srcSlice, ok := argVal.([]any); ok {
					if isSet {
						outSlice = make([]any, 0, len(srcSlice))
						for _, item := range srcSlice {
							seen := false
							for _, ex := range outSlice {
								if painlessValuesEqual(item, ex) {
									seen = true
									break
								}
							}
							if !seen {
								outSlice = append(outSlice, item)
							}
						}
					} else {
						outSlice = make([]any, len(srcSlice))
						copy(outSlice, srcSlice)
					}
				}
			}
		}
		if (clsName == "TreeSet" || clsName == "PriorityQueue") && len(outSlice) > 1 {
			_ = sortPainlessSliceInPlace(outSlice, "", sourceMap, params, depth+1)
		}
		ctorVal = outSlice
	} else if isUUID {
		uArgs := splitTopLevelCommaPainless(argStr)
		if len(uArgs) < 2 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "UUID(long, long) requires 2 arguments"}
		}
		msbVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(uArgs[0]), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		lsbVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(uArgs[1]), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		msb, _ := toInt64Painless(msbVal)
		lsb, _ := toInt64Painless(lsbVal)
		uMsb := uint64(msb) // #nosec G115 -- intentional 64-bit UUID MSB bit pattern
		uLsb := uint64(lsb) // #nosec G115 -- intentional 64-bit UUID LSB bit pattern
		ctorVal = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			(uMsb>>32)&0xffffffff,
			(uMsb>>16)&0xffff,
			uMsb&0xffff,
			(uLsb>>48)&0xffff,
			uLsb&0xffffffffffff,
		)
	} else if isMap {
		outMap := map[string]any{}
		if argStr != "" {
			mArgs := splitTopLevelCommaPainless(argStr)
			if len(mArgs) == 1 {
				argVal, err := evalRHSExprDepth(sourceMap, argStr, params, depth+1)
				if err != nil {
					return nil, true, err
				}
				if srcMap, ok := argVal.(map[string]any); ok {
					outMap = make(map[string]any, len(srcMap))
					for k, v := range srcMap {
						outMap[k] = v
					}
				}
			}
		}
		ctorVal = outMap
	} else if isBigDecimal {
		if argStr == "" {
			ctorVal = newPainlessBigDecimal(big.NewInt(0), 0)
		} else {
			cArgs := splitTopLevelCommaPainless(argStr)
			arg0Val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if bi, isBI := arg0Val.(*painlessBigInteger); isBI && bi != nil && len(cArgs) >= 2 {
				arg1Val, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1)
				if err1 != nil {
					return nil, true, err1
				}
				if mc, isMC := arg1Val.(painlessMathContext); isMC {
					bd, mcErr := applyMathContextPainless(newPainlessBigDecimal(bi.val, 0), mc)
					if mcErr != nil {
						return nil, true, mcErr
					}
					ctorVal = bd
				} else if sc, okSc := toInt64Painless(arg1Val); okSc {
					bd := newPainlessBigDecimal(bi.val, int(sc))
					if len(cArgs) >= 3 {
						arg2Val, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[2]), params, depth+1)
						if err2 != nil {
							return nil, true, err2
						}
						if mc, isMC := arg2Val.(painlessMathContext); isMC {
							var mcErr error
							bd, mcErr = applyMathContextPainless(bd, mc)
							if mcErr != nil {
								return nil, true, mcErr
							}
						}
					}
					ctorVal = bd
				}
			}
			if ctorVal == nil {
				bd, ok := parsePainlessBigDecimal(arg0Val)
				if !ok {
					return nil, true, &painlessExceptionError{
						exType:  "NumberFormatException",
						message: fmt.Sprintf("For input string: %q", fmt.Sprintf("%v", arg0Val)),
					}
				}
				if len(cArgs) >= 2 {
					arg1Val, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1)
					if err1 != nil {
						return nil, true, err1
					}
					if mc, isMC := arg1Val.(painlessMathContext); isMC {
						var mcErr error
						bd, mcErr = applyMathContextPainless(bd, mc)
						if mcErr != nil {
							return nil, true, mcErr
						}
					}
				}
				ctorVal = bd
			}
		}
	} else if isBigInteger {
		cArgs := splitTopLevelCommaPainless(argStr)
		if len(cArgs) == 0 {
			ctorVal = newPainlessBigInteger(big.NewInt(0))
		} else {
			arg0Val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, isArr := arg0Val.([]any); isArr && len(cArgs) == 1 {
				if len(arr) == 0 {
					return nil, true, &painlessExceptionError{exType: "NumberFormatException", message: "Zero length BigInteger"}
				}
				ctorVal = newPainlessBigIntegerFromBytes(toBytesPainless(arr))
			} else {
				radix := 10
				if len(cArgs) >= 2 {
					rVal, rErr := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1)
					if rErr != nil {
						return nil, true, rErr
					}
					if rv, okR := toInt64Painless(rVal); okR {
						radix = int(rv)
					}
				}
				if radix < 2 || radix > 36 {
					return nil, true, &painlessExceptionError{exType: "NumberFormatException", message: fmt.Sprintf("Radix out of range: %d", radix)}
				}
				s := strings.TrimSpace(fmt.Sprintf("%v", arg0Val))
				bi := new(big.Int)
				if s == "" {
					return nil, true, &painlessExceptionError{exType: "NumberFormatException", message: "Zero length BigInteger"}
				}
				if _, ok := bi.SetString(s, radix); !ok {
					return nil, true, &painlessExceptionError{exType: "NumberFormatException", message: fmt.Sprintf("For input string: %q", s)}
				}
				ctorVal = newPainlessBigInteger(bi)
			}
		}
	} else if isMathContext {
		cArgs := splitTopLevelCommaPainless(argStr)
		prec := 0
		mode := "HALF_UP"
		if len(cArgs) >= 1 {
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[0]), params, depth+1)
			if err0 != nil {
				return nil, true, err0
			}
			if pv, okP := toInt64Painless(v0); okP {
				if pv < 0 {
					return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Digits < 0"}
				}
				prec = int(pv)
			} else if s0, isS := v0.(string); isS {
				for _, f := range strings.Fields(s0) {
					if strings.HasPrefix(f, "precision=") {
						prec, _ = strconv.Atoi(strings.TrimPrefix(f, "precision="))
					} else if strings.HasPrefix(f, "roundingMode=") {
						mode = normalizeRoundingModePainless(strings.TrimPrefix(f, "roundingMode="))
					}
				}
			}
		}
		if len(cArgs) >= 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1)
			if err1 != nil {
				return nil, true, err1
			}
			mode = normalizeRoundingModePainless(fmt.Sprintf("%v", v1))
		}
		ctorVal = painlessMathContext{precision: prec, roundingMode: mode}
	} else if isBitSet {
		if argStr != "" {
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(argStr), params, depth+1)
			if err0 != nil {
				return nil, true, err0
			}
			if nbits, okN := toInt64Painless(v0); okN && nbits < 0 {
				return nil, true, &painlessExceptionError{exType: "NegativeArraySizeException", message: fmt.Sprintf("nbits < 0: %d", nbits)}
			}
		}
		ctorVal = &painlessBitSet{}
	} else if isStringJoiner {
		cArgs := splitTopLevelCommaPainless(argStr)
		sj := &painlessStringJoiner{}
		if len(cArgs) >= 1 {
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[0]), params, depth+1)
			if err0 != nil {
				return nil, true, err0
			}
			if v0 == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "The delimiter must not be null"}
			}
			sj.delim = fmt.Sprintf("%v", v0)
		}
		if len(cArgs) >= 3 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[1]), params, depth+1)
			if err1 != nil {
				return nil, true, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(cArgs[2]), params, depth+1)
			if err2 != nil {
				return nil, true, err2
			}
			if v1 == nil || v2 == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "The prefix and suffix must not be null"}
			}
			sj.prefix = fmt.Sprintf("%v", v1)
			sj.suffix = fmt.Sprintf("%v", v2)
		}
		ctorVal = sj
	} else if userCls != nil {
		uObj, err := instantiateUserClassPainless(userCls, argStr, sourceMap, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		ctorVal = uObj
	}

	if tail != "" {
		prevTmp, hadTmp := params["__ctor_res"]
		params["__ctor_res"] = ctorVal
		res, err := evalRHSExprDepth(sourceMap, "__ctor_res"+tail, params, depth+1)
		if hadTmp {
			params["__ctor_res"] = prevTmp
		} else {
			delete(params, "__ctor_res")
		}
		return res, true, err
	}
	return ctorVal, true, nil
}

func defaultZeroForJavaArrayTypePainless(clsName string) any {
	switch clsName {
	case "int", "long", "short", "byte", "char":
		return int64(0)
	case "double", "float":
		return float64(0)
	case "boolean":
		return false
	default:
		return nil
	}
}

func allocMultiDimArrayPainless(dims []int, hasTrailingEmptyDim bool, clsName string, budget *evalBudget) ([]any, error) {
	if len(dims) == 0 {
		return []any{}, nil
	}
	n := dims[0]
	if n < 0 {
		return nil, &painlessExceptionError{exType: "NegativeArraySizeException", message: strconv.Itoa(n)}
	}
	if n > MaxPainlessSliceItems {
		return nil, fmt.Errorf("painless array size %d exceeds maximum (%d)", n, MaxPainlessSliceItems)
	}
	out := make([]any, n)
	if len(dims) == 1 {
		if hasTrailingEmptyDim {
			return out, nil
		}
		defVal := defaultZeroForJavaArrayTypePainless(clsName)
		for i := 0; i < n; i++ {
			if budget != nil {
				if err := budget.step(); err != nil {
					return nil, err
				}
			}
			out[i] = defVal
		}
		return out, nil
	}
	for i := 0; i < n; i++ {
		if budget != nil {
			if err := budget.step(); err != nil {
				return nil, err
			}
		}
		sub, err := allocMultiDimArrayPainless(dims[1:], hasTrailingEmptyDim, clsName, budget)
		if err != nil {
			return nil, err
		}
		out[i] = sub
	}
	return out, nil
}

func evalArrayBraceInitializerPainless(sourceMap map[string]any, braceExpr string, clsName string, dimDepth int, params map[string]any, depth int) ([]any, error) {
	braceExpr = strings.TrimSpace(braceExpr)
	if len(braceExpr) < 2 || braceExpr[0] != '{' || braceExpr[len(braceExpr)-1] != '}' {
		return []any{}, nil
	}
	inner := strings.TrimSpace(braceExpr[1 : len(braceExpr)-1])
	if inner == "" {
		return []any{}, nil
	}
	parts := splitTopLevelCommaPainless(inner)
	if len(parts) > 0 && strings.TrimSpace(parts[len(parts)-1]) == "" {
		parts = parts[:len(parts)-1]
	}
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		ps := strings.TrimSpace(p)
		if strings.HasPrefix(ps, "{") && strings.HasSuffix(ps, "}") {
			sub, err := evalArrayBraceInitializerPainless(sourceMap, ps, clsName, dimDepth-1, params, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, sub)
			continue
		}
		val, err := evalRHSExprDepth(sourceMap, ps, params, depth+1)
		if err != nil {
			return nil, err
		}
		if dimDepth <= 1 {
			switch clsName {
			case "int", "long", "short", "byte", "Integer", "Long", "Short", "Byte":
				if f, ok := toFloat64(val); ok {
					val = int64(f)
				}
			case "double", "float", "Double", "Float":
				if f, ok := toFloat64(val); ok {
					val = f
				}
			}
		}
		out = append(out, val)
	}
	return out, nil
}

func evalNewArrayConstructorPainless(sourceMap map[string]any, clsName string, rem string, params map[string]any, depth int) (any, bool, error) {
	pos := 0
	var dimExprs []string
	seenEmptyDim := false
	totalDims := 0
	for pos < len(rem) {
		for pos < len(rem) && (rem[pos] == ' ' || rem[pos] == '\t') {
			pos++
		}
		if pos >= len(rem) || rem[pos] != '[' {
			break
		}
		closeBr := findMatchingDelimiter(rem, pos, '[', ']')
		if closeBr < 0 {
			return nil, false, nil
		}
		dimInner := strings.TrimSpace(rem[pos+1 : closeBr])
		totalDims++
		if dimInner == "" {
			seenEmptyDim = true
		} else if !seenEmptyDim {
			dimExprs = append(dimExprs, dimInner)
		} else {
			// A non-empty bracket after an empty dimension bracket is chained indexing on the newly created array
			break
		}
		pos = closeBr + 1
	}
	if totalDims == 0 {
		return nil, false, nil
	}
	afterDims := strings.TrimSpace(rem[pos:])
	var arrVal any
	var tail string
	if strings.HasPrefix(afterDims, "{") {
		closeBrace := findMatchingDelimiter(afterDims, 0, '{', '}')
		if closeBrace < 0 {
			return nil, false, nil
		}
		initList, err := evalArrayBraceInitializerPainless(sourceMap, afterDims[:closeBrace+1], clsName, totalDims, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		arrVal = initList
		tail = strings.TrimSpace(afterDims[closeBrace+1:])
	} else {
		if len(dimExprs) == 0 {
			return nil, false, nil
		}
		dims := make([]int, len(dimExprs))
		for i, de := range dimExprs {
			dv, err := evalRHSExprDepth(sourceMap, de, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			f, ok := toFloat64(dv)
			if !ok {
				return nil, false, nil
			}
			dims[i] = int(f)
		}
		budget := getOrInitEvalBudget(params)
		allocSlice, err := allocMultiDimArrayPainless(dims, seenEmptyDim, clsName, budget)
		if err != nil {
			return nil, true, err
		}
		arrVal = allocSlice
		tail = afterDims
	}
	if tail != "" {
		if !strings.HasPrefix(tail, ".") && !strings.HasPrefix(tail, "?.") && !strings.HasPrefix(tail, "[") {
			return nil, false, nil
		}
		prevTmp, hadTmp := params["__ctor_res"]
		params["__ctor_res"] = arrVal
		res, err := evalRHSExprDepth(sourceMap, expandDynamicBrackets("__ctor_res"+tail, sourceMap, params, depth+1), params, depth+1)
		if hadTmp {
			params["__ctor_res"] = prevTmp
		} else {
			delete(params, "__ctor_res")
		}
		return res, true, err
	}
	return arrVal, true, nil
}

func hasTopLevelBooleanOrRegexOp(s string) bool {
	s = stripConstructorGenericsPainless(s)
	if strings.HasPrefix(s, "!") && !strings.HasPrefix(s, "!=") {
		if opIdx, _ := findTopLevelAddSub(s); opIdx < 0 {
			return true
		}
	}
	if len(splitTopLevelCondOp(s, "||")) > 1 || len(splitTopLevelCondOp(s, "&&")) > 1 {
		return true
	}
	for _, op := range []string{"==~", "=~", "!~", "===", "!==", "==", "!=", ">=", "<=", ">", "<", " instanceof "} {
		if findTopLevelOpPainless(s, op) > 0 {
			return true
		}
	}
	return false
}

func isPrimitiveTypeCastKeyword(s string) bool {
	switch s {
	case "int", "long", "double", "float", "short", "byte", "char", "String", "boolean",
		"Integer", "Long", "Double", "Float", "Short", "Byte", "Character", "Boolean",
		"def", "Object", "List", "Map":
		return true
	}
	return false
}

func splitLeadingTypeCastPainless(s string) (castType, rest string, ok bool) {
	if !strings.HasPrefix(s, "(") {
		return "", "", false
	}
	closeP := findMatchingDelimiter(s, 0, '(', ')')
	if closeP <= 1 || closeP >= len(s)-1 {
		return "", "", false
	}
	cand := strings.TrimSpace(s[1:closeP])
	if !isPrimitiveTypeCastKeyword(cand) {
		return "", "", false
	}
	tail := strings.TrimSpace(s[closeP+1:])
	if tail == "" {
		return "", "", false
	}
	return cand, tail, true
}

func isCastPrefixOnly(prev string) bool {
	cur := strings.TrimSpace(prev)
	strippedAny := false
	for strings.HasSuffix(cur, ")") {
		openIdx := -1
		for i := len(cur) - 2; i >= 0; i-- {
			if cur[i] == '(' && findMatchingDelimiter(cur, i, '(', ')') == len(cur)-1 {
				openIdx = i
				break
			}
		}
		if openIdx < 0 || !isPrimitiveTypeCastKeyword(strings.TrimSpace(cur[openIdx+1:len(cur)-1])) {
			break
		}
		strippedAny = true
		cur = strings.TrimSpace(cur[:openIdx])
	}
	if !strippedAny {
		return false
	}
	if cur == "" {
		return true
	}
	lastChar := cur[len(cur)-1]
	return lastChar == '+' || lastChar == '-' || lastChar == '*' || lastChar == '/' || lastChar == '%' ||
		lastChar == '(' || lastChar == ',' || lastChar == '?' || lastChar == ':' || lastChar == '=' ||
		lastChar == '<' || lastChar == '>' || lastChar == '!' || lastChar == '~' || lastChar == '&' || lastChar == '|' || lastChar == '^'
}

func findTopLevelAddSub(expr string) (int, bool) {
	inQuotes := byte(0)
	inRegexClass := false
	depth := 0
	lastIdx := -1
	lastIsAdd := false
	for i := 0; i < len(expr); i++ {
		if stepQuoteState(expr, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := expr[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '+', '-':
			if depth == 0 && i > 0 {
				if (i+1 < len(expr) && expr[i+1] == c) || expr[i-1] == c {
					continue
				}
				if (expr[i-1] == 'e' || expr[i-1] == 'E') && i >= 2 && ((expr[i-2] >= '0' && expr[i-2] <= '9') || expr[i-2] == '.') {
					continue
				}
				prev := strings.TrimSpace(expr[:i])
				if len(prev) > 0 && !isCastPrefixOnly(prev) {
					lastChar := prev[len(prev)-1]
					isPostfixIncDec := (lastChar == '+' || lastChar == '-') && len(prev) >= 3 && prev[len(prev)-2] == lastChar &&
						isBracketReceiverByte(prev[len(prev)-3])
					if (isPostfixIncDec || (lastChar != '+' && lastChar != '-')) && lastChar != '*' && lastChar != '/' && lastChar != '%' && lastChar != '(' &&
						lastChar != ',' && lastChar != '?' && lastChar != ':' && lastChar != '=' && lastChar != '<' && lastChar != '>' && lastChar != '!' && lastChar != '~' &&
						lastChar != '&' && lastChar != '|' && lastChar != '^' {
						lastIdx = i
						lastIsAdd = c == '+'
					}
				}
			}
		}
	}
	return lastIdx, lastIsAdd
}

func findTopLevelMulDiv(expr string) (int, byte) {
	inQuotes := byte(0)
	inRegexClass := false
	depth := 0
	lastIdx := -1
	lastOp := byte(0)
	for i := 0; i < len(expr); i++ {
		if stepQuoteState(expr, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := expr[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '*', '/', '%':
			if depth == 0 && i > 0 {
				lastIdx = i
				lastOp = c
			}
		}
	}
	return lastIdx, lastOp
}

func applyMulDiv(a, b any, op byte) any {
	ai, aOk := isIntegerValuePainless(a)
	bi, bOk := isIntegerValuePainless(b)
	if aOk && bOk {
		switch op {
		case '*':
			return ai * bi
		case '/':
			if bi == 0 {
				panic(&painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"})
			}
			return ai / bi
		case '%':
			if bi == 0 {
				panic(&painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"})
			}
			return ai % bi
		}
	}
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		var res float64
		switch op {
		case '*':
			res = af * bf
		case '/':
			if bf != 0 {
				res = af / bf
			}
		case '%':
			if bf != 0 {
				res = math.Mod(af, bf)
			}
		}
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return float64(0)
		}
		if res >= float64(math.MinInt64) && res < float64(math.MaxInt64) && res == float64(int64(res)) {
			return int64(res)
		}
		return res
	}
	return float64(0)
}

func applyArithmetic(a, b any, isAdd bool) any {
	if isAdd {
		if aSlice, ok := a.([]any); ok {
			if len(aSlice) >= MaxPainlessSliceItems {
				return aSlice[:MaxPainlessSliceItems]
			}
			if bSlice, ok2 := b.([]any); ok2 {
				rem := MaxPainlessSliceItems - len(aSlice)
				if len(bSlice) > rem {
					bSlice = bSlice[:rem]
				}
				out := make([]any, 0, len(aSlice)+len(bSlice))
				out = append(out, aSlice...)
				out = append(out, bSlice...)
				return out
			}
			out := make([]any, 0, len(aSlice)+1)
			out = append(out, aSlice...)
			out = append(out, b)
			return out
		}
		if aMap, ok := a.(map[string]any); ok {
			if bMap, ok2 := b.(map[string]any); ok2 {
				out := make(map[string]any, len(aMap)+len(bMap))
				for k, v := range aMap {
					out[k] = v
				}
				for k, v := range bMap {
					out[k] = v
				}
				return out
			}
		}
		_, aIsStr := a.(string)
		_, bIsStr := b.(string)
		if aIsStr || bIsStr {
			as := fmt.Sprintf("%v", a)
			if len(as) >= MaxPainlessStringBytes {
				return as[:MaxPainlessStringBytes]
			}
			bs := fmt.Sprintf("%v", b)
			if len(as)+len(bs) > MaxPainlessStringBytes {
				bs = bs[:MaxPainlessStringBytes-len(as)]
			}
			return as + bs
		}
	}
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		res := af + bf
		if !isAdd {
			res = af - bf
		}
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return float64(0)
		}
		if res >= float64(math.MinInt64) && res < float64(math.MaxInt64) && res == float64(int64(res)) {
			return int64(res)
		}
		return res
	}
	if isAdd {
		as := fmt.Sprintf("%v", a)
		if len(as) >= MaxPainlessStringBytes {
			return as[:MaxPainlessStringBytes]
		}
		bs := fmt.Sprintf("%v", b)
		if len(as)+len(bs) > MaxPainlessStringBytes {
			bs = bs[:MaxPainlessStringBytes-len(as)]
		}
		return as + bs
	}
	return a
}

func toFloat64(v any) (float64, bool) {
	var f float64
	var ok bool
	switch val := v.(type) {
	case nil:
		return 0, true
	case *painlessBigDecimal:
		if val == nil {
			return 0, true
		}
		f, ok = val.float64Value(), true
	case *painlessBigInteger:
		if val == nil {
			return 0, true
		}
		f, ok = val.float64Value(), true
	case int:
		f, ok = float64(val), true
	case int64:
		f, ok = float64(val), true
	case float64:
		f, ok = val, true
	case json.Number:
		parsed, err := val.Float64()
		f, ok = parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(val, 64)
		if err == nil {
			f, ok = parsed, true
		} else if len(val) >= 10 && val[4] == '-' && val[7] == '-' {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
				if t, tErr := time.Parse(layout, strings.TrimSpace(val)); tErr == nil {
					f, ok = float64(t.UTC().UnixMilli()), true
					break
				}
			}
		}
	default:
		return 0, false
	}
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func hasElseKeywordPrefix(s string) bool {
	return strings.HasPrefix(s, "else") && (len(s) == 4 || !isIdentByte(s[4]))
}

func hasCatchOrFinallyPrefix(s string) bool {
	if strings.HasPrefix(s, "catch") && (len(s) == 5 || !isIdentByte(s[5])) {
		return true
	}
	if strings.HasPrefix(s, "finally") && (len(s) == 7 || !isIdentByte(s[7])) {
		return true
	}
	return false
}

func stripLeadingLoopLabelPainless(s string) (label, rest string, ok bool) {
	t := strings.TrimSpace(s)
	colonIdx := strings.IndexByte(t, ':')
	if colonIdx <= 0 {
		return "", "", false
	}
	lbl := strings.TrimSpace(t[:colonIdx])
	if !reIdentOnly.MatchString(lbl) || lbl == "default" || lbl == "case" {
		return "", "", false
	}
	after := strings.TrimSpace(t[colonIdx+1:])
	for _, kw := range []string{"for", "while", "do"} {
		if strings.HasPrefix(after, kw) && (len(after) == len(kw) || after[len(kw)] == ' ' || after[len(kw)] == '\t' || after[len(kw)] == '\n' || after[len(kw)] == '(' || after[len(kw)] == '{') {
			return lbl, after, true
		}
	}
	return "", "", false
}

func hasDoWhileContinuation(curr, rem string) bool {
	t := strings.TrimSpace(curr)
	if _, stripped, ok := stripLeadingLoopLabelPainless(t); ok {
		t = stripped
	}
	if strings.HasPrefix(t, "do") && (len(t) == 2 || !isIdentByte(t[2])) {
		return strings.HasPrefix(rem, "while") && (len(rem) == 5 || !isIdentByte(rem[5]))
	}
	return false
}

func hasTrailingContinuationOp(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	for _, sfx := range []string{"&&", "||", "?:", "===", "!==", "==", "!=", ">=", "<=", "=~", "==~", ">>>", "<<", ">>", "?."} {
		if strings.HasSuffix(t, sfx) {
			return true
		}
	}
	if strings.HasSuffix(t, "++") || strings.HasSuffix(t, "--") {
		return false
	}
	last := t[len(t)-1]
	return last == '+' || last == '-' || last == '*' || last == '/' || last == '%' ||
		last == '&' || last == '|' || last == '^' || last == '<' || last == '>' ||
		last == ',' || last == '?' || last == ':' || last == '=' || last == '.'
}

func isControlBlockStmt(s string) bool {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "{") {
		return true
	}
	if _, stripped, ok := stripLeadingLoopLabelPainless(t); ok {
		t = stripped
	}
	for _, kw := range []string{"if", "for", "while", "try", "do", "switch", "class"} {
		if strings.HasPrefix(t, kw) && (len(t) == len(kw) || t[len(kw)] == ' ' || t[len(kw)] == '\t' || t[len(kw)] == '\n' || t[len(kw)] == '(' || t[len(kw)] == '{') {
			return true
		}
	}
	if openP := strings.IndexByte(t, '('); openP > 0 && reUserFuncHeaderPrefix.MatchString(strings.TrimSpace(t[:openP])) {
		return true
	}
	return false
}

func isIncompleteControlHeader(s string) bool {
	t := strings.TrimSpace(s)
	if _, stripped, ok := stripLeadingLoopLabelPainless(t); ok {
		t = stripped
	}
	if t == "" || !isControlBlockStmt(t) || strings.HasPrefix(t, "{") {
		return false
	}
	openP := strings.IndexByte(t, '(')
	closeP := findMatchingDelimiter(t, openP, '(', ')')
	if openP > 0 && closeP == len(t)-1 {
		return true
	}
	if strings.HasSuffix(t, "else") && len(t) > 4 && !isIdentByte(t[len(t)-5]) {
		return true
	}
	if strings.HasSuffix(t, ")") {
		// Check trailing `else if (...)`
		if idx := strings.LastIndex(t, "else"); idx > 0 && !isIdentByte(t[idx-1]) {
			tail := strings.TrimSpace(t[idx+4:])
			if strings.HasPrefix(tail, "if") && (len(tail) == 2 || tail[2] == ' ' || tail[2] == '\t' || tail[2] == '(') {
				op := strings.IndexByte(tail, '(')
				cp := findMatchingDelimiter(tail, op, '(', ')')
				if op > 0 && cp == len(tail)-1 {
					return true
				}
			}
		}
	}
	return false
}

func parseIfBlocks(stmt string) (cond, thenBody, elseBody string, ok bool) {
	openParen := strings.IndexByte(stmt, '(')
	closeParen := findMatchingDelimiter(stmt, openParen, '(', ')')
	if openParen < 0 || closeParen < 0 {
		return "", "", "", false
	}
	cond = strings.TrimSpace(stmt[openParen+1 : closeParen])
	rest := strings.TrimSpace(stmt[closeParen+1:])
	if strings.HasPrefix(rest, "{") {
		closeBrace := findMatchingDelimiter(rest, 0, '{', '}')
		if closeBrace < 0 {
			return "", "", "", false
		}
		thenBody = rest[1:closeBrace]
		afterThen := strings.TrimSpace(rest[closeBrace+1:])
		if hasElseKeywordPrefix(afterThen) {
			elseRest := strings.TrimSpace(afterThen[4:])
			if strings.HasPrefix(elseRest, "{") && findMatchingDelimiter(elseRest, 0, '{', '}') == len(elseRest)-1 {
				elseBody = elseRest[1 : len(elseRest)-1]
			} else {
				elseBody = elseRest
			}
		}
		return cond, thenBody, elseBody, true
	}
	// Braceless `if (cond) thenStmt; else elseStmt`
	braceDepth := 0
	parenDepth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(rest); i++ {
		if stepQuoteState(rest, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch rest[i] {
		case '(', '[':
			parenDepth++
		case ')', ']':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ';', '\n':
			if braceDepth == 0 && parenDepth == 0 {
				after := strings.TrimSpace(rest[i+1:])
				if hasElseKeywordPrefix(after) {
					thenBody = strings.TrimSpace(rest[:i])
					elseRest := strings.TrimSpace(after[4:])
					if strings.HasPrefix(elseRest, "{") && findMatchingDelimiter(elseRest, 0, '{', '}') == len(elseRest)-1 {
						elseBody = elseRest[1 : len(elseRest)-1]
					} else {
						elseBody = elseRest
					}
					return cond, thenBody, elseBody, true
				}
			}
		}
	}
	return cond, rest, "", true
}

func findMatchingDelimiter(s string, openIdx int, openChar, closeChar byte) int {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != openChar {
		return -1
	}
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := openIdx; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		c := s[i]
		switch c {
		case openChar:
			depth++
		case closeChar:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitTopLevelStatements(s string) []string {
	var out []string
	var curr strings.Builder
	braceDepth := 0
	parenDepth := 0
	inQuotes := byte(0)
	inRegexClass := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			curr.WriteByte(c)
			continue
		}
		switch c {
		case '(', '[':
			parenDepth++
			curr.WriteByte(c)
		case ')', ']':
			if parenDepth > 0 {
				parenDepth--
			}
			curr.WriteByte(c)
		case '{':
			braceDepth++
			curr.WriteByte(c)
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
			curr.WriteByte(c)
			if braceDepth == 0 && parenDepth == 0 && isControlBlockStmt(curr.String()) {
				rem := strings.TrimSpace(s[i+1:])
				if !hasElseKeywordPrefix(rem) && !hasCatchOrFinallyPrefix(rem) && !hasDoWhileContinuation(curr.String(), rem) {
					out = append(out, curr.String())
					curr.Reset()
				}
			}
		case ';', '\n':
			if braceDepth == 0 && parenDepth == 0 {
				rem := strings.TrimSpace(s[i+1:])
				if c == '\n' && (hasElseKeywordPrefix(rem) || hasCatchOrFinallyPrefix(rem) || hasDoWhileContinuation(curr.String(), rem) || isIncompleteControlHeader(curr.String()) || hasTrailingContinuationOp(curr.String()) || strings.HasPrefix(rem, ".") || strings.HasPrefix(rem, "?.")) {
					curr.WriteByte(c)
					continue
				}
				if c == ';' && isControlBlockStmt(curr.String()) && hasElseKeywordPrefix(rem) {
					curr.WriteByte(c)
					continue
				}
				if strings.TrimSpace(curr.String()) != "" {
					out = append(out, curr.String())
				}
				curr.Reset()
			} else {
				curr.WriteByte(c)
			}
		default:
			curr.WriteByte(c)
		}
	}
	if strings.TrimSpace(curr.String()) != "" {
		out = append(out, curr.String())
	}
	return out
}

func parseSliceIndex(seg string, length int) (int, bool) {
	idx, err := strconv.Atoi(seg)
	if err != nil {
		return 0, false
	}
	if idx < 0 {
		idx = length + idx
	}
	if idx < 0 || idx >= length {
		return 0, false
	}
	return idx, true
}

func resolveDocValuesSlice(sourceMap map[string]any, fieldPath string) []any {
	if sourceMap == nil || fieldPath == "" {
		return []any{}
	}
	val := resolveParamPath(sourceMap, strings.Split(fieldPath, "."))
	if val == nil && (strings.HasSuffix(fieldPath, ".keyword") || strings.HasSuffix(fieldPath, "\x00keyword")) {
		kwTrimmed := strings.TrimSuffix(strings.TrimSuffix(fieldPath, ".keyword"), "\x00keyword")
		val = resolveParamPath(sourceMap, strings.Split(kwTrimmed, "."))
	}
	if val == nil && (fieldPath == "_id" || fieldPath == "_id.keyword" || fieldPath == "_id\x00keyword") {
		val = sourceMap["__meta_id"]
	}
	if val == nil && (fieldPath == "_index" || fieldPath == "_index.keyword" || fieldPath == "_index\x00keyword") {
		val = sourceMap["__meta_index"]
	}
	if val == nil && fieldPath == "_version" {
		val = sourceMap["__meta_version"]
	}
	if val == nil {
		return []any{}
	}
	if slice, ok := val.([]any); ok {
		out := make([]any, 0, len(slice))
		for _, item := range slice {
			if item != nil {
				out = append(out, item)
			}
		}
		return out
	}
	return []any{val}
}

func resolveParamPath(params map[string]any, path []string) any {
	var curr any = params
	for i, rawSeg := range path {
		seg := decodeBracketSeg(rawSeg)
		if slice, isSlice := curr.([]any); isSlice {
			if idx, ok := parseSliceIndex(seg, len(slice)); ok {
				curr = slice[idx]
				continue
			}
			if i == len(path)-1 {
				if seg == "length" {
					return int64(len(slice))
				}
				if seg == "empty" {
					return len(slice) == 0
				}
			}
			var projected []any
			for _, elem := range slice {
				if em, ok := elem.(map[string]any); ok {
					if v := resolveParamPath(em, path[i:]); v != nil {
						if subSlice, isSub := v.([]any); isSub {
							projected = append(projected, subSlice...)
						} else {
							projected = append(projected, v)
						}
					}
				}
			}
			if len(projected) == 0 {
				return nil
			}
			return projected
		}
		if strVal, isStr := curr.(string); isStr && i == len(path)-1 {
			if seg == "length" {
				return int64(utf8.RuneCountInString(strVal))
			}
			if seg == "empty" {
				return len(strVal) == 0
			}
		}
		if uo, isUO := curr.(*painlessUserObject); isUO {
			if uo == nil || uo.fields == nil {
				return nil
			}
			curr = uo.fields[seg]
			continue
		}
		m, ok := curr.(map[string]any)
		if !ok {
			return nil
		}
		if i == 0 {
			if uo, isThis := m["this"].(*painlessUserObject); isThis && uo != nil && uo.fields != nil && seg != "this" {
				shadowed := false
				if mp, okMP := m["__method_params"].(map[string]bool); okMP && mp[seg] {
					shadowed = true
				}
				if sl, okSL := m["__script_locals"].(map[string]bool); okSL && sl[seg] {
					shadowed = true
				}
				if !shadowed {
					if fVal, hasField := uo.fields[seg]; hasField {
						curr = fVal
						continue
					}
				}
			}
		}
		val, exists := m[seg]
		if !exists {
			if i == len(path)-1 {
				if seg == "empty" {
					return visiblePainlessMapLen(m) == 0
				}
				if seg == "length" {
					return int64(visiblePainlessMapLen(m))
				}
			}
			if strings.Contains(seg, ".") {
				return resolveParamPath(m, append(strings.Split(seg, "."), path[i+1:]...))
			} else if i < len(path)-1 {
				decodedRest := make([]string, len(path)-i)
				for j := i; j < len(path); j++ {
					decodedRest[j-i] = decodeBracketSeg(path[j])
				}
				if flatVal, flatOk := m[strings.Join(decodedRest, ".")]; flatOk {
					return flatVal
				}
			}
		}
		curr = val
	}
	return curr
}

func setValueAtPath(root map[string]any, path []string, val any) {
	if len(path) == 0 {
		return
	}
	if len(path) > 1 {
		decoded := make([]string, len(path))
		for i, p := range path {
			decoded[i] = decodeBracketSeg(p)
		}
		delete(root, strings.Join(decoded, "."))
	}
	var curr any = root
	for i := 0; i < len(path)-1; i++ {
		seg := decodeBracketSeg(path[i])
		switch node := curr.(type) {
		case map[string]any:
			next, exists := node[seg]
			if !exists || next == nil {
				nextMap := make(map[string]any)
				node[seg] = nextMap
				curr = nextMap
				continue
			}
			if _, isMap := next.(map[string]any); isMap {
				curr = next
				continue
			}
			if _, isSlice := next.([]any); isSlice {
				curr = next
				continue
			}
			if _, isUO := next.(*painlessUserObject); isUO {
				curr = next
				continue
			}
			nextMap := make(map[string]any)
			node[seg] = nextMap
			curr = nextMap
		case []any:
			idx, ok := parseSliceIndex(seg, len(node))
			if !ok {
				return
			}
			if node[idx] == nil {
				node[idx] = make(map[string]any)
			}
			curr = node[idx]
		case *painlessUserObject:
			if node == nil || node.fields == nil {
				return
			}
			curr = node.fields[seg]
		default:
			return
		}
	}
	lastSeg := decodeBracketSeg(path[len(path)-1])
	switch node := curr.(type) {
	case *painlessUserObject:
		if node != nil && node.fields != nil {
			node.fields[lastSeg] = val
			if root != nil {
				if mp, okMP := root["__method_params"].(map[string]bool); !okMP || !mp[lastSeg] {
					if _, exists := root[lastSeg]; exists {
						root[lastSeg] = val
					}
				}
			}
		}
	case map[string]any:
		if len(path) == 1 {
			if uo, isThis := node["this"].(*painlessUserObject); isThis && uo != nil && uo.fields != nil && lastSeg != "this" {
				shadowed := false
				if mp, okMP := node["__method_params"].(map[string]bool); okMP && mp[lastSeg] {
					shadowed = true
				}
				if !shadowed {
					if _, hasField := uo.fields[lastSeg]; hasField {
						uo.fields[lastSeg] = val
						node[lastSeg] = val
						return
					}
				}
			}
		}
		if strings.Contains(lastSeg, ".") {
			if _, flatExists := node[lastSeg]; !flatExists {
				subSegs := strings.Split(lastSeg, ".")
				if resolveParamPath(node, subSegs) != nil {
					setValueAtPath(node, subSegs, val)
					return
				}
			}
		}
		node[lastSeg] = val
	case []any:
		if idx, ok := parseSliceIndex(lastSeg, len(node)); ok {
			node[idx] = val
		}
	}
}

func splitTopLevelSemicolonPainless(s string) []string {
	var parts []string
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	last := 0
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				parts = append(parts, s[last:i])
				last = i + 1
			}
		}
	}
	parts = append(parts, s[last:])
	return parts
}

func evalInstanceOfPainless(val any, typeName string) bool {
	if val == nil {
		return false
	}
	typeName = strings.TrimSpace(typeName)
	for _, pfx := range []string{"java.time.temporal.", "java.time.", "java.math.", "java.lang.", "java.util.regex.", "java.util."} {
		typeName = strings.TrimPrefix(typeName, pfx)
	}
	if val == painlessEmptyOptional {
		return typeName == "Optional" || typeName == "OptionalInt" || typeName == "OptionalLong" || typeName == "OptionalDouble" || typeName == "Object" || typeName == "def"
	}
	if strings.HasSuffix(typeName, "]") {
		_, ok := val.([]any)
		return ok
	}
	switch typeName {
	case "List", "ArrayList", "LinkedList", "Set", "HashSet", "LinkedHashSet", "TreeSet", "NavigableSet", "SortedSet", "Deque", "ArrayDeque", "Queue", "PriorityQueue", "Collection":
		_, ok := val.([]any)
		return ok
	case "Map", "HashMap", "LinkedHashMap", "TreeMap", "NavigableMap", "SortedMap":
		_, ok := val.(map[string]any)
		return ok
	case "UUID":
		s, ok := val.(string)
		if !ok {
			return false
		}
		_, valid := parseAndFormatUUIDPainless(s)
		return valid
	case "HexFormat":
		_, ok := val.(painlessHexFormat)
		return ok
	case "Optional", "OptionalInt", "OptionalLong", "OptionalDouble":
		return true
	case "String", "CharSequence":
		_, ok := val.(string)
		return ok
	case "StringBuilder", "StringBuffer":
		_, ok := val.(*painlessStringBuilder)
		return ok
	case "Period":
		_, ok := val.(painlessPeriod)
		return ok
	case "Duration":
		_, ok := val.(time.Duration)
		return ok
	case "Matcher":
		_, ok := val.(*painlessMatcher)
		return ok
	case "Pattern":
		if _, ok := val.(*painlessPattern); ok {
			return true
		}
		if s, ok := val.(string); ok && len(s) >= 2 && s[0] == '/' {
			return true
		}
		return false
	case "Class":
		_, ok := val.(painlessClassObject)
		return ok
	case "BigDecimal":
		_, ok := val.(*painlessBigDecimal)
		return ok
	case "BigInteger":
		_, ok := val.(*painlessBigInteger)
		return ok
	case "MathContext":
		_, ok := val.(painlessMathContext)
		return ok
	case "TemporalAdjuster", "TemporalAdjusters":
		_, ok := val.(*painlessTemporalAdjuster)
		return ok
	case "Comparator":
		_, ok := val.(*painlessComparator)
		return ok
	case "BitSet":
		_, ok := val.(*painlessBitSet)
		return ok
	case "StringJoiner":
		_, ok := val.(*painlessStringJoiner)
		return ok
	case "RoundingMode":
		_, ok := val.(string)
		return ok
	case "Year":
		_, ok := val.(painlessYear)
		return ok
	case "MonthDay":
		_, ok := val.(painlessMonthDay)
		return ok
	case "ChronoField":
		_, ok := val.(painlessChronoField)
		return ok
	case "LocalTime":
		return isLocalTimeOnlyStringPainless(val)
	case "LocalDate", "YearMonth", "LocalDateTime", "ZonedDateTime", "OffsetDateTime", "Instant":
		_, ok := parsePainlessDateTime(val)
		return ok
	case "Boolean", "boolean":
		_, ok := val.(bool)
		return ok
	case "Number":
		switch val.(type) {
		case int, int64, float64, json.Number, *painlessBigDecimal, *painlessBigInteger:
			return true
		default:
			return false
		}
	case "Integer", "Long", "Double", "Float", "int", "long", "double", "float":
		switch val.(type) {
		case int, int64, float64, json.Number:
			return true
		default:
			return false
		}
	case "Object", "def":
		return true
	default:
		if uo, ok := val.(*painlessUserObject); ok && uo != nil && uo.class != nil {
			return uo.class.name == typeName
		}
		return false
	}
}

func splitPostCallPropertyAccess(s string) (callExpr, tailPath string, ok bool) {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	lastCallEnd := -1
	for i := 0; i < len(s); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		ch := s[i]
		if ch == '(' || ch == '[' {
			depth++
			continue
		}
		if ch == ')' || ch == ']' {
			if depth > 0 {
				depth--
			}
			if depth == 0 && i+1 < len(s) {
				if s[i+1] == '.' || (i+2 < len(s) && s[i+1:i+3] == "?.") {
					lastCallEnd = i
				}
			}
		}
	}
	if depth != 0 || lastCallEnd <= 0 || lastCallEnd >= len(s)-1 {
		return "", "", false
	}
	rest := s[lastCallEnd+1:]
	rest = strings.TrimPrefix(rest, "?")
	rest = strings.TrimPrefix(rest, ".")
	if rest == "" || strings.ContainsAny(rest, "(),+-*/?:=!<>|& ") {
		return "", "", false
	}
	rest = strings.ReplaceAll(rest, "?.", ".")
	return strings.TrimSpace(s[:lastCallEnd+1]), rest, true
}

func putAllAtPath(root map[string]any, path []string, values map[string]any) {
	if len(path) == 0 {
		for k, v := range values {
			root[k] = v
		}
		return
	}
	if existing, ok := resolveParamPath(root, path).(map[string]any); ok && existing != nil {
		for k, v := range values {
			existing[k] = v
		}
		return
	}
	cp := make(map[string]any, len(values))
	for k, v := range values {
		cp[k] = v
	}
	setValueAtPath(root, path, cp)
}

func removeKeyValueAtPath(root map[string]any, parentPath []string, keyVal, expectedVal any) bool {
	if keyVal == nil {
		return false
	}
	var targetMap map[string]any
	if len(parentPath) == 0 {
		targetMap = root
	} else {
		targetMap, _ = resolveParamPath(root, parentPath).(map[string]any)
	}
	if targetMap == nil {
		return false
	}
	k := fmt.Sprintf("%v", keyVal)
	cur, exists := targetMap[k]
	if !exists || !painlessValuesEqual(cur, expectedVal) {
		return false
	}
	delete(targetMap, k)
	return true
}

func insertAllIntoSliceAtPath(root map[string]any, path []string, idxVal any, items []any, budget *evalBudget) (bool, error) {
	if len(items) == 0 {
		return false, nil
	}
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	if len(existing)+len(items) > MaxPainlessSliceItems {
		return false, fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	if budget != nil {
		for range items {
			if err := budget.step(); err != nil {
				return false, err
			}
		}
	}
	f, fOk := toFloat64(idxVal)
	idx := len(existing)
	if fOk {
		idx = int(f)
		if idx < 0 {
			idx = 0
		} else if idx > len(existing) {
			idx = len(existing)
		}
	}
	itemsCopy := make([]any, len(items))
	copy(itemsCopy, items)
	next := make([]any, 0, len(existing)+len(itemsCopy))
	next = append(next, existing[:idx]...)
	next = append(next, itemsCopy...)
	next = append(next, existing[idx:]...)
	setValueAtPath(root, path, next)
	return true, nil
}

func removeKeyOrIndexAtPath(root map[string]any, parentPath []string, keyOrIdx any) any {
	if len(parentPath) == 0 {
		if root == nil || keyOrIdx == nil {
			return nil
		}
		k := fmt.Sprintf("%v", keyOrIdx)
		if old, exists := root[k]; exists {
			delete(root, k)
			return old
		}
		if strings.Contains(k, ".") {
			segs := strings.Split(k, ".")
			return removeKeyOrIndexAtPath(root, segs[:len(segs)-1], segs[len(segs)-1])
		}
		return nil
	}
	switch target := resolveParamPath(root, parentPath).(type) {
	case map[string]any:
		if keyOrIdx == nil {
			return nil
		}
		k := fmt.Sprintf("%v", keyOrIdx)
		if old, exists := target[k]; exists {
			delete(target, k)
			return old
		}
		return nil
	case []any:
		removeAt := func(idx int) any {
			old := target[idx]
			next := make([]any, 0, len(target)-1)
			next = append(next, target[:idx]...)
			next = append(next, target[idx+1:]...)
			setValueAtPath(root, parentPath, next)
			return old
		}
		if _, isStr := keyOrIdx.(string); !isStr {
			if idx, ok := parseSliceIndex(fmt.Sprintf("%v", keyOrIdx), len(target)); ok {
				return removeAt(idx)
			}
		}
		for idx, elem := range target {
			if painlessValuesEqual(elem, keyOrIdx) {
				_ = removeAt(idx)
				return true
			}
		}
		return false
	}
	return nil
}

func setSliceElementAtPath(root map[string]any, arrPath []string, idxVal any, newVal any) any {
	if idxVal == nil {
		return nil
	}
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return nil
	}
	f, fOk := toFloat64(idxVal)
	if !fOk {
		return nil
	}
	idx, okIdx := parseSliceIndex(strconv.Itoa(int(f)), len(existing))
	if !okIdx {
		return nil
	}
	prev := existing[idx]
	next := make([]any, len(existing))
	copy(next, existing)
	next[idx] = newVal
	setValueAtPath(root, arrPath, next)
	return prev
}

func insertIntoSliceAtPath(root map[string]any, path []string, idxVal any, val any) error {
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	if len(existing) >= MaxPainlessSliceItems {
		return fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	f, fOk := toFloat64(idxVal)
	idx := len(existing)
	if fOk {
		idx = int(f)
		if idx < 0 {
			idx = 0
		} else if idx > len(existing) {
			idx = len(existing)
		}
	}
	next := make([]any, 0, len(existing)+1)
	next = append(next, existing[:idx]...)
	next = append(next, val)
	next = append(next, existing[idx:]...)
	setValueAtPath(root, path, next)
	return nil
}

func appendToSlice(root map[string]any, path []string, val any) error {
	existing, ok := resolveParamPath(root, path).([]any)
	if !ok {
		existing = []any{}
	}
	if len(existing) >= MaxPainlessSliceItems {
		return fmt.Errorf("painless array at %q exceeded maximum size (%d)", strings.Join(path, "."), MaxPainlessSliceItems)
	}
	var colKind string
	if len(path) == 1 && root != nil {
		colKind, _ = root["__col_kind_"+decodeBracketSeg(path[0])].(string)
	}
	if colKind == "TreeSet" || colKind == "Set" {
		for _, item := range existing {
			if painlessValuesEqual(item, val) {
				return nil
			}
		}
	}
	next := append(existing, val)
	if (colKind == "TreeSet" || colKind == "PriorityQueue") && len(next) > 1 {
		_ = sortPainlessSliceInPlace(next, "", nil, root, 1)
	}
	setValueAtPath(root, path, next)
	return nil
}

func applyBitwiseAssign(curVal, rhsVal any, op string) any {
	lf, ok1 := toFloat64(curVal)
	rf, ok2 := toFloat64(rhsVal)
	if !ok1 || !ok2 {
		return int64(0)
	}
	li := int64(lf)
	ri := int64(rf)
	shift := ri & 63
	switch op {
	case "&=":
		return li & ri
	case "|=":
		return li | ri
	case "^=":
		return li ^ ri
	case "<<=":
		return li << shift
	case ">>=":
		return li >> shift
	case ">>>=":
		if shift == 0 {
			return li
		}
		return ((li >> 1) & math.MaxInt64) >> (shift - 1)
	}
	return li
}

func isGoDateTimeLayoutPainless(v any, expr string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	cleanExpr := strings.TrimSpace(expr)
	if strings.HasPrefix(cleanExpr, "DateTimeFormatter.") || strings.Contains(cleanExpr, ".ofPattern(") || strings.Contains(cleanExpr, ".withZone(") || strings.Contains(cleanExpr, ".withLocale(") {
		return true
	}
	if strings.Contains(s, "@@") || strings.Contains(s, "Z07") || strings.Contains(s, "-07") {
		return true
	}
	if strings.Contains(s, "2006") || strings.Contains(s, "15:04") || strings.Contains(s, "Jan") || strings.Contains(s, "Mon") {
		return true
	}
	return false
}

func parseDayOfWeekIndexPainless(v any) int {
	if v == nil {
		return 0
	}
	if s, ok := v.(string); ok {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "MONDAY":
			return 1
		case "TUESDAY":
			return 2
		case "WEDNESDAY":
			return 3
		case "THURSDAY":
			return 4
		case "FRIDAY":
			return 5
		case "SATURDAY":
			return 6
		case "SUNDAY":
			return 7
		}
	}
	if f, ok := toFloat64(v); ok {
		iv := int(f)
		if iv >= 1 && iv <= 7 {
			return iv
		}
	}
	return 0
}

func dayOfWeekNamePainless(idx int) string {
	switch idx {
	case 1:
		return "MONDAY"
	case 2:
		return "TUESDAY"
	case 3:
		return "WEDNESDAY"
	case 4:
		return "THURSDAY"
	case 5:
		return "FRIDAY"
	case 6:
		return "SATURDAY"
	case 7:
		return "SUNDAY"
	}
	return ""
}

func parseMonthIndexPainless(v any) int {
	if v == nil {
		return 0
	}
	if s, ok := v.(string); ok {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "JANUARY":
			return 1
		case "FEBRUARY":
			return 2
		case "MARCH":
			return 3
		case "APRIL":
			return 4
		case "MAY":
			return 5
		case "JUNE":
			return 6
		case "JULY":
			return 7
		case "AUGUST":
			return 8
		case "SEPTEMBER":
			return 9
		case "OCTOBER":
			return 10
		case "NOVEMBER":
			return 11
		case "DECEMBER":
			return 12
		}
	}
	if f, ok := toFloat64(v); ok {
		iv := int(f)
		if iv >= 1 && iv <= 12 {
			return iv
		}
	}
	return 0
}

func monthNamePainless(idx int) string {
	if idx >= 1 && idx <= 12 {
		return strings.ToUpper(time.Month(idx).String())
	}
	return ""
}

func parsePainlessDateTime(v any) (time.Time, bool) {
	switch tv := v.(type) {
	case time.Time:
		return tv, true
	case string:
		s := strings.TrimSpace(tv)
		if idx := strings.IndexByte(s, '['); idx > 0 && strings.HasSuffix(s, "]") {
			s = strings.TrimSpace(s[:idx])
		}
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.999999999Z0700",
			"2006-01-02T15:04:05Z0700",
			"2006-01-02 15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05Z07:00",
			"2006-01-02 15:04:05.999999999Z0700",
			"2006-01-02 15:04:05Z0700",
			"2006-01-02T15:04:05.999999999",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04",
			"2006-01-02",
			"20060102",
			"2006-01",
			"15:04:05.999999999",
			"15:04:05",
			"15:04",
		} {
			if tm, err := time.Parse(layout, s); err == nil {
				return tm, true
			}
		}
	case int, int64, float64, json.Number:
		if f, ok := toFloat64(tv); ok {
			return time.UnixMilli(int64(f)).UTC(), true
		}
	}
	return time.Time{}, false
}

func formatLocalTimePainless(hour, minute, second, nano int) string {
	hour = ((hour % 24) + 24) % 24
	minute = ((minute % 60) + 60) % 60
	second = ((second % 60) + 60) % 60
	nano = ((nano % 1_000_000_000) + 1_000_000_000) % 1_000_000_000
	if nano > 0 {
		frac := fmt.Sprintf("%09d", nano)
		frac = strings.TrimRight(frac, "0")
		return fmt.Sprintf("%02d:%02d:%02d.%s", hour, minute, second, frac)
	}
	if second > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hour, minute, second)
	}
	return fmt.Sprintf("%02d:%02d", hour, minute)
}

func isLocalTimeOnlyStringPainless(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	if len(s) < 5 || len(s) > 18 || s[2] != ':' {
		return false
	}
	for _, layout := range []string{"15:04:05.999999999", "15:04:05", "15:04"} {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}

func mutateSliceRemoveOrRetainAtPath(root map[string]any, arrPath []string, argVal any, isRetain bool) bool {
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return false
	}
	needles, ok2 := argVal.([]any)
	if !ok2 {
		return false
	}
	filtered := make([]any, 0, len(existing))
	for _, elem := range existing {
		inNeedles := false
		for _, needle := range needles {
			if painlessValuesEqual(elem, needle) {
				inNeedles = true
				break
			}
		}
		if (isRetain && inNeedles) || (!isRetain && !inNeedles) {
			filtered = append(filtered, elem)
		}
	}
	changed := len(filtered) != len(existing)
	setValueAtPath(root, arrPath, filtered)
	return changed
}

func evalBitwiseOrShiftPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	tiers := [][]string{
		{"|"},
		{"^"},
		{"&"},
		{">>>", "<<", ">>"},
	}
	for _, tier := range tiers {
		idx, op := findLastTopLevelOpPainless(rhs, tier...)
		if idx <= 0 {
			continue
		}
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[:idx]), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		rightVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rhs[idx+len(op):]), params, depth+1)
		if err != nil {
			return nil, true, err
		}
		if lb, ok1 := leftVal.(bool); ok1 {
			if rb, ok2 := rightVal.(bool); ok2 {
				switch op {
				case "|":
					return lb || rb, true, nil
				case "^":
					return lb != rb, true, nil
				case "&":
					return lb && rb, true, nil
				}
			}
		}
		lf, ok1 := toFloat64(leftVal)
		rf, ok2 := toFloat64(rightVal)
		if !ok1 || !ok2 {
			return int64(0), true, nil
		}
		li := int64(lf)
		ri := int64(rf)
		shift := ri & 63
		switch op {
		case "|":
			return li | ri, true, nil
		case "^":
			return li ^ ri, true, nil
		case "&":
			return li & ri, true, nil
		case "<<":
			return li << shift, true, nil
		case ">>":
			return li >> shift, true, nil
		case ">>>":
			if shift == 0 {
				return li, true, nil
			}
			return ((li >> 1) & math.MaxInt64) >> (shift - 1), true, nil
		}
	}
	return nil, false, nil
}

func removeIfCondFromSlice(sourceMap, root map[string]any, arrPath []string, paramName, condExpr string, params map[string]any) (bool, error) {
	existing, ok := resolveParamPath(root, arrPath).([]any)
	if !ok {
		return false, nil
	}
	rawBody := strings.TrimSpace(condExpr)
	budget := getOrInitEvalBudget(params)
	preExistingKeys := make(map[string]bool, len(params))
	itemParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		preExistingKeys[k] = true
		itemParams[k] = v
	}
	loopDeclared := make(map[string]bool)
	itemParams["__loop_declared"] = loopDeclared
	itemParams["__eval_budget"] = budget
	filtered := make([]any, 0, len(existing))
	var iterErr error
	for _, item := range existing {
		if err := budget.step(); err != nil {
			iterErr = err
			break
		}
		itemParams[paramName] = item
		matched, err := evalPainlessPredicateLambda(rawBody, sourceMap, itemParams, 1)
		if err != nil {
			iterErr = err
			break
		}
		if matched {
			continue
		}
		filtered = append(filtered, item)
	}
	syncLoopScopeBack(params, itemParams, preExistingKeys, map[string]bool{paramName: true}, loopDeclared)
	if iterErr != nil {
		return false, iterErr
	}
	changed := len(filtered) != len(existing)
	setValueAtPath(root, arrPath, filtered)
	return changed, nil
}

func deepMergeMap(dst, src map[string]any) {
	for k, v := range src {
		if srcSubMap, ok := v.(map[string]any); ok {
			if dstSubMap, ok := dst[k].(map[string]any); ok {
				deepMergeMap(dstSubMap, srcSubMap)
				continue
			}
		}
		dst[k] = v
	}
}

func clearAtPath(root map[string]any, path []string) {
	if len(path) == 0 {
		for k := range root {
			if !isInternalPainlessMapKey(root, k) {
				delete(root, k)
			}
		}
		return
	}
	switch target := resolveParamPath(root, path).(type) {
	case map[string]any:
		for k := range target {
			if !isInternalPainlessMapKey(target, k) {
				delete(target, k)
			}
		}
	case []any:
		setValueAtPath(root, path, []any{})
	case *painlessBitSet:
		if target != nil {
			target.words = nil
		}
	}
}

func evalStaticCallPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	openParen := strings.IndexByte(rhs, '(')
	if openParen <= 0 || !strings.HasSuffix(rhs, ")") || findMatchingDelimiter(rhs, openParen, '(', ')') != len(rhs)-1 {
		return nil, false, nil
	}
	fnName := strings.TrimSpace(rhs[:openParen])
	for _, pfx := range []string{"java.time.format.", "java.time.temporal.", "java.time.", "java.math.", "java.lang.", "java.util.stream.", "java.util.regex.", "java.util.", "java.nio.charset."} {
		if strings.HasPrefix(fnName, pfx) {
			fnName = strings.TrimPrefix(fnName, pfx)
			break
		}
	}
	if strings.HasPrefix(fnName, "StrictMath.") {
		fnName = "Math." + strings.TrimPrefix(fnName, "StrictMath.")
	}
	argStr := strings.TrimSpace(rhs[openParen+1 : len(rhs)-1])
	args := splitTopLevelCommaPainless(argStr)

	evalNumArg := func(idx int) (float64, bool) {
		if idx >= len(args) {
			return 0, false
		}
		v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
		if err != nil || v == nil {
			return 0, false
		}
		return toFloat64(v)
	}
	evalInt64Arg := func(idx int) (int64, bool) {
		if idx >= len(args) {
			return 0, false
		}
		v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
		if err != nil || v == nil {
			return 0, false
		}
		return toInt64Painless(v)
	}
	formatMathResult := func(res float64) any {
		if math.IsNaN(res) || math.IsInf(res, 0) {
			return float64(0)
		}
		if res >= float64(math.MinInt64) && res < float64(math.MaxInt64) && res == float64(int64(res)) {
			return int64(res)
		}
		return res
	}

	switch fnName {
	case "Math.abs":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Abs(f)), true, nil
		}
		return int64(0), true, nil
	case "Math.min":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Min(f1, f2)), true, nil
		}
		return int64(0), true, nil
	case "Math.max":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Max(f1, f2)), true, nil
		}
		return int64(0), true, nil
	case "Math.round":
		if f, ok := evalNumArg(0); ok {
			return int64(math.Floor(f + 0.5)), true, nil
		}
		return int64(0), true, nil
	case "Math.floor":
		if f, ok := evalNumArg(0); ok {
			return math.Floor(f), true, nil
		}
		return float64(0), true, nil
	case "Math.ceil":
		if f, ok := evalNumArg(0); ok {
			return math.Ceil(f), true, nil
		}
		return float64(0), true, nil
	case "Math.pow":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Pow(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.sqrt":
		if f, ok := evalNumArg(0); ok && f >= 0 {
			return formatMathResult(math.Sqrt(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.hypot":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Hypot(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.log":
		if f, ok := evalNumArg(0); ok && f > 0 {
			return formatMathResult(math.Log(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.log10":
		if f, ok := evalNumArg(0); ok && f > 0 {
			return formatMathResult(math.Log10(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.exp":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Exp(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.signum":
		if f, ok := evalNumArg(0); ok {
			if f > 0 {
				return float64(1), true, nil
			}
			if f < 0 {
				return float64(-1), true, nil
			}
		}
		return float64(0), true, nil
	case "Math.clamp":
		v, ok1 := evalNumArg(0)
		lo, ok2 := evalNumArg(1)
		hi, ok3 := evalNumArg(2)
		if ok1 && ok2 && ok3 {
			return formatMathResult(math.Min(math.Max(v, lo), hi)), true, nil
		}
		return int64(0), true, nil
	case "Math.sin":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Sin(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.cos":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Cos(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.tan":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Tan(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.asin":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Asin(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.acos":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Acos(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.atan":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Atan(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.atan2":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Atan2(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.sinh":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Sinh(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.cosh":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Cosh(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.tanh":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Tanh(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.cbrt":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Cbrt(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.expm1":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Expm1(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.log1p":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(math.Log1p(f)), true, nil
		}
		return float64(0), true, nil
	case "Math.toRadians":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(f * math.Pi / 180.0), true, nil
		}
		return float64(0), true, nil
	case "Math.toDegrees":
		if f, ok := evalNumArg(0); ok {
			return formatMathResult(f * 180.0 / math.Pi), true, nil
		}
		return float64(0), true, nil
	case "Math.floorDiv":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 && int64(f2) != 0 {
			x, y := int64(f1), int64(f2)
			q := x / y
			if (x^y) < 0 && q*y != x {
				q--
			}
			return q, true, nil
		}
		return int64(0), true, nil
	case "Math.floorMod":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 && int64(f2) != 0 {
			x, y := int64(f1), int64(f2)
			r := x % y
			if r != 0 && (r^y) < 0 {
				r += y
			}
			return r, true, nil
		}
		return int64(0), true, nil
	case "Math.addExact":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			r := x + y
			if ((x ^ r) & (y ^ r)) < 0 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return r, true, nil
		}
		return int64(0), true, nil
	case "Math.subtractExact":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			r := x - y
			if ((x ^ y) & (x ^ r)) < 0 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return r, true, nil
		}
		return int64(0), true, nil
	case "Math.multiplyExact":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			r := x * y
			if x != 0 && y != 0 && ((x == math.MinInt64 && y == -1) || (y == math.MinInt64 && x == -1) || r/y != x) {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return r, true, nil
		}
		return int64(0), true, nil
	case "Math.incrementExact":
		if x, ok := evalInt64Arg(0); ok {
			if x == math.MaxInt64 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return x + 1, true, nil
		}
		return int64(0), true, nil
	case "Math.decrementExact":
		if x, ok := evalInt64Arg(0); ok {
			if x == math.MinInt64 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return x - 1, true, nil
		}
		return int64(0), true, nil
	case "Math.negateExact":
		if x, ok := evalInt64Arg(0); ok {
			if x == math.MinInt64 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return -x, true, nil
		}
		return int64(0), true, nil
	case "Math.toIntExact":
		if x, ok := evalInt64Arg(0); ok {
			if x < math.MinInt32 || x > math.MaxInt32 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "integer overflow"}
			}
			return int64(int32(x)), true, nil // #nosec G115 -- bounds checked in MinInt32..MaxInt32
		}
		return int64(0), true, nil
	case "Math.ulp":
		if f, ok := evalNumArg(0); ok {
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return float64(0), true, nil
			}
			if f == math.MaxFloat64 || f == -math.MaxFloat64 {
				return math.Pow(2, 971), true, nil
			}
			return math.Abs(math.Nextafter(f, math.Inf(1)) - f), true, nil
		}
		return float64(0), true, nil
	case "Math.nextAfter":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return math.Nextafter(f1, f2), true, nil
		}
		return float64(0), true, nil
	case "Math.nextUp":
		if f, ok := evalNumArg(0); ok {
			return math.Nextafter(f, math.Inf(1)), true, nil
		}
		return float64(0), true, nil
	case "Math.nextDown":
		if f, ok := evalNumArg(0); ok {
			return math.Nextafter(f, math.Inf(-1)), true, nil
		}
		return float64(0), true, nil
	case "Math.IEEEremainder":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 && f2 != 0 {
			return formatMathResult(math.Remainder(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.copySign":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Copysign(f1, f2)), true, nil
		}
		return float64(0), true, nil
	case "Math.scalb":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return formatMathResult(math.Ldexp(f1, int(f2))), true, nil
		}
		return float64(0), true, nil
	case "Math.getExponent":
		if f, ok := evalNumArg(0); ok {
			if f == 0 {
				return int64(-1023), true, nil
			}
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return int64(1024), true, nil
			}
			_, exp := math.Frexp(math.Abs(f))
			return int64(exp - 1), true, nil
		}
		return int64(0), true, nil
	case "Integer.parseInt", "Long.parseLong", "Short.parseShort", "Byte.parseByte",
		"Integer.valueOf", "Long.valueOf", "Short.valueOf", "Byte.valueOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(0), true, err
			}
			wrapIntResult := func(iv int64) int64 {
				switch fnName {
				case "Integer.parseInt", "Integer.valueOf":
					return int64(int32(iv)) // #nosec G115 -- intentional Java 32-bit signed integer wrap
				case "Short.parseShort", "Short.valueOf":
					return int64(int16(iv)) // #nosec G115 -- intentional Java 16-bit signed short wrap
				case "Byte.parseByte", "Byte.valueOf":
					return int64(int8(iv)) // #nosec G115 -- intentional Java 8-bit signed byte wrap
				default:
					return iv
				}
			}
			if v != nil && len(args) == 1 {
				switch tv := v.(type) {
				case int:
					return wrapIntResult(int64(tv)), true, nil
				case int64:
					return wrapIntResult(tv), true, nil
				case float64:
					return wrapIntResult(int64(tv)), true, nil
				case json.Number:
					if iv, pErr := tv.Int64(); pErr == nil {
						return wrapIntResult(iv), true, nil
					}
					if fv, fErr := tv.Float64(); fErr == nil {
						return wrapIntResult(int64(fv)), true, nil
					}
				}
			}
			base := 10
			if len(args) >= 2 {
				if bf, ok := evalNumArg(1); ok && int(bf) >= 2 && int(bf) <= 36 {
					base = int(bf)
				}
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if v != nil {
				if iv, pErr := strconv.ParseInt(s, base, 64); pErr == nil {
					return wrapIntResult(iv), true, nil
				}
			}
			return int64(0), true, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", s),
			}
		}
		return int64(0), true, nil
	case "Double.parseDouble", "Float.parseFloat", "Double.valueOf", "Float.valueOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return float64(0), true, err
			}
			if v != nil {
				switch tv := v.(type) {
				case int, int64, float64, json.Number:
					if f, ok := toFloat64(tv); ok {
						return f, true, nil
					}
				case string:
					if fv, pErr := strconv.ParseFloat(strings.TrimSpace(tv), 64); pErr == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						return fv, true, nil
					}
				}
			}
			return float64(0), true, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", fmt.Sprintf("%v", v)),
			}
		}
		return float64(0), true, nil
	case "Boolean.valueOf", "Boolean.parseBoolean":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			if b, ok := v.(bool); ok {
				return b, true, nil
			}
			return strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v)), "true"), true, nil
		}
		return false, true, nil
	case "Integer.toString", "Long.toString", "Short.toString", "Byte.toString":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			base := 10
			if len(args) >= 2 {
				if bf, ok := evalNumArg(1); ok && int(bf) >= 2 && int(bf) <= 36 {
					base = int(bf)
				}
			}
			if f, ok := toFloat64(v); ok {
				iv := int64(f)
				switch fnName {
				case "Integer.toString":
					iv = int64(int32(iv)) // #nosec G115 -- intentional Java 32-bit signed integer wrap
				case "Short.toString":
					iv = int64(int16(iv)) // #nosec G115 -- intentional Java 16-bit signed short wrap
				case "Byte.toString":
					iv = int64(int8(iv)) // #nosec G115 -- intentional Java 8-bit signed byte wrap
				}
				return strconv.FormatInt(iv, base), true, nil
			}
			return fmt.Sprintf("%v", v), true, nil
		}
		return "", true, nil
	case "Double.toString", "Float.toString":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			if f, ok := toFloat64(v); ok {
				return strconv.FormatFloat(f, 'f', -1, 64), true, nil
			}
			return fmt.Sprintf("%v", v), true, nil
		}
		return "", true, nil
	case "Boolean.toString":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "false", true, err
			}
			if b, ok := v.(bool); ok {
				if b {
					return "true", true, nil
				}
				return "false", true, nil
			}
			if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v)), "true") {
				return "true", true, nil
			}
		}
		return "false", true, nil
	case "Integer.toHexString", "Integer.toBinaryString", "Integer.toOctalString",
		"Long.toHexString", "Long.toBinaryString", "Long.toOctalString":
		if iv, ok := evalInt64Arg(0); ok {
			base := 16
			if strings.HasSuffix(fnName, "BinaryString") {
				base = 2
			} else if strings.HasSuffix(fnName, "OctalString") {
				base = 8
			}
			if strings.HasPrefix(fnName, "Integer.") {
				return strconv.FormatUint(uint64(uint32(int32(iv))), base), true, nil // #nosec G115 -- intentional Java 32-bit unsigned two's-complement formatting
			}
			return strconv.FormatUint(uint64(iv), base), true, nil // #nosec G115 -- intentional Java 64-bit unsigned two's-complement formatting
		}
		return "0", true, nil
	case "Integer.toUnsignedString", "Long.toUnsignedString":
		if iv, ok := evalInt64Arg(0); ok {
			base := 10
			if len(args) >= 2 {
				if bf, okB := evalNumArg(1); okB && int(bf) >= 2 && int(bf) <= 36 {
					base = int(bf)
				}
			}
			if fnName == "Integer.toUnsignedString" {
				return strconv.FormatUint(uint64(uint32(int32(iv))), base), true, nil // #nosec G115 -- intentional Java 32-bit unsigned formatting
			}
			return strconv.FormatUint(uint64(iv), base), true, nil // #nosec G115 -- intentional Java 64-bit unsigned formatting
		}
		return "0", true, nil
	case "Integer.parseUnsignedInt", "Long.parseUnsignedLong":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(0), true, err
			}
			base := 10
			if len(args) >= 2 {
				if bf, okB := evalNumArg(1); okB && int(bf) >= 2 && int(bf) <= 36 {
					base = int(bf)
				}
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			bitSize := 64
			if fnName == "Integer.parseUnsignedInt" {
				bitSize = 32
			}
			if v != nil {
				if uv, pErr := strconv.ParseUint(s, base, bitSize); pErr == nil {
					if bitSize == 32 {
						return int64(int32(uint32(uv))), true, nil // #nosec G115 -- intentional Java 32-bit signed reinterpretation of unsigned int
					}
					return int64(uv), true, nil // #nosec G115 -- intentional Java 64-bit signed reinterpretation of unsigned long
				}
			}
			return int64(0), true, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", s),
			}
		}
		return int64(0), true, nil
	case "Integer.compareUnsigned", "Long.compareUnsigned":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			var ux, uy uint64
			if fnName == "Integer.compareUnsigned" {
				ux = uint64(uint32(int32(x))) // #nosec G115 -- intentional Java 32-bit unsigned comparison
				uy = uint64(uint32(int32(y))) // #nosec G115 -- intentional Java 32-bit unsigned comparison
			} else {
				ux = uint64(x) // #nosec G115 -- intentional Java 64-bit unsigned comparison
				uy = uint64(y) // #nosec G115 -- intentional Java 64-bit unsigned comparison
			}
			if ux < uy {
				return int64(-1), true, nil
			}
			if ux > uy {
				return int64(1), true, nil
			}
		}
		return int64(0), true, nil
	case "Integer.divideUnsigned", "Long.divideUnsigned":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			if fnName == "Integer.divideUnsigned" {
				ux := uint32(int32(x)) // #nosec G115 -- intentional Java 32-bit unsigned division
				uy := uint32(int32(y)) // #nosec G115 -- intentional Java 32-bit unsigned division
				if uy == 0 {
					return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
				}
				return int64(int32(ux / uy)), true, nil // #nosec G115 -- intentional Java 32-bit signed return
			}
			ux := uint64(x) // #nosec G115 -- intentional Java 64-bit unsigned division
			uy := uint64(y) // #nosec G115 -- intentional Java 64-bit unsigned division
			if uy == 0 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
			}
			return int64(ux / uy), true, nil // #nosec G115 -- intentional Java 64-bit signed return
		}
		return int64(0), true, nil
	case "Integer.remainderUnsigned", "Long.remainderUnsigned":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			if fnName == "Integer.remainderUnsigned" {
				ux := uint32(int32(x)) // #nosec G115 -- intentional Java 32-bit unsigned remainder
				uy := uint32(int32(y)) // #nosec G115 -- intentional Java 32-bit unsigned remainder
				if uy == 0 {
					return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
				}
				return int64(int32(ux % uy)), true, nil // #nosec G115 -- intentional Java 32-bit signed return
			}
			ux := uint64(x) // #nosec G115 -- intentional Java 64-bit unsigned remainder
			uy := uint64(y) // #nosec G115 -- intentional Java 64-bit unsigned remainder
			if uy == 0 {
				return int64(0), true, &painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}
			}
			return int64(ux % uy), true, nil // #nosec G115 -- intentional Java 64-bit signed return
		}
		return int64(0), true, nil
	case "Integer.compare", "Long.compare", "Short.compare", "Byte.compare", "Double.compare", "Float.compare":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			if f1 < f2 {
				return int64(-1), true, nil
			}
			if f1 > f2 {
				return int64(1), true, nil
			}
		}
		return int64(0), true, nil
	case "Boolean.compare":
		if len(args) >= 2 {
			v1, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			v2, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			b1, ok1 := v1.(bool)
			if !ok1 {
				b1 = strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v1)), "true")
			}
			b2, ok2 := v2.(bool)
			if !ok2 {
				b2 = strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v2)), "true")
			}
			if b1 == b2 {
				return int64(0), true, nil
			}
			if b1 {
				return int64(1), true, nil
			}
			return int64(-1), true, nil
		}
		return int64(0), true, nil
	case "BigInteger.valueOf":
		if len(args) >= 1 {
			if iv, ok := evalInt64Arg(0); ok {
				return newPainlessBigInteger(big.NewInt(iv)), true, nil
			}
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err0 != nil {
				return nil, true, err0
			}
			if bi, ok := parsePainlessBigInteger(v0); ok {
				return bi, true, nil
			}
		}
		return newPainlessBigInteger(big.NewInt(0)), true, nil
	case "BitSet.valueOf":
		if len(args) >= 1 {
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err0 != nil {
				return nil, true, err0
			}
			return newPainlessBitSetFromValueOf(v0), true, nil
		}
		return &painlessBitSet{}, true, nil
	case "BigDecimal.valueOf":
		if len(args) >= 1 {
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err0 != nil {
				return nil, true, err0
			}
			if len(args) >= 2 {
				if iv, ok1 := toInt64Painless(v0); ok1 {
					if sc, ok2 := evalInt64Arg(1); ok2 {
						return newPainlessBigDecimal(big.NewInt(iv), int(sc)), true, nil
					}
				}
			}
			if bd, ok := parsePainlessBigDecimal(v0); ok {
				return bd, true, nil
			}
		}
		return newPainlessBigDecimal(big.NewInt(0), 0), true, nil
	case "RoundingMode.valueOf":
		if len(args) >= 1 {
			v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err0 != nil {
				return "", true, err0
			}
			if iv, ok := toInt64Painless(v0); ok {
				switch iv {
				case 0:
					return "UP", true, nil
				case 1:
					return "DOWN", true, nil
				case 2:
					return "CEILING", true, nil
				case 3:
					return "FLOOR", true, nil
				case 4:
					return "HALF_UP", true, nil
				case 5:
					return "HALF_DOWN", true, nil
				case 6:
					return "HALF_EVEN", true, nil
				case 7:
					return "UNNECESSARY", true, nil
				}
			}
			return strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", v0))), true, nil
		}
		return "HALF_UP", true, nil
	case "Integer.sum", "Long.sum":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			if fnName == "Integer.sum" {
				return int64(int32(x) + int32(y)), true, nil // #nosec G115 -- intentional Java 32-bit signed integer wrap
			}
			return x + y, true, nil
		}
		return int64(0), true, nil
	case "Double.sum", "Float.sum":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return f1 + f2, true, nil
		}
		return float64(0), true, nil
	case "Integer.max", "Long.max":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			if x >= y {
				return x, true, nil
			}
			return y, true, nil
		}
		return int64(0), true, nil
	case "Integer.min", "Long.min":
		x, ok1 := evalInt64Arg(0)
		y, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			if x <= y {
				return x, true, nil
			}
			return y, true, nil
		}
		return int64(0), true, nil
	case "Double.max", "Float.max":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return math.Max(f1, f2), true, nil
		}
		return float64(0), true, nil
	case "Double.min", "Float.min":
		f1, ok1 := evalNumArg(0)
		f2, ok2 := evalNumArg(1)
		if ok1 && ok2 {
			return math.Min(f1, f2), true, nil
		}
		return float64(0), true, nil
	case "Integer.bitCount", "Long.bitCount":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.bitCount" {
				return int64(bits.OnesCount32(uint32(int32(iv)))), true, nil // #nosec G115 -- intentional Java 32-bit bitCount
			}
			return int64(bits.OnesCount64(uint64(iv))), true, nil // #nosec G115 -- intentional Java 64-bit bitCount
		}
		return int64(0), true, nil
	case "Integer.highestOneBit", "Long.highestOneBit":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.highestOneBit" {
				u := uint32(int32(iv)) // #nosec G115 -- intentional Java 32-bit bit manipulation
				if u == 0 {
					return int64(0), true, nil
				}
				return int64(int32(uint32(1) << (31 - bits.LeadingZeros32(u)))), true, nil // #nosec G115 -- intentional Java 32-bit signed return
			}
			u := uint64(iv) // #nosec G115 -- intentional Java 64-bit bit manipulation
			if u == 0 {
				return int64(0), true, nil
			}
			return int64(uint64(1) << (63 - bits.LeadingZeros64(u))), true, nil // #nosec G115 -- intentional Java 64-bit signed return
		}
		return int64(0), true, nil
	case "Integer.lowestOneBit", "Long.lowestOneBit":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.lowestOneBit" {
				s := int32(iv) // #nosec G115 -- intentional Java 32-bit signed wrap
				return int64(s & -s), true, nil
			}
			return iv & -iv, true, nil
		}
		return int64(0), true, nil
	case "Integer.numberOfLeadingZeros", "Long.numberOfLeadingZeros":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.numberOfLeadingZeros" {
				return int64(bits.LeadingZeros32(uint32(int32(iv)))), true, nil // #nosec G115 -- intentional Java 32-bit leading zeros
			}
			return int64(bits.LeadingZeros64(uint64(iv))), true, nil // #nosec G115 -- intentional Java 64-bit leading zeros
		}
		return int64(0), true, nil
	case "Integer.numberOfTrailingZeros", "Long.numberOfTrailingZeros":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.numberOfTrailingZeros" {
				return int64(bits.TrailingZeros32(uint32(int32(iv)))), true, nil // #nosec G115 -- intentional Java 32-bit trailing zeros
			}
			return int64(bits.TrailingZeros64(uint64(iv))), true, nil // #nosec G115 -- intentional Java 64-bit trailing zeros
		}
		return int64(0), true, nil
	case "Integer.rotateLeft", "Long.rotateLeft", "Integer.rotateRight", "Long.rotateRight":
		iv, ok1 := evalInt64Arg(0)
		dist, ok2 := evalInt64Arg(1)
		if ok1 && ok2 {
			k := int(dist)
			if strings.HasSuffix(fnName, "Right") {
				k = -k
			}
			if strings.HasPrefix(fnName, "Integer.") {
				return int64(int32(bits.RotateLeft32(uint32(int32(iv)), k))), true, nil // #nosec G115 -- intentional Java 32-bit rotate
			}
			return int64(bits.RotateLeft64(uint64(iv), k)), true, nil // #nosec G115 -- intentional Java 64-bit rotate
		}
		return int64(0), true, nil
	case "Integer.reverse", "Long.reverse":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.reverse" {
				return int64(int32(bits.Reverse32(uint32(int32(iv))))), true, nil // #nosec G115 -- intentional Java 32-bit bit reverse
			}
			return int64(bits.Reverse64(uint64(iv))), true, nil // #nosec G115 -- intentional Java 64-bit bit reverse
		}
		return int64(0), true, nil
	case "Integer.reverseBytes", "Long.reverseBytes", "Short.reverseBytes":
		if iv, ok := evalInt64Arg(0); ok {
			switch fnName {
			case "Integer.reverseBytes":
				return int64(int32(bits.ReverseBytes32(uint32(int32(iv))))), true, nil // #nosec G115 -- intentional Java 32-bit byte reverse
			case "Short.reverseBytes":
				return int64(int16(bits.ReverseBytes16(uint16(int16(iv))))), true, nil // #nosec G115 -- intentional Java 16-bit byte reverse
			default:
				return int64(bits.ReverseBytes64(uint64(iv))), true, nil // #nosec G115 -- intentional Java 64-bit byte reverse
			}
		}
		return int64(0), true, nil
	case "Integer.signum", "Long.signum":
		if iv, ok := evalInt64Arg(0); ok {
			if fnName == "Integer.signum" {
				iv = int64(int32(iv)) // #nosec G115 -- intentional Java 32-bit signum
			}
			if iv > 0 {
				return int64(1), true, nil
			}
			if iv < 0 {
				return int64(-1), true, nil
			}
		}
		return int64(0), true, nil
	case "Integer.decode", "Long.decode", "Short.decode", "Byte.decode":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(0), true, err
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			neg := false
			rest := s
			if strings.HasPrefix(rest, "-") {
				neg = true
				rest = rest[1:]
			} else if strings.HasPrefix(rest, "+") {
				rest = rest[1:]
			}
			base := 10
			if strings.HasPrefix(rest, "0x") || strings.HasPrefix(rest, "0X") {
				base = 16
				rest = rest[2:]
			} else if strings.HasPrefix(rest, "#") {
				base = 16
				rest = rest[1:]
			} else if strings.HasPrefix(rest, "0") && len(rest) > 1 {
				base = 8
				rest = rest[1:]
			}
			if neg {
				rest = "-" + rest
			}
			if iv, pErr := strconv.ParseInt(rest, base, 64); pErr == nil {
				switch fnName {
				case "Integer.decode":
					return int64(int32(iv)), true, nil // #nosec G115 -- intentional Java 32-bit wrap
				case "Short.decode":
					return int64(int16(iv)), true, nil // #nosec G115 -- intentional Java 16-bit wrap
				case "Byte.decode":
					return int64(int8(iv)), true, nil // #nosec G115 -- intentional Java 8-bit wrap
				default:
					return iv, true, nil
				}
			}
			return int64(0), true, &painlessExceptionError{
				exType:  "NumberFormatException",
				message: fmt.Sprintf("For input string: %q", s),
			}
		}
		return int64(0), true, nil
	case "Double.isNaN", "Float.isNaN":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			if f, ok := v.(float64); ok {
				return math.IsNaN(f), true, nil
			}
		}
		return false, true, nil
	case "Double.isInfinite", "Float.isInfinite":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			if f, ok := v.(float64); ok {
				return math.IsInf(f, 0), true, nil
			}
		}
		return false, true, nil
	case "Double.isFinite", "Float.isFinite":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			if f, ok := v.(float64); ok {
				return !math.IsNaN(f) && !math.IsInf(f, 0), true, nil
			}
			if isNumericValuePainless(v) {
				return true, true, nil
			}
		}
		return false, true, nil
	case "Objects.equals":
		if len(args) >= 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return false, true, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err2 != nil {
				return false, true, err2
			}
			return painlessValuesEqual(v1, v2), true, nil
		}
		return false, true, nil
	case "Objects.isNull":
		if len(args) >= 1 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return false, true, err1
			}
			return isEmptyOptionalOrNilPainless(v1), true, nil
		}
		return true, true, nil
	case "Objects.nonNull":
		if len(args) >= 1 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return false, true, err1
			}
			return !isEmptyOptionalOrNilPainless(v1), true, nil
		}
		return false, true, nil
	case "Objects.toString":
		if len(args) >= 1 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return "", true, err1
			}
			if v1 == nil {
				if len(args) >= 2 {
					v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if err2 != nil {
						return "", true, err2
					}
					if v2 == nil {
						return nil, true, nil
					}
					return fmt.Sprintf("%v", v2), true, nil
				}
				return "null", true, nil
			}
			return fmt.Sprintf("%v", v1), true, nil
		}
		return "null", true, nil
	case "Objects.requireNonNull":
		if len(args) >= 1 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return nil, true, err1
			}
			if v1 == nil {
				msg := "null"
				if len(args) >= 2 {
					if mVal, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1); err2 == nil && mVal != nil {
						msg = fmt.Sprintf("%v", mVal)
					}
				}
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: msg}
			}
			return v1, true, nil
		}
		return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "null"}
	case "Objects.requireNonNullElse":
		if len(args) >= 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return nil, true, err1
			}
			if v1 != nil {
				return v1, true, nil
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err2 != nil {
				return nil, true, err2
			}
			if v2 == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "defaultObj"}
			}
			return v2, true, nil
		}
		return nil, true, nil
	case "String.valueOf", "String.copyValueOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			if arr, ok := v.([]any); ok {
				chars := make([]rune, 0, len(arr))
				for _, el := range arr {
					if s, okS := el.(string); okS {
						for _, r := range s {
							chars = append(chars, r)
						}
					} else if iv, okI := toInt64Painless(el); okI {
						chars = append(chars, rune(iv)) // #nosec G115 -- char code point
					} else if el != nil {
						for _, r := range fmt.Sprintf("%v", el) {
							chars = append(chars, r)
						}
					}
				}
				if len(args) >= 3 {
					offVal, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
					if err1 != nil {
						return "", true, err1
					}
					cntVal, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
					if err2 != nil {
						return "", true, err2
					}
					off, _ := toInt64Painless(offVal)
					cnt, _ := toInt64Painless(cntVal)
					if off < 0 || cnt < 0 || int(off+cnt) > len(chars) {
						return "", true, &painlessExceptionError{
							exType:  "IndexOutOfBoundsException",
							message: fmt.Sprintf("offset %d, count %d, length %d", off, cnt, len(chars)),
						}
					}
					return string(chars[int(off):int(off+cnt)]), true, nil
				}
				return string(chars), true, nil
			}
			if v == nil {
				if fnName == "String.copyValueOf" {
					return "", true, &painlessExceptionError{exType: "NullPointerException", message: "Cannot read the array length because \"data\" is null"}
				}
				return "null", true, nil
			}
			return fmt.Sprintf("%v", v), true, nil
		}
		return "", true, nil
	case "String.format":
		if len(args) >= 1 {
			fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			fmtStr := fmt.Sprintf("%v", fmtVal)
			fmtArgs := make([]any, 0, len(args)-1)
			for _, a := range args[1:] {
				av, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
				if jn, isJN := av.(json.Number); isJN {
					if iv, err := jn.Int64(); err == nil {
						av = iv
					} else if fv, err := jn.Float64(); err == nil {
						av = fv
					}
				}
				fmtArgs = append(fmtArgs, av)
			}
			return fmt.Sprintf(fmtStr, fmtArgs...), true, nil
		}
		return "", true, nil
	case "String.join":
		if len(args) >= 2 {
			sepVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			sepStr := fmt.Sprintf("%v", sepVal)
			if len(args) == 2 {
				colExpr := strings.TrimSpace(args[1])
				var colVal any
				if (strings.HasPrefix(colExpr, "doc.") || strings.HasPrefix(colExpr, "doc?.")) &&
					!strings.HasSuffix(colExpr, ".value") && !strings.Contains(colExpr, ".values.") {
					docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(colExpr, "doc?."), "doc."), ".values")
					colVal = resolveDocValuesSlice(sourceMap, docPath)
				} else {
					colVal, _ = evalRHSExprDepth(sourceMap, colExpr, params, depth+1)
				}
				if tv, ok := colVal.([]any); ok {
					parts := make([]string, len(tv))
					for i, item := range tv {
						parts[i] = fmt.Sprintf("%v", item)
					}
					return strings.Join(parts, sepStr), true, nil
				}
				if colVal != nil {
					return fmt.Sprintf("%v", colVal), true, nil
				}
				return "", true, nil
			}
			parts := make([]string, len(args)-1)
			for i := 1; i < len(args); i++ {
				itemVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[i]), params, depth+1)
				parts[i-1] = fmt.Sprintf("%v", itemVal)
			}
			return strings.Join(parts, sepStr), true, nil
		}
		return "", true, nil
	case "Encoding.encodeBase64":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			return base64.StdEncoding.EncodeToString(toBytesPainless(v)), true, nil
		}
		return "", true, nil
	case "Encoding.decodeBase64":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if dec, dErr := base64.StdEncoding.DecodeString(s); dErr == nil {
				return string(dec), true, nil
			}
			if dec, dErr := base64.RawStdEncoding.DecodeString(s); dErr == nil {
				return string(dec), true, nil
			}
			if dec, dErr := base64.URLEncoding.DecodeString(s); dErr == nil {
				return string(dec), true, nil
			}
			if dec, dErr := base64.RawURLEncoding.DecodeString(s); dErr == nil {
				return string(dec), true, nil
			}
		}
		return "", true, nil
	case "Encoding.encodeHex", "Hex.encodeHexString":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			return hex.EncodeToString(toBytesPainless(v)), true, nil
		}
		return "", true, nil
	case "Encoding.decodeHex":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			if dec, dErr := hex.DecodeString(strings.TrimSpace(fmt.Sprintf("%v", v))); dErr == nil {
				return string(dec), true, nil
			}
		}
		return "", true, nil
	case "Base64.getEncoder", "Base64.getMimeEncoder":
		return "__base64_encoder:std", true, nil
	case "Base64.getUrlEncoder":
		return "__base64_encoder:url", true, nil
	case "Base64.getDecoder":
		return "__base64_decoder:std", true, nil
	case "Base64.getMimeDecoder":
		return "__base64_decoder:mime", true, nil
	case "Base64.getUrlDecoder":
		return "__base64_decoder:url", true, nil
	case "HexFormat.of":
		return painlessHexFormat{}, true, nil
	case "HexFormat.ofDelimiter":
		delim := ""
		if len(args) >= 1 {
			dv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if dv != nil {
				delim = fmt.Sprintf("%v", dv)
			}
		}
		return painlessHexFormat{delimiter: delim}, true, nil
	case "HexFormat.fromHexDigits", "HexFormat.fromHexDigitsToLong", "HexFormat.isHexDigit", "HexFormat.fromHexDigit":
		mName := "." + strings.TrimPrefix(fnName, "HexFormat.") + "("
		res, err := evalHexFormatMethodPainless(mName, painlessHexFormat{}, strings.Join(args, ", "), sourceMap, params, depth+1)
		return res, true, err
	case "Digest.sha256", "Digest.md5", "Digest.sha1", "Digest.sha384", "Digest.sha512":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			raw := toBytesPainless(v)
			switch fnName {
			case "Digest.sha256":
				sum := sha256.Sum256(raw)
				return hex.EncodeToString(sum[:]), true, nil
			case "Digest.md5":
				sum := md5.Sum(raw) // #nosec G401 -- intentional Painless Digest.md5 support
				return hex.EncodeToString(sum[:]), true, nil
			case "Digest.sha1":
				sum := sha1.Sum(raw) // #nosec G401 -- intentional Painless Digest.sha1 support
				return hex.EncodeToString(sum[:]), true, nil
			case "Digest.sha384":
				sum := sha512.Sum384(raw)
				return hex.EncodeToString(sum[:]), true, nil
			case "Digest.sha512":
				sum := sha512.Sum512(raw)
				return hex.EncodeToString(sum[:]), true, nil
			}
		}
		return "", true, nil
	case "Arrays.asList", "List.of", "Set.of", "Stream.of":
		if argStr == "" {
			return []any{}, true, nil
		}
		out := make([]any, 0, len(args))
		for _, a := range args {
			av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if fnName == "Set.of" {
				dup := false
				for _, existing := range out {
					if painlessValuesEqual(existing, av) {
						dup = true
						break
					}
				}
				if dup {
					continue
				}
			}
			out = append(out, av)
		}
		return out, true, nil
	case "List.copyOf", "Set.copyOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if srcSlice, ok := v.([]any); ok {
				if fnName == "Set.copyOf" {
					out := make([]any, 0, len(srcSlice))
					for _, item := range srcSlice {
						seen := false
						for _, ex := range out {
							if painlessValuesEqual(item, ex) {
								seen = true
								break
							}
						}
						if !seen {
							out = append(out, item)
						}
					}
					return out, true, nil
				}
				out := make([]any, len(srcSlice))
				copy(out, srcSlice)
				return out, true, nil
			}
		}
		return []any{}, true, nil
	case "Map.copyOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if srcMap, ok := v.(map[string]any); ok {
				out := make(map[string]any, len(srcMap))
				for k, val := range srcMap {
					if !isInternalPainlessMapKey(srcMap, k) {
						out[k] = val
					}
				}
				return out, true, nil
			}
		}
		return map[string]any{}, true, nil
	case "Arrays.sort":
		if len(args) >= 1 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := listVal.([]any); ok {
				fromIdx, toIdx := 0, len(arr)
				cmpExpr := ""
				if len(args) == 2 {
					cmpExpr = strings.TrimSpace(args[1])
				} else if len(args) >= 3 {
					if ff, okF := evalNumArg(1); okF {
						fromIdx = int(ff)
					}
					if tf, okT := evalNumArg(2); okT {
						toIdx = int(tf)
					}
					if len(args) >= 4 {
						cmpExpr = strings.TrimSpace(args[3])
					}
				}
				if fromIdx < 0 {
					fromIdx = 0
				}
				if fromIdx > len(arr) {
					fromIdx = len(arr)
				}
				if toIdx < fromIdx {
					toIdx = fromIdx
				}
				if toIdx > len(arr) {
					toIdx = len(arr)
				}
				if err := sortPainlessSliceInPlace(arr[fromIdx:toIdx], cmpExpr, sourceMap, params, depth+1); err != nil {
					return nil, true, err
				}
				syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Arrays.binarySearch":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(-1), true, err
			}
			arr, ok := listVal.([]any)
			if !ok {
				return int64(-1), true, nil
			}
			low, high := 0, len(arr)-1
			keyIdx := 1
			cmpExpr := ""
			if len(args) == 3 {
				cmpExpr = strings.TrimSpace(args[2])
			} else if len(args) >= 4 {
				if ff, okF := evalNumArg(1); okF {
					low = int(ff)
				}
				if tf, okT := evalNumArg(2); okT {
					high = int(tf) - 1
				}
				keyIdx = 3
				if len(args) >= 5 {
					cmpExpr = strings.TrimSpace(args[4])
				}
			}
			if low < 0 {
				low = 0
			}
			if high >= len(arr) {
				high = len(arr) - 1
			}
			keyVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[keyIdx]), params, depth+1)
			if err != nil {
				return int64(-1), true, err
			}
			for low <= high {
				mid := int(uint(low+high) >> 1)
				var cmp int
				if cmpExpr != "" {
					var cmpErr error
					cmp, cmpErr = evalPainlessComparatorPair(cmpExpr, arr[mid], keyVal, sourceMap, params, depth+1)
					if cmpErr != nil {
						return int64(-1), true, cmpErr
					}
				} else {
					cmp = comparePainlessValues(arr[mid], keyVal)
				}
				if cmp < 0 {
					low = mid + 1
				} else if cmp > 0 {
					high = mid - 1
				} else {
					return int64(mid), true, nil
				}
			}
			return int64(-(low + 1)), true, nil
		}
		return int64(-1), true, nil
	case "Arrays.fill":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := listVal.([]any); ok {
				fromIdx, toIdx := 0, len(arr)
				valIdx := 1
				if len(args) >= 4 {
					if ff, okF := evalNumArg(1); okF {
						fromIdx = int(ff)
					}
					if tf, okT := evalNumArg(2); okT {
						toIdx = int(tf)
					}
					valIdx = 3
				}
				if fromIdx < 0 {
					fromIdx = 0
				}
				if fromIdx > len(arr) {
					fromIdx = len(arr)
				}
				if toIdx < fromIdx {
					toIdx = fromIdx
				}
				if toIdx > len(arr) {
					toIdx = len(arr)
				}
				fillVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[valIdx]), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				for i := fromIdx; i < toIdx; i++ {
					arr[i] = fillVal
				}
				syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Arrays.copyOf":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			nf, okN := evalNumArg(1)
			if arr, ok := listVal.([]any); ok && okN {
				newLen := int(nf)
				if newLen < 0 {
					newLen = 0
				}
				if newLen > MaxPainlessSliceItems {
					newLen = MaxPainlessSliceItems
				}
				out := make([]any, newLen)
				copy(out, arr)
				return out, true, nil
			}
		}
		return []any{}, true, nil
	case "Arrays.copyOfRange":
		if len(args) >= 3 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			ff, okF := evalNumArg(1)
			tf, okT := evalNumArg(2)
			if arr, ok := listVal.([]any); ok && okF && okT {
				fromIdx, toIdx := int(ff), int(tf)
				if fromIdx < 0 {
					fromIdx = 0
				}
				if fromIdx > len(arr) {
					fromIdx = len(arr)
				}
				if toIdx < fromIdx {
					toIdx = fromIdx
				}
				newLen := toIdx - fromIdx
				if newLen > MaxPainlessSliceItems {
					newLen = MaxPainlessSliceItems
				}
				out := make([]any, newLen)
				if fromIdx < len(arr) {
					copy(out, arr[fromIdx:])
				}
				return out, true, nil
			}
		}
		return []any{}, true, nil
	case "Arrays.equals", "Arrays.deepEquals":
		if len(args) >= 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return false, true, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err2 != nil {
				return false, true, err2
			}
			if v1 == nil && v2 == nil {
				return true, true, nil
			}
			a1, ok1 := v1.([]any)
			a2, ok2 := v2.([]any)
			if !ok1 || !ok2 || len(a1) != len(a2) {
				return false, true, nil
			}
			if fnName == "Arrays.deepEquals" {
				return painlessDeepEquals(a1, a2), true, nil
			}
			for i := range a1 {
				if !painlessValuesEqual(a1[i], a2[i]) {
					return false, true, nil
				}
			}
			return true, true, nil
		}
		return false, true, nil
	case "Arrays.toString", "Arrays.deepToString":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "null", true, err
			}
			if v == nil {
				return "null", true, nil
			}
			if arr, ok := v.([]any); ok {
				return formatArraysToStringPainless(arr, fnName == "Arrays.deepToString"), true, nil
			}
			return fmt.Sprintf("%v", v), true, nil
		}
		return "null", true, nil
	case "Arrays.setAll", "Arrays.parallelSetAll":
		if len(args) >= 2 {
			arrVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := arrVal.([]any); ok {
				genExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(args[1]), 1)
				if arrowIdx := findNextUnquotedSubstr(genExpr, "->", 0); arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(genExpr[:arrowIdx])
					if len(pNames) > 0 {
						pName := pNames[0]
						body := strings.TrimSpace(genExpr[arrowIdx+2:])
						prev, hadPrev := params[pName]
						for i := range arr {
							params[pName] = int64(i)
							val, lErr := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
							if lErr != nil {
								if hadPrev {
									params[pName] = prev
								} else {
									delete(params, pName)
								}
								return nil, true, lErr
							}
							arr[i] = val
						}
						if hadPrev {
							params[pName] = prev
						} else {
							delete(params, pName)
						}
						syncMutatedListExprPainless(args[0], arr, sourceMap, params)
					}
				}
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Arrays.parallelPrefix":
		if len(args) >= 2 {
			arrVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := arrVal.([]any); ok {
				fromIdx, toIdx := 0, len(arr)
				opArgIdx := 1
				if len(args) >= 4 {
					if ff, okF := evalNumArg(1); okF {
						fromIdx = int(ff)
					}
					if tf, okT := evalNumArg(2); okT {
						toIdx = int(tf)
					}
					opArgIdx = 3
				}
				if fromIdx < 0 || toIdx > len(arr) || fromIdx > toIdx {
					return nil, true, &painlessExceptionError{
						exType:  "ArrayIndexOutOfBoundsException",
						message: fmt.Sprintf("Range [%d, %d) out of bounds for length %d", fromIdx, toIdx, len(arr)),
					}
				}
				opExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(args[opArgIdx]), 2)
				if arrowIdx := findNextUnquotedSubstr(opExpr, "->", 0); arrowIdx > 0 {
					pNames := parsePainlessLambdaHeader(opExpr[:arrowIdx])
					if len(pNames) >= 2 {
						pA, pB := pNames[0], pNames[1]
						body := strings.TrimSpace(opExpr[arrowIdx+2:])
						prevA, hadA := params[pA]
						prevB, hadB := params[pB]
						for i := fromIdx + 1; i < toIdx; i++ {
							params[pA] = arr[i-1]
							params[pB] = arr[i]
							val, lErr := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
							if lErr != nil {
								if hadA {
									params[pA] = prevA
								} else {
									delete(params, pA)
								}
								if hadB {
									params[pB] = prevB
								} else {
									delete(params, pB)
								}
								return nil, true, lErr
							}
							arr[i] = val
						}
						if hadA {
							params[pA] = prevA
						} else {
							delete(params, pA)
						}
						if hadB {
							params[pB] = prevB
						} else {
							delete(params, pB)
						}
						syncMutatedListExprPainless(args[0], arr, sourceMap, params)
					}
				}
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Arrays.compare":
		res, err := evalArraysCompareOrMismatchPainless(args, false, sourceMap, params, depth+1)
		return res, true, err
	case "Arrays.mismatch":
		res, err := evalArraysCompareOrMismatchPainless(args, true, sourceMap, params, depth+1)
		return res, true, err
	case "Arrays.stream":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := v.([]any); ok {
				fromIdx, toIdx := 0, len(arr)
				if len(args) >= 3 {
					if ff, okF := evalNumArg(1); okF {
						fromIdx = int(ff)
					}
					if tf, okT := evalNumArg(2); okT {
						toIdx = int(tf)
					}
				}
				if fromIdx < 0 {
					fromIdx = 0
				}
				if fromIdx > len(arr) {
					fromIdx = len(arr)
				}
				if toIdx < fromIdx {
					toIdx = fromIdx
				}
				if toIdx > len(arr) {
					toIdx = len(arr)
				}
				out := make([]any, toIdx-fromIdx)
				copy(out, arr[fromIdx:toIdx])
				return out, true, nil
			}
		}
		return []any{}, true, nil
	case "IntStream.range", "IntStream.rangeClosed", "LongStream.range", "LongStream.rangeClosed":
		if len(args) >= 2 {
			start, ok1 := evalInt64Arg(0)
			end, ok2 := evalInt64Arg(1)
			if ok1 && ok2 {
				if strings.HasSuffix(fnName, "Closed") {
					end++
				}
				if end <= start {
					return []any{}, true, nil
				}
				count := end - start
				if count > int64(MaxPainlessSliceItems) {
					count = int64(MaxPainlessSliceItems)
				}
				out := make([]any, int(count))
				for i := int64(0); i < count; i++ {
					out[i] = start + i
				}
				return out, true, nil
			}
		}
		return []any{}, true, nil
	case "IntStream.of", "LongStream.of":
		if argStr == "" {
			return []any{}, true, nil
		}
		out := make([]any, 0, len(args))
		for _, a := range args {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := v.([]any); ok && len(args) == 1 {
				for _, item := range arr {
					if f, okF := toFloat64(item); okF {
						out = append(out, int64(f))
					} else {
						out = append(out, item)
					}
				}
				return out, true, nil
			}
			if f, okF := toFloat64(v); okF {
				out = append(out, int64(f))
			} else {
				out = append(out, v)
			}
		}
		return out, true, nil
	case "DoubleStream.of":
		if argStr == "" {
			return []any{}, true, nil
		}
		out := make([]any, 0, len(args))
		for _, a := range args {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := v.([]any); ok && len(args) == 1 {
				for _, item := range arr {
					if f, okF := toFloat64(item); okF {
						out = append(out, f)
					} else {
						out = append(out, item)
					}
				}
				return out, true, nil
			}
			if f, okF := toFloat64(v); okF {
				out = append(out, f)
			} else {
				out = append(out, v)
			}
		}
		return out, true, nil
	case "Stream.empty", "IntStream.empty", "LongStream.empty", "DoubleStream.empty":
		return []any{}, true, nil
	case "Stream.concat", "IntStream.concat", "LongStream.concat", "DoubleStream.concat":
		if len(args) >= 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return nil, true, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err2 != nil {
				return nil, true, err2
			}
			a1, _ := v1.([]any)
			a2, _ := v2.([]any)
			total := len(a1) + len(a2)
			if total > MaxPainlessSliceItems {
				total = MaxPainlessSliceItems
			}
			out := make([]any, 0, total)
			for _, it := range a1 {
				if len(out) >= MaxPainlessSliceItems {
					break
				}
				out = append(out, it)
			}
			for _, it := range a2 {
				if len(out) >= MaxPainlessSliceItems {
					break
				}
				out = append(out, it)
			}
			return out, true, nil
		}
		return []any{}, true, nil
	case "Map.of":
		out := make(map[string]any, len(args)/2)
		if argStr == "" {
			return out, true, nil
		}
		for i := 0; i+1 < len(args); i += 2 {
			kv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[i]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			vv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[i+1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if kv != nil {
				out[fmt.Sprintf("%v", kv)] = vv
			}
		}
		return out, true, nil
	case "Map.entry":
		if len(args) >= 2 {
			kv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			vv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			return map[string]any{"key": kv, "value": vv}, true, nil
		}
		return map[string]any{}, true, nil
	case "Map.ofEntries":
		out := make(map[string]any, len(args))
		if argStr == "" {
			return out, true, nil
		}
		for _, a := range args {
			ev, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if em, ok := ev.(map[string]any); ok && em != nil {
				if kVal, hasK := em["key"]; hasK && kVal != nil {
					out[fmt.Sprintf("%v", kVal)] = em["value"]
				} else {
					for k, v := range em {
						if !isInternalPainlessMapKey(em, k) {
							out[k] = v
						}
					}
				}
			}
		}
		return out, true, nil
	case "Optional.of", "Optional.ofNullable", "OptionalInt.of", "OptionalLong.of", "OptionalDouble.of":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if isEmptyOptionalOrNilPainless(v) {
				if fnName == "Optional.ofNullable" {
					return painlessEmptyOptional, true, nil
				}
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "Optional.of(null)"}
			}
			return v, true, nil
		}
		return painlessEmptyOptional, true, nil
	case "Optional.empty", "OptionalInt.empty", "OptionalLong.empty", "OptionalDouble.empty":
		return painlessEmptyOptional, true, nil
	case "Charset.forName":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			if v != nil {
				return strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", v))), true, nil
			}
		}
		return "UTF-8", true, nil
	case "Charset.defaultCharset":
		return "UTF-8", true, nil
	case "Collections.emptyList", "Collections.emptySet":
		return []any{}, true, nil
	case "Collections.emptyMap":
		return map[string]any{}, true, nil
	case "Collections.singletonList", "Collections.singleton":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			return []any{v}, true, nil
		}
		return []any{}, true, nil
	case "Collections.singletonMap":
		if len(args) >= 2 {
			kv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			vv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if kv != nil {
				return map[string]any{fmt.Sprintf("%v", kv): vv}, true, nil
			}
		}
		return map[string]any{}, true, nil
	case "Collections.min", "Collections.max":
		if len(args) >= 1 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := listVal.([]any); ok && len(arr) > 0 {
				if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
					cp := make([]any, len(arr))
					copy(cp, arr)
					if err := sortPainlessSliceInPlace(cp, strings.TrimSpace(args[1]), sourceMap, params, depth+1); err != nil {
						return nil, true, err
					}
					if fnName == "Collections.min" {
						return cp[0], true, nil
					}
					return cp[len(cp)-1], true, nil
				}
				best := arr[0]
				for _, it := range arr[1:] {
					cmp := comparePainlessValues(it, best)
					if (fnName == "Collections.min" && cmp < 0) || (fnName == "Collections.max" && cmp > 0) {
						best = it
					}
				}
				return best, true, nil
			}
		}
		return nil, true, nil
	case "Collections.binarySearch":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(-1), true, err
			}
			arr, ok := listVal.([]any)
			if !ok {
				return int64(-1), true, nil
			}
			keyVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return int64(-1), true, err
			}
			cmpExpr := ""
			if len(args) >= 3 {
				cmpExpr = strings.TrimSpace(args[2])
			}
			low, high := 0, len(arr)-1
			for low <= high {
				mid := int(uint(low+high) >> 1)
				var cmp int
				if cmpExpr != "" {
					var cmpErr error
					cmp, cmpErr = evalPainlessComparatorPair(cmpExpr, arr[mid], keyVal, sourceMap, params, depth+1)
					if cmpErr != nil {
						return int64(-1), true, cmpErr
					}
				} else {
					cmp = comparePainlessValues(arr[mid], keyVal)
				}
				if cmp < 0 {
					low = mid + 1
				} else if cmp > 0 {
					high = mid - 1
				} else {
					return int64(mid), true, nil
				}
			}
			return int64(-(low + 1)), true, nil
		}
		return int64(-1), true, nil
	case "Collections.frequency":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return int64(0), true, err
			}
			needle, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return int64(0), true, err
			}
			if arr, ok := listVal.([]any); ok {
				var count int64
				for _, it := range arr {
					if painlessValuesEqual(it, needle) {
						count++
					}
				}
				return count, true, nil
			}
		}
		return int64(0), true, nil
	case "Collections.disjoint":
		if len(args) >= 2 {
			c1Val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return true, true, err
			}
			c2Val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return true, true, err
			}
			a1, ok1 := c1Val.([]any)
			a2, ok2 := c2Val.([]any)
			if ok1 && ok2 {
				for _, x := range a1 {
					for _, y := range a2 {
						if painlessValuesEqual(x, y) {
							return false, true, nil
						}
					}
				}
			}
		}
		return true, true, nil
	case "Collections.nCopies":
		if len(args) >= 2 {
			nf, ok := evalNumArg(0)
			if !ok || int(nf) <= 0 {
				return []any{}, true, nil
			}
			n := int(nf)
			if n > MaxPainlessSliceItems {
				n = MaxPainlessSliceItems
			}
			val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			out := make([]any, n)
			for i := 0; i < n; i++ {
				out[i] = val
			}
			return out, true, nil
		}
		return []any{}, true, nil
	case "Collections.swap":
		if len(args) >= 3 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			f1, ok1 := evalNumArg(1)
			f2, ok2 := evalNumArg(2)
			if arr, ok := listVal.([]any); ok && ok1 && ok2 {
				i, j := int(f1), int(f2)
				if i >= 0 && i < len(arr) && j >= 0 && j < len(arr) {
					arr[i], arr[j] = arr[j], arr[i]
					syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				}
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Collections.fill":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			fillVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if arr, ok := listVal.([]any); ok {
				for i := range arr {
					arr[i] = fillVal
				}
				syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Collections.rotate":
		if len(args) >= 2 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			df, okDist := evalNumArg(1)
			if arr, ok := listVal.([]any); ok && okDist {
				n := len(arr)
				if n > 1 {
					d := int(df) % n
					if d < 0 {
						d += n
					}
					if d > 0 {
						tmp := make([]any, n)
						for i := 0; i < n; i++ {
							tmp[(i+d)%n] = arr[i]
						}
						copy(arr, tmp)
						syncMutatedListExprPainless(args[0], arr, sourceMap, params)
					}
				}
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Collections.replaceAll":
		if len(args) >= 3 {
			listVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			oldVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			newVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
			if err != nil {
				return false, true, err
			}
			if arr, ok := listVal.([]any); ok {
				changed := false
				for i, it := range arr {
					if painlessValuesEqual(it, oldVal) {
						arr[i] = newVal
						changed = true
					}
				}
				if changed {
					syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				}
				return changed, true, nil
			}
		}
		return false, true, nil
	case "Collections.sort":
		if len(args) >= 1 {
			listVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if arr, ok := listVal.([]any); ok {
				cmpExpr := ""
				if len(args) >= 2 {
					cmpExpr = strings.TrimSpace(args[1])
				}
				if err := sortPainlessSliceInPlace(arr, cmpExpr, sourceMap, params, depth+1); err != nil {
					return nil, true, err
				}
				syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "Collections.reverse":
		if len(args) >= 1 {
			listVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if arr, ok := listVal.([]any); ok {
				for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
					arr[i], arr[j] = arr[j], arr[i]
				}
				syncMutatedListExprPainless(args[0], arr, sourceMap, params)
				return arr, true, nil
			}
		}
		return nil, true, nil
	case "DateTimeFormatter.ofPattern":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			return translateJavaDateTimePatternToGo(fmt.Sprintf("%v", v)), true, nil
		}
		return time.RFC3339Nano, true, nil
	case "ZoneId.of", "ZoneOffset.of":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			return fmt.Sprintf("%v", v), true, nil
		}
		return "UTC", true, nil
	case "ZoneOffset.ofHours":
		if f, ok := evalNumArg(0); ok {
			hrs := int(f)
			if hrs == 0 {
				return "UTC", true, nil
			}
			if hrs > 0 {
				return fmt.Sprintf("+%02d:00", hrs), true, nil
			}
			return fmt.Sprintf("-%02d:00", -hrs), true, nil
		}
		return "UTC", true, nil
	case "Instant.now":
		nowMs := time.Now().UTC().UnixMilli()
		if b := getOrInitEvalBudget(params); b != nil && b.nowMillis > 0 {
			nowMs = b.nowMillis
		}
		return time.UnixMilli(nowMs).UTC().Format(time.RFC3339Nano), true, nil
	case "ZonedDateTime.now", "OffsetDateTime.now", "LocalDateTime.now", "LocalDate.now", "LocalTime.now", "YearMonth.now", "Year.now", "MonthDay.now":
		nowMs := time.Now().UTC().UnixMilli()
		if b := getOrInitEvalBudget(params); b != nil && b.nowMillis > 0 {
			nowMs = b.nowMillis
		}
		loc := time.UTC
		if len(args) >= 1 && strings.TrimSpace(args[0]) != "" {
			zVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			loc = parseZoneLocationPainless(zVal)
		}
		tm := time.UnixMilli(nowMs).In(loc)
		switch fnName {
		case "LocalDate.now":
			return tm.Format("2006-01-02"), true, nil
		case "LocalTime.now":
			return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), true, nil
		case "YearMonth.now":
			return tm.Format("2006-01"), true, nil
		case "Year.now":
			return painlessYear{year: int64(tm.Year())}, true, nil
		case "MonthDay.now":
			return painlessMonthDay{month: int(tm.Month()), day: tm.Day()}, true, nil
		case "LocalDateTime.now":
			return tm.Format("2006-01-02T15:04:05.999999999"), true, nil
		default:
			return tm.Format(time.RFC3339Nano), true, nil
		}
	case "Year.of":
		if len(args) >= 1 {
			if y, ok := evalNumArg(0); ok {
				return painlessYear{year: int64(y)}, true, nil
			}
		}
		return nil, true, nil
	case "Year.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if len(args) >= 2 {
				fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if tm, ok := parseDateTimeWithFormatterPainless(v, fmtVal); ok {
					return painlessYear{year: int64(tm.Year())}, true, nil
				}
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if y, err := strconv.ParseInt(s, 10, 64); err == nil {
				return painlessYear{year: y}, true, nil
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				return painlessYear{year: int64(tm.Year())}, true, nil
			}
		}
		return nil, true, nil
	case "Year.isLeap":
		if len(args) >= 1 {
			if y, ok := evalNumArg(0); ok {
				return (painlessYear{year: int64(y)}).isLeap(), true, nil
			}
		}
		return false, true, nil
	case "Year.from":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if yr, ok := v.(painlessYear); ok {
				return yr, true, nil
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				return painlessYear{year: int64(tm.Year())}, true, nil
			}
		}
		return nil, true, nil
	case "MonthDay.of":
		if len(args) >= 2 {
			mv, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			m := parseMonthIndexPainless(mv)
			d, _ := evalNumArg(1)
			if m >= 1 && m <= 12 {
				return painlessMonthDay{month: m, day: int(d)}, true, nil
			}
		}
		return nil, true, nil
	case "MonthDay.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if len(args) >= 2 {
				fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if tm, ok := parseDateTimeWithFormatterPainless(v, fmtVal); ok {
					return painlessMonthDay{month: int(tm.Month()), day: tm.Day()}, true, nil
				}
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			s = strings.TrimPrefix(s, "--")
			if parts := strings.Split(s, "-"); len(parts) == 2 {
				m, err1 := strconv.Atoi(parts[0])
				d, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && m >= 1 && m <= 12 && d >= 1 && d <= 31 {
					return painlessMonthDay{month: m, day: d}, true, nil
				}
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				return painlessMonthDay{month: int(tm.Month()), day: tm.Day()}, true, nil
			}
		}
		return nil, true, nil
	case "MonthDay.from":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if md, ok := v.(painlessMonthDay); ok {
				return md, true, nil
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				return painlessMonthDay{month: int(tm.Month()), day: tm.Day()}, true, nil
			}
		}
		return nil, true, nil
	case "YearMonth.of":
		if len(args) >= 2 {
			y, _ := evalNumArg(0)
			m, okM := evalNumArg(1)
			if !okM {
				mv, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if mi := parseMonthIndexPainless(mv); mi > 0 {
					m = float64(mi)
				}
			}
			tm := time.Date(int(y), time.Month(int(m)), 1, 0, 0, 0, 0, time.UTC)
			return tm.Format("2006-01"), true, nil
		}
		return nil, true, nil
	case "YearMonth.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if len(args) >= 2 {
				fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if tm, ok := parseDateTimeWithFormatterPainless(v, fmtVal); ok {
					return tm.Format("2006-01"), true, nil
				}
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				return tm.Format("2006-01"), true, nil
			}
		}
		return nil, true, nil
	case "DayOfWeek.of", "DayOfWeek.valueOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			if idx := parseDayOfWeekIndexPainless(v); idx > 0 {
				return dayOfWeekNamePainless(idx), true, nil
			}
		}
		return "", true, nil
	case "Month.of", "Month.valueOf":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			if idx := parseMonthIndexPainless(v); idx > 0 {
				return monthNamePainless(idx), true, nil
			}
		}
		return "", true, nil
	case "Instant.ofEpochMilli":
		if f, ok := evalNumArg(0); ok {
			return time.UnixMilli(int64(f)).UTC().Format(time.RFC3339Nano), true, nil
		}
		return nil, true, nil
	case "Instant.ofEpochSecond":
		if f, ok := evalNumArg(0); ok {
			sec := int64(f)
			var nsec int64
			if len(args) >= 2 {
				if nf, ok2 := evalNumArg(1); ok2 {
					nsec = int64(nf)
				}
			}
			return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano), true, nil
		}
		return nil, true, nil
	case "Instant.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if tm, ok := parsePainlessDateTime(v); ok {
				return tm.UTC().Format(time.RFC3339Nano), true, nil
			}
		}
		return nil, true, nil
	case "ZonedDateTime.parse", "LocalDateTime.parse", "LocalDate.parse", "OffsetDateTime.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if len(args) >= 2 {
				fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if tm, ok := parseDateTimeWithFormatterPainless(v, fmtVal); ok {
					if fnName == "LocalDate.parse" {
						return tm.Format("2006-01-02"), true, nil
					}
					return tm.Format(time.RFC3339Nano), true, nil
				}
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				if fnName == "LocalDate.parse" && len(strings.TrimSpace(fmt.Sprintf("%v", v))) == 10 {
					return tm.Format("2006-01-02"), true, nil
				}
				return tm.Format(time.RFC3339Nano), true, nil
			}
		}
		return nil, true, nil
	case "ZonedDateTime.of":
		if len(args) == 2 {
			ldtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			zVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if tm, ok := parsePainlessDateTime(ldtVal); ok {
				loc := parseZoneLocationPainless(zVal)
				return time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), loc).Format(time.RFC3339Nano), true, nil
			}
		}
		if len(args) >= 7 {
			y, _ := evalNumArg(0)
			m, okM := evalNumArg(1)
			if !okM {
				mv, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if mi := parseMonthIndexPainless(mv); mi > 0 {
					m = float64(mi)
				}
			}
			d, _ := evalNumArg(2)
			hr, _ := evalNumArg(3)
			min, _ := evalNumArg(4)
			sec, _ := evalNumArg(5)
			nano, _ := evalNumArg(6)
			loc := time.UTC
			if len(args) >= 8 {
				zVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[7]), params, depth+1)
				loc = parseZoneLocationPainless(zVal)
			}
			tm := time.Date(int(y), time.Month(int(m)), int(d), int(hr), int(min), int(sec), int(nano), loc)
			return tm.Format(time.RFC3339Nano), true, nil
		}
		return nil, true, nil
	case "ZonedDateTime.ofInstant":
		if len(args) >= 2 {
			instVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			zVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if tm, ok := parsePainlessDateTime(instVal); ok {
				loc := parseZoneLocationPainless(zVal)
				return tm.In(loc).Format(time.RFC3339Nano), true, nil
			}
		}
		return nil, true, nil
	case "LocalDate.of":
		if len(args) >= 3 {
			y, _ := evalNumArg(0)
			m, okM := evalNumArg(1)
			if !okM {
				mv, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if mi := parseMonthIndexPainless(mv); mi > 0 {
					m = float64(mi)
				}
			}
			d, _ := evalNumArg(2)
			tm := time.Date(int(y), time.Month(int(m)), int(d), 0, 0, 0, 0, time.UTC)
			return tm.Format("2006-01-02"), true, nil
		}
		return nil, true, nil
	case "LocalDate.ofEpochDay":
		if f, ok := evalNumArg(0); ok {
			tm := time.Unix(int64(f)*86400, 0).UTC()
			return tm.Format("2006-01-02"), true, nil
		}
		return nil, true, nil
	case "LocalTime.of":
		if len(args) >= 2 {
			hr, _ := evalNumArg(0)
			min, _ := evalNumArg(1)
			sec := 0.0
			nano := 0.0
			if len(args) >= 3 {
				sec, _ = evalNumArg(2)
			}
			if len(args) >= 4 {
				nano, _ = evalNumArg(3)
			}
			return formatLocalTimePainless(int(hr), int(min), int(sec), int(nano)), true, nil
		}
		return nil, true, nil
	case "LocalTime.ofSecondOfDay":
		if sec, ok := evalInt64Arg(0); ok {
			s := ((int(sec) % 86400) + 86400) % 86400
			return formatLocalTimePainless(s/3600, (s%3600)/60, s%60, 0), true, nil
		}
		return nil, true, nil
	case "LocalTime.ofNanoOfDay":
		if nano, ok := evalInt64Arg(0); ok {
			sec := int(nano / 1_000_000_000)
			ns := int(nano % 1_000_000_000)
			return formatLocalTimePainless(sec/3600, (sec%3600)/60, sec%60, ns), true, nil
		}
		return nil, true, nil
	case "LocalTime.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if len(args) >= 2 {
				fmtVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if tm, ok := parseDateTimeWithFormatterPainless(v, fmtVal); ok {
					return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), true, nil
				}
			}
			if tm, ok := parsePainlessDateTime(v); ok {
				return formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()), true, nil
			}
		}
		return nil, true, nil
	case "LocalDateTime.of":
		if len(args) == 2 {
			dVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			tVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			dt, okD := parsePainlessDateTime(dVal)
			tm, okT := parsePainlessDateTime(tVal)
			if okD && okT {
				tStr := formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond())
				return fmt.Sprintf("%04d-%02d-%02dT%s", dt.Year(), int(dt.Month()), dt.Day(), tStr), true, nil
			}
		}
		if len(args) >= 5 {
			y, _ := evalNumArg(0)
			m, okM := evalNumArg(1)
			if !okM {
				mv, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
				if mi := parseMonthIndexPainless(mv); mi > 0 {
					m = float64(mi)
				}
			}
			d, _ := evalNumArg(2)
			hr, _ := evalNumArg(3)
			min, _ := evalNumArg(4)
			sec := 0.0
			nano := 0.0
			if len(args) >= 6 {
				sec, _ = evalNumArg(5)
			}
			if len(args) >= 7 {
				nano, _ = evalNumArg(6)
			}
			tm := time.Date(int(y), time.Month(int(m)), int(d), int(hr), int(min), int(sec), int(nano), time.UTC)
			if int(nano) > 0 {
				return tm.Format("2006-01-02T15:04:05.999999999"), true, nil
			}
			return tm.Format("2006-01-02T15:04:05"), true, nil
		}
		return nil, true, nil
	case "Duration.between":
		if len(args) >= 2 {
			v1, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			v2, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			t1, ok1 := parsePainlessDateTime(v1)
			t2, ok2 := parsePainlessDateTime(v2)
			if ok1 && ok2 {
				return t2.Sub(t1), true, nil
			}
		}
		return time.Duration(0), true, nil
	case "Duration.ofDays":
		if f, ok := evalNumArg(0); ok {
			return time.Duration(int64(f)) * 24 * time.Hour, true, nil
		}
		return time.Duration(0), true, nil
	case "Duration.ofHours":
		if f, ok := evalNumArg(0); ok {
			return time.Duration(int64(f)) * time.Hour, true, nil
		}
		return time.Duration(0), true, nil
	case "Duration.ofMinutes":
		if f, ok := evalNumArg(0); ok {
			return time.Duration(int64(f)) * time.Minute, true, nil
		}
		return time.Duration(0), true, nil
	case "Duration.ofSeconds":
		if f, ok := evalNumArg(0); ok {
			dur := time.Duration(int64(f)) * time.Second
			if len(args) >= 2 {
				if nf, ok2 := evalNumArg(1); ok2 {
					dur += time.Duration(int64(nf)) * time.Nanosecond
				}
			}
			return dur, true, nil
		}
		return time.Duration(0), true, nil
	case "Duration.ofMillis":
		if f, ok := evalNumArg(0); ok {
			return time.Duration(int64(f)) * time.Millisecond, true, nil
		}
		return time.Duration(0), true, nil
	case "Duration.ofNanos":
		if f, ok := evalNumArg(0); ok {
			return time.Duration(int64(f)) * time.Nanosecond, true, nil
		}
		return time.Duration(0), true, nil
	case "Duration.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if dur, ok := parsePainlessDuration(v); ok {
				return dur, true, nil
			}
		}
		return time.Duration(0), true, nil
	case "Period.of":
		if len(args) >= 3 {
			y, _ := evalNumArg(0)
			m, _ := evalNumArg(1)
			d, _ := evalNumArg(2)
			return painlessPeriod{years: int(y), months: int(m), days: int(d)}, true, nil
		}
		return painlessPeriod{}, true, nil
	case "Period.ofYears":
		if y, ok := evalNumArg(0); ok {
			return painlessPeriod{years: int(y)}, true, nil
		}
		return painlessPeriod{}, true, nil
	case "Period.ofMonths":
		if m, ok := evalNumArg(0); ok {
			return painlessPeriod{months: int(m)}, true, nil
		}
		return painlessPeriod{}, true, nil
	case "Period.ofWeeks":
		if w, ok := evalNumArg(0); ok {
			return painlessPeriod{days: int(w) * 7}, true, nil
		}
		return painlessPeriod{}, true, nil
	case "Period.ofDays":
		if d, ok := evalNumArg(0); ok {
			return painlessPeriod{days: int(d)}, true, nil
		}
		return painlessPeriod{}, true, nil
	case "Period.between":
		if len(args) >= 2 {
			v1, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			v2, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			t1, ok1 := parsePainlessDateTime(v1)
			t2, ok2 := parsePainlessDateTime(v2)
			if ok1 && ok2 {
				d1 := time.Date(t1.Year(), t1.Month(), t1.Day(), 0, 0, 0, 0, time.UTC)
				d2 := time.Date(t2.Year(), t2.Month(), t2.Day(), 0, 0, 0, 0, time.UTC)
				totalMonths := (d2.Year()-d1.Year())*12 + int(d2.Month()-d1.Month())
				days := d2.Day() - d1.Day()
				if totalMonths > 0 && days < 0 {
					totalMonths--
					calcDate := addMonthsClampedPainless(d1, totalMonths)
					days = int(d2.Sub(calcDate) / (24 * time.Hour))
				} else if totalMonths < 0 && days > 0 {
					totalMonths++
					days -= daysInMonthPainless(d2.Year(), d2.Month())
				}
				return painlessPeriod{
					years:  totalMonths / 12,
					months: totalMonths % 12,
					days:   days,
				}, true, nil
			}
		}
		return painlessPeriod{}, true, nil
	case "Period.parse":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if p, ok := parsePainlessPeriod(v); ok {
				return p, true, nil
			}
		}
		return painlessPeriod{}, true, nil
	case "ChronoUnit.YEARS.between", "ChronoUnit.MONTHS.between", "ChronoUnit.WEEKS.between", "ChronoUnit.DAYS.between", "ChronoUnit.HALF_DAYS.between", "ChronoUnit.HOURS.between", "ChronoUnit.MINUTES.between", "ChronoUnit.SECONDS.between", "ChronoUnit.MILLIS.between", "ChronoUnit.MICROS.between", "ChronoUnit.NANOS.between", "ChronoUnit.DECADES.between", "ChronoUnit.CENTURIES.between", "ChronoUnit.MILLENNIA.between":
		if len(args) >= 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err1 != nil {
				return int64(0), true, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err2 != nil {
				return int64(0), true, err2
			}
			unitName := strings.TrimSuffix(strings.TrimPrefix(fnName, "ChronoUnit."), ".between")
			return evalTemporalBetweenUnitPainless(unitName, v1, v2), true, nil
		}
		return int64(0), true, nil
	case "TemporalAdjusters.firstDayOfMonth", "TemporalAdjusters.lastDayOfMonth", "TemporalAdjusters.firstDayOfNextMonth",
		"TemporalAdjusters.firstDayOfYear", "TemporalAdjusters.lastDayOfYear", "TemporalAdjusters.firstDayOfNextYear",
		"TemporalAdjusters.next", "TemporalAdjusters.nextOrSame", "TemporalAdjusters.previous", "TemporalAdjusters.previousOrSame",
		"TemporalAdjusters.firstInMonth", "TemporalAdjusters.lastInMonth", "TemporalAdjusters.dayOfWeekInMonth":
		res, err := evalTemporalAdjustersStaticPainless(fnName, args, sourceMap, params, depth+1)
		return res, true, err
	case "Comparator.naturalOrder", "Comparator.reverseOrder", "Collections.reverseOrder",
		"Comparator.nullsFirst", "Comparator.nullsLast",
		"Comparator.comparing", "Comparator.comparingInt", "Comparator.comparingLong", "Comparator.comparingDouble":
		res, err := evalComparatorStaticPainless(fnName, args, sourceMap, params, depth+1)
		return res, true, err
	case "Character.charCount", "Character.toChars", "Character.toString", "Character.valueOf",
		"Character.isValidCodePoint", "Character.isBmpCodePoint", "Character.isSupplementaryCodePoint",
		"Character.isHighSurrogate", "Character.isLowSurrogate", "Character.isSurrogate", "Character.isSurrogatePair",
		"Character.toCodePoint", "Character.codePointAt", "Character.codePointBefore", "Character.codePointCount",
		"Character.getNumericValue", "Character.getType", "Character.compare",
		"Character.isDigit", "Character.isLetter", "Character.isLetterOrDigit", "Character.isAlphabetic",
		"Character.isWhitespace", "Character.isSpaceChar", "Character.isUpperCase", "Character.isLowerCase",
		"Character.isTitleCase", "Character.toUpperCase", "Character.toLowerCase", "Character.toTitleCase",
		"Character.isIdeographic", "Character.isJavaIdentifierStart", "Character.isJavaIdentifierPart",
		"Character.isISOControl", "Character.isDefined", "Character.digit", "Character.forDigit", "Character.reverseBytes":
		res, err := evalCharacterStaticPainless(fnName, args, sourceMap, params, depth+1)
		return res, true, err
	case "UUID.randomUUID":
		var b [16]byte
		_, _ = rand.Read(b[:])
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), true, nil
	case "UUID.nameUUIDFromBytes":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			sum := md5.Sum(toBytesPainless(v)) // #nosec G401 -- Java UUID.nameUUIDFromBytes specifies MD5 (UUID v3)
			sum[6] = (sum[6] & 0x0f) | 0x30
			sum[8] = (sum[8] & 0x3f) | 0x80
			return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]), true, nil
		}
		return "", true, nil
	case "UUID.fromString":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return "", true, err
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			formatted, ok := parseAndFormatUUIDPainless(s)
			if !ok {
				return "", true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Invalid UUID string: %s", s),
				}
			}
			return formatted, true, nil
		}
		return "", true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Invalid UUID string"}
	case "Pattern.compile":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if v != nil {
				patStr := fmt.Sprintf("%v", v)
				if isRawRegexLiteralPainless(patStr) && len(patStr) >= 2 && patStr[0] == '/' && patStr[len(patStr)-1] == '/' {
					patStr = strings.ReplaceAll(patStr[1:len(patStr)-1], `\/`, `/`)
				}
				rawPattern := patStr
				flags := 0
				if len(args) >= 2 {
					if ff, ok := evalNumArg(1); ok {
						flags = int(ff)
						if flags&16 != 0 { // Pattern.LITERAL
							patStr = regexp.QuoteMeta(patStr)
						} else {
							patStr = normalizeJavaNamedGroupsPainless(patStr)
						}
						var flagChars strings.Builder
						if flags&2 != 0 { // Pattern.CASE_INSENSITIVE
							flagChars.WriteByte('i')
						}
						if flags&8 != 0 { // Pattern.MULTILINE
							flagChars.WriteByte('m')
						}
						if flags&32 != 0 { // Pattern.DOTALL
							flagChars.WriteByte('s')
						}
						if flagChars.Len() > 0 {
							patStr = "(?" + flagChars.String() + ")" + patStr
						}
					}
				} else {
					patStr = normalizeJavaNamedGroupsPainless(patStr)
				}
				re, _ := compilePainlessRegexp(patStr)
				return &painlessPattern{
					raw:     rawPattern,
					flags:   flags,
					re:      re,
					literal: "/" + strings.ReplaceAll(patStr, "/", `\/`) + "/",
				}, true, nil
			}
		}
		return nil, true, nil
	case "Pattern.matches":
		if len(args) >= 2 {
			patVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			inVal, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			return evalRegexMatchPainless(inVal, patVal, isRawRegexLiteralPainless(strings.TrimSpace(args[0])), true), true, nil
		}
		return false, true, nil
	case "Pattern.quote":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			return regexp.QuoteMeta(fmt.Sprintf("%v", v)), true, nil
		}
		return "", true, nil
	case "Matcher.quoteReplacement":
		if len(args) >= 1 {
			v, _ := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			s := fmt.Sprintf("%v", v)
			s = strings.ReplaceAll(s, `\`, `\\`)
			s = strings.ReplaceAll(s, `$`, `\$`)
			return s, true, nil
		}
		return "", true, nil
	}
	budget := getOrInitEvalBudget(params)
	if params != nil {
		if thisObj, isUO := params["this"].(*painlessUserObject); isUO && thisObj != nil && thisObj.class != nil && thisObj.class.methods[fnName] != nil {
			res, err := evalUserObjectMethodPainless(thisObj, fnName, argStr, sourceMap, params, depth+1)
			return res, true, err
		}
	}
	if budget != nil && budget.userFuncs != nil {
		if fn, ok := budget.userFuncs[fnName]; ok && fn != nil {
			if err := budget.step(); err != nil {
				return nil, true, err
			}
			var argVals []any
			if argStr != "" {
				argVals = make([]any, len(args))
				for i, a := range args {
					av, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(a), params, depth+1)
					if err != nil {
						return nil, true, err
					}
					argVals[i] = av
				}
			}
			fnParams := make(map[string]any, len(params)+len(fn.paramNames)+4)
			for k, v := range params {
				if k == "_return_val" || k == "_last_expr_val" || k == "__loop_declared" || k == "__reassigned_vars" {
					continue
				}
				fnParams[k] = v
			}
			fnLocals := make(map[string]bool)
			if sl, ok := params["__script_locals"].(map[string]bool); ok {
				for k, v := range sl {
					fnLocals[k] = v
				}
			}
			fnParams["__script_locals"] = fnLocals
			reassignedVars := make(map[string]bool)
			fnParams["__reassigned_vars"] = reassignedVars
			fnParams["__eval_budget"] = budget
			preCallEp := make(map[string]bool)
			if ep, ok := params["__explicit_params_keys"].(map[string]bool); ok {
				for k, v := range ep {
					if v {
						preCallEp[k] = true
					}
				}
			}
			paramNamesSet := make(map[string]bool, len(fn.paramNames))
			callerVarBindings := make(map[string]string, len(fn.paramNames))
			for i, pName := range fn.paramNames {
				paramNamesSet[pName] = true
				if i < len(argVals) {
					fnParams[pName] = argVals[i]
				} else {
					fnParams[pName] = nil
				}
				fnLocals[pName] = true
				delete(fnParams, "__alias_"+pName)
				if i < len(args) {
					argExpr := strings.TrimSpace(expandDynamicBrackets(strings.TrimSpace(args[i]), sourceMap, params, depth+1))
					matchedAlias := false
					for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
						if strings.HasPrefix(argExpr, pfx) {
							tail := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(argExpr, pfx)), "?")
							if reSimpleFieldPath.MatchString(tail) && !strings.HasSuffix(tail, ".size()") && !strings.HasSuffix(tail, ".length()") {
								switch argVals[i].(type) {
								case []any, map[string]any:
									fnParams["__alias_"+pName] = tail
									matchedAlias = true
								}
							}
							break
						}
					}
					if !matchedAlias && reSimpleFieldPath.MatchString(argExpr) && !strings.Contains(argExpr, ".") {
						callerVar := decodeBracketSeg(argExpr)
						if _, exists := params[callerVar]; exists {
							if _, isSlice := argVals[i].([]any); isSlice {
								callerVarBindings[pName] = callerVar
							}
							if aliasPath, ok := params["__alias_"+callerVar].(string); ok && aliasPath != "" {
								fnParams["__alias_"+pName] = aliasPath
							}
						}
					} else if !matchedAlias && reSimpleFieldPath.MatchString(argExpr) && !strings.HasSuffix(argExpr, ".size()") && !strings.HasSuffix(argExpr, ".length()") {
						rhsParts := normalizeLocalLHSPath(strings.Split(argExpr, "."), params)
						if len(rhsParts) > 0 {
							rootVar := decodeBracketSeg(rhsParts[0])
							if baseAlias, ok := params["__alias_"+rootVar].(string); ok && baseAlias != "" {
								switch argVals[i].(type) {
								case []any, map[string]any:
									fnParams["__alias_"+pName] = strings.Join(append([]string{baseAlias}, rhsParts[1:]...), ".")
								}
							}
						}
					}
				}
			}
			fnCtxOp := ""
			err := execBlock(sourceMap, fn.body, fnParams, &fnCtxOp, budget)
			for _, pName := range fn.paramNames {
				if !reassignedVars[pName] {
					syncLocalVarAlias(sourceMap, fnParams, pName)
					if callerVar, bound := callerVarBindings[pName]; bound && params != nil {
						params[callerVar] = fnParams[pName]
						syncLocalVarAlias(sourceMap, params, callerVar)
					}
				}
			}
			if params != nil {
				if ep, ok := fnParams["__explicit_params_keys"].(map[string]bool); ok {
					for k := range ep {
						if paramNamesSet[k] {
							continue
						}
						if v, exists := fnParams[k]; exists {
							params[k] = v
						}
					}
					for k := range preCallEp {
						if !ep[k] && !paramNamesSet[k] {
							delete(params, k)
						}
					}
				}
			}
			if fnCtxOp != "" {
				budget.ctxOp = fnCtxOp
				budget.hasCtxOp = true
				if params != nil {
					params["_ctx_op"] = fnCtxOp
				}
			}
			if params != nil {
				for _, metaKey := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version"} {
					if v, exists := fnParams[metaKey]; exists {
						params[metaKey] = v
					}
				}
			}
			if err != nil && !errors.Is(err, errPainlessReturn) {
				return nil, true, err
			}
			if fn.returnType == "void" {
				return nil, true, nil
			}
			if retVal, hasRet := fnParams["_return_val"]; hasRet {
				return retVal, true, nil
			}
			return fnParams["_last_expr_val"], true, nil
		}
	}
	return nil, false, nil
}

func normalizeJavaRegexReplacement(repl string) string {
	var sb strings.Builder
	sb.Grow(len(repl) + 8)
	for i := 0; i < len(repl); i++ {
		if repl[i] == '\\' && i+1 < len(repl) {
			i++
			if repl[i] == '$' {
				sb.WriteString("$$")
			} else {
				sb.WriteByte(repl[i])
			}
			continue
		}
		if repl[i] == '$' {
			if i+1 < len(repl) && repl[i+1] >= '0' && repl[i+1] <= '9' {
				j := i + 1
				for j < len(repl) && repl[j] >= '0' && repl[j] <= '9' {
					j++
				}
				sb.WriteString("${")
				sb.WriteString(repl[i+1 : j])
				sb.WriteByte('}')
				i = j - 1
				continue
			}
			if i+1 < len(repl) && repl[i+1] == '{' {
				if closeRel := strings.IndexByte(repl[i+2:], '}'); closeRel > 0 {
					sb.WriteString(repl[i : i+2+closeRel+1])
					i += 2 + closeRel
					continue
				}
			}
			sb.WriteString("$$")
			continue
		}
		sb.WriteByte(repl[i])
	}
	return sb.String()
}

func comparePainlessValues(a, b any) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	if ya, okA := a.(painlessYear); okA {
		if yb, okB := b.(painlessYear); okB {
			if ya.year < yb.year {
				return -1
			}
			if ya.year > yb.year {
				return 1
			}
			return 0
		}
	}
	if ma, okA := a.(painlessMonthDay); okA {
		if mb, okB := b.(painlessMonthDay); okB {
			if ma.month != mb.month {
				if ma.month < mb.month {
					return -1
				}
				return 1
			}
			if ma.day < mb.day {
				return -1
			}
			if ma.day > mb.day {
				return 1
			}
			return 0
		}
	}
	if ba, okA := a.(*painlessBigDecimal); okA && ba != nil {
		if bb, okB := parsePainlessBigDecimal(b); okB && bb != nil {
			return compareBigDecimalPainless(ba, bb)
		}
	}
	if bb, okB := b.(*painlessBigDecimal); okB && bb != nil {
		if ba, okA := parsePainlessBigDecimal(a); okA && ba != nil {
			return compareBigDecimalPainless(ba, bb)
		}
	}
	if ia, okA := a.(*painlessBigInteger); okA && ia != nil && ia.val != nil {
		if ib, okB := parsePainlessBigInteger(b); okB && ib != nil && ib.val != nil {
			return ia.val.Cmp(ib.val)
		}
	}
	if ib, okB := b.(*painlessBigInteger); okB && ib != nil && ib.val != nil {
		if ia, okA := parsePainlessBigInteger(a); okA && ia != nil && ia.val != nil {
			return ia.val.Cmp(ib.val)
		}
	}
	fa, okA := toFloat64(a)
	fb, okB := toFloat64(b)
	if okA && okB {
		if fa < fb {
			return -1
		}
		if fa > fb {
			return 1
		}
		return 0
	}
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

func evalPainlessComparatorPair(cmpExpr string, a, b any, sourceMap, params map[string]any, depth int) (int, error) {
	cmpExpr = strings.TrimSpace(cmpExpr)
	if cmpExpr == "" || cmpExpr == "null" {
		return comparePainlessValues(a, b), nil
	}
	if findNextUnquotedSubstr(cmpExpr, "->", 0) < 0 && findTopLevelSubstrPainless(cmpExpr, "::") < 0 {
		if cmpVal, err := evalRHSExprDepth(sourceMap, cmpExpr, params, depth+1); err == nil {
			if pc, ok := cmpVal.(*painlessComparator); ok && pc != nil {
				return evalComparatorObjectPairPainless(pc, a, b, sourceMap, params, depth+1)
			}
		}
	} else if strings.HasPrefix(cmpExpr, "Comparator.") || strings.HasPrefix(cmpExpr, "java.util.Comparator.") || strings.HasPrefix(cmpExpr, "Collections.") || strings.HasPrefix(cmpExpr, "String.CASE_INSENSITIVE_ORDER") {
		if cmpVal, err := evalRHSExprDepth(sourceMap, cmpExpr, params, depth+1); err == nil {
			if pc, ok := cmpVal.(*painlessComparator); ok && pc != nil {
				return evalComparatorObjectPairPainless(pc, a, b, sourceMap, params, depth+1)
			}
		}
	} else if dotIdx := strings.IndexByte(cmpExpr, '.'); dotIdx > 0 && params != nil {
		rootIdent := strings.TrimSpace(cmpExpr[:dotIdx])
		if _, isPC := params[rootIdent].(*painlessComparator); isPC {
			if cmpVal, err := evalRHSExprDepth(sourceMap, cmpExpr, params, depth+1); err == nil {
				if pc, ok := cmpVal.(*painlessComparator); ok && pc != nil {
					return evalComparatorObjectPairPainless(pc, a, b, sourceMap, params, depth+1)
				}
			}
		}
	}
	reversed := false
	if strings.HasSuffix(cmpExpr, ".reversed()") {
		reversed = true
		cmpExpr = strings.TrimSpace(strings.TrimSuffix(cmpExpr, ".reversed()"))
	}
	applyRev := func(c int) int {
		if reversed {
			return -c
		}
		return c
	}
	if strings.Contains(cmpExpr, "reverseOrder") {
		return applyRev(comparePainlessValues(b, a)), nil
	}
	if strings.Contains(cmpExpr, "naturalOrder") {
		return applyRev(comparePainlessValues(a, b)), nil
	}
	for _, cmpPfx := range []string{"Comparator.comparingInt(", "Comparator.comparingLong(", "Comparator.comparingDouble(", "Comparator.comparing("} {
		if strings.HasPrefix(cmpExpr, cmpPfx) && strings.HasSuffix(cmpExpr, ")") {
			keyFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(cmpExpr[len(cmpPfx):len(cmpExpr)-1]), 1)
			if arrowIdx := findNextUnquotedSubstr(keyFn, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(keyFn[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := strings.TrimSpace(keyFn[arrowIdx+2:])
					prev, hadPrev := params[pName]
					params[pName] = a
					ka, err1 := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
					params[pName] = b
					kb, err2 := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					if err1 != nil {
						return 0, err1
					}
					if err2 != nil {
						return 0, err2
					}
					return applyRev(comparePainlessValues(ka, kb)), nil
				}
			}
		}
	}
	cmpExpr = normalizeMethodReferenceToLambdaPainless(cmpExpr, 2)
	if arrowIdx := strings.Index(cmpExpr, "->"); arrowIdx > 0 {
		pNames := parsePainlessLambdaHeader(cmpExpr[:arrowIdx])
		if len(pNames) >= 2 {
			pA, pB := pNames[0], pNames[1]
			body := strings.TrimSpace(cmpExpr[arrowIdx+2:])
			prevA, hadA := params[pA]
			prevB, hadB := params[pB]
			params[pA] = a
			params[pB] = b
			res, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if hadA {
				params[pA] = prevA
			} else {
				delete(params, pA)
			}
			if hadB {
				params[pB] = prevB
			} else {
				delete(params, pB)
			}
			if err != nil {
				return 0, err
			}
			if f, ok := toFloat64(res); ok {
				if f < 0 {
					return applyRev(-1), nil
				}
				if f > 0 {
					return applyRev(1), nil
				}
				return 0, nil
			}
		}
	}
	return applyRev(comparePainlessValues(a, b)), nil
}

func normalizeMethodReferenceToLambdaPainless(expr string, arity int) string {
	expr = strings.TrimSpace(expr)
	if findNextUnquotedSubstr(expr, "->", 0) >= 0 {
		return expr
	}
	for len(expr) >= 2 && expr[0] == '(' && expr[len(expr)-1] == ')' && findMatchingDelimiter(expr, 0, '(', ')') == len(expr)-1 {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	ccIdx := findTopLevelSubstrPainless(expr, "::")
	if ccIdx <= 0 {
		return expr
	}
	target := strings.TrimSpace(expr[:ccIdx])
	method := strings.TrimSpace(expr[ccIdx+2:])
	if target == "" || method == "" {
		return expr
	}
	for i := 0; i < len(method); i++ {
		if !isIdentByte(method[i]) {
			return expr
		}
	}
	for _, pfx := range []string{"java.util.stream.", "java.util.regex.", "java.util.", "java.lang.", "java.math.", "java.time."} {
		if strings.HasPrefix(target, pfx) {
			target = strings.TrimPrefix(target, pfx)
			break
		}
	}
	if strings.HasSuffix(target, ">") {
		if openA := strings.IndexByte(target, '<'); openA > 0 {
			target = strings.TrimSpace(target[:openA])
		}
	}
	if arity == 0 {
		if method == "new" {
			switch target {
			case "String":
				return `() -> ""`
			case "ArrayList", "LinkedList":
				return "() -> new ArrayList()"
			case "HashMap", "LinkedHashMap", "TreeMap":
				return "() -> new HashMap()"
			case "HashSet", "LinkedHashSet", "TreeSet":
				return "() -> new HashSet()"
			case "StringBuilder", "StringBuffer":
				return "() -> new StringBuilder()"
			default:
				return "() -> new " + target + "()"
			}
		}
		return "() -> " + target + "." + method + "()"
	}
	if arity == 2 {
		switch target + "::" + method {
		case "Integer::sum", "Long::sum", "Double::sum", "Float::sum", "Short::sum", "Byte::sum":
			return "(__mr0, __mr1) -> __mr0 + __mr1"
		case "Integer::max", "Long::max", "Double::max", "Float::max", "Math::max", "StrictMath::max":
			return "(__mr0, __mr1) -> Math.max(__mr0, __mr1)"
		case "Integer::min", "Long::min", "Double::min", "Float::min", "Math::min", "StrictMath::min":
			return "(__mr0, __mr1) -> Math.min(__mr0, __mr1)"
		case "Integer::compare", "Long::compare", "Double::compare", "Float::compare", "Short::compare", "Byte::compare", "Boolean::compare":
			return "(__mr0, __mr1) -> " + target + ".compare(__mr0, __mr1)"
		case "String::concat":
			return "(__mr0, __mr1) -> __mr0.concat(__mr1)"
		case "String::compareTo", "Integer::compareTo", "Long::compareTo", "Double::compareTo", "Float::compareTo", "BigDecimal::compareTo":
			return "(__mr0, __mr1) -> __mr0.compareTo(__mr1)"
		case "String::compareToIgnoreCase":
			return "(__mr0, __mr1) -> __mr0.compareToIgnoreCase(__mr1)"
		case "BigDecimal::add", "BigDecimal::subtract", "BigDecimal::multiply", "BigDecimal::min", "BigDecimal::max":
			return "(__mr0, __mr1) -> __mr0." + method + "(__mr1)"
		}
		return "(__mr0, __mr1) -> " + target + "." + method + "(__mr0, __mr1)"
	}
	// Default: arity == 1
	if method == "new" {
		switch target {
		case "ArrayList", "LinkedList":
			return "__mr0 -> new ArrayList()"
		case "HashMap", "LinkedHashMap", "TreeMap":
			return "__mr0 -> new HashMap()"
		case "HashSet", "LinkedHashSet", "TreeSet":
			return "__mr0 -> new HashSet()"
		case "StringBuilder", "StringBuffer":
			return "__mr0 -> new StringBuilder(__mr0)"
		case "String":
			return "__mr0 -> new String(__mr0)"
		case "BigDecimal":
			return "__mr0 -> new BigDecimal(__mr0)"
		default:
			return "__mr0 -> new " + target + "(__mr0)"
		}
	}
	switch target + "::" + method {
	case "Objects::nonNull":
		return "__mr0 -> __mr0 != null"
	case "Objects::isNull":
		return "__mr0 -> __mr0 == null"
	case "Objects::toString":
		return "__mr0 -> Objects.toString(__mr0)"
	case "String::valueOf":
		return "__mr0 -> String.valueOf(__mr0)"
	case "Integer::parseInt", "Integer::valueOf":
		return "__mr0 -> Integer.parseInt(__mr0)"
	case "Long::parseLong", "Long::valueOf":
		return "__mr0 -> Long.parseLong(__mr0)"
	case "Double::parseDouble", "Double::valueOf":
		return "__mr0 -> Double.parseDouble(__mr0)"
	case "Float::parseFloat", "Float::valueOf":
		return "__mr0 -> Float.parseFloat(__mr0)"
	case "Short::parseShort", "Short::valueOf":
		return "__mr0 -> Short.parseShort(__mr0)"
	case "Byte::parseByte", "Byte::valueOf":
		return "__mr0 -> Byte.parseByte(__mr0)"
	case "Boolean::parseBoolean", "Boolean::valueOf":
		return "__mr0 -> Boolean.parseBoolean(__mr0)"
	case "BigDecimal::valueOf":
		return "__mr0 -> BigDecimal.valueOf(__mr0)"
	case "Math::abs", "StrictMath::abs":
		return "__mr0 -> Math.abs(__mr0)"
	}
	switch target {
	case "String", "CharSequence", "Object", "Number", "Integer", "Long", "Double", "Float", "Short", "Byte", "Boolean",
		"BigDecimal", "Collection", "List", "ArrayList", "Set", "HashSet", "Map", "HashMap", "Map.Entry", "Entry", "Optional",
		"LocalDate", "LocalTime", "LocalDateTime", "ZonedDateTime", "OffsetDateTime", "Instant", "YearMonth":
		switch method {
		case "toLowerCase", "toUpperCase", "trim", "strip", "stripLeading", "stripTrailing", "length", "isEmpty", "isBlank",
			"toString", "toPlainString", "getKey", "getValue", "stream", "size", "intValue", "longValue", "doubleValue", "floatValue",
			"shortValue", "byteValue", "get", "getAsInt", "getAsLong", "getAsDouble", "isPresent", "abs", "negate", "plus",
			"stripTrailingZeros", "scale", "precision", "signum", "toLocalDate", "toLocalTime", "toEpochDay", "toSecondOfDay", "toNanoOfDay", "toEpochMilli":
			return "__mr0 -> __mr0." + method + "()"
		}
	}
	return "__mr0 -> " + target + "." + method + "(__mr0)"
}

func sortPainlessSliceInPlace(arr []any, cmpExpr string, sourceMap, params map[string]any, depth int) error {
	if len(arr) <= 1 {
		return nil
	}
	cmpExpr = strings.TrimSpace(cmpExpr)
	if cmpExpr != "" && cmpExpr != "null" {
		tryEvalCmpObj := findTopLevelSubstrPainless(cmpExpr, "->") < 0 && findTopLevelSubstrPainless(cmpExpr, "::") < 0
		if !tryEvalCmpObj && (strings.HasPrefix(cmpExpr, "Comparator.") || strings.HasPrefix(cmpExpr, "java.util.Comparator.") || strings.HasPrefix(cmpExpr, "Collections.") || strings.HasPrefix(cmpExpr, "String.CASE_INSENSITIVE_ORDER")) {
			tryEvalCmpObj = true
		}
		if !tryEvalCmpObj {
			if dotIdx := strings.IndexByte(cmpExpr, '.'); dotIdx > 0 && params != nil {
				if _, isPC := params[strings.TrimSpace(cmpExpr[:dotIdx])].(*painlessComparator); isPC {
					tryEvalCmpObj = true
				}
			}
		}
		if tryEvalCmpObj {
			if cmpVal, err := evalRHSExprDepth(sourceMap, cmpExpr, params, depth+1); err == nil {
				if pc, ok := cmpVal.(*painlessComparator); ok && pc != nil {
					var sortErr error
					sort.SliceStable(arr, func(i, j int) bool {
						if sortErr != nil {
							return false
						}
						c, cErr := evalComparatorObjectPairPainless(pc, arr[i], arr[j], sourceMap, params, depth+1)
						if cErr != nil {
							sortErr = cErr
							return false
						}
						return c < 0
					})
					return sortErr
				}
			}
		}
	}
	reversed := false
	if strings.HasSuffix(cmpExpr, ".reversed()") {
		reversed = true
		cmpExpr = strings.TrimSpace(strings.TrimSuffix(cmpExpr, ".reversed()"))
	}
	if strings.Contains(cmpExpr, "reverseOrder") {
		sort.SliceStable(arr, func(i, j int) bool {
			if reversed {
				return comparePainlessValues(arr[i], arr[j]) < 0
			}
			return comparePainlessValues(arr[i], arr[j]) > 0
		})
		return nil
	}
	if strings.Contains(cmpExpr, "naturalOrder") {
		sort.SliceStable(arr, func(i, j int) bool {
			if reversed {
				return comparePainlessValues(arr[i], arr[j]) > 0
			}
			return comparePainlessValues(arr[i], arr[j]) < 0
		})
		return nil
	}
	for _, cmpPfx := range []string{"Comparator.comparingInt(", "Comparator.comparingLong(", "Comparator.comparingDouble(", "Comparator.comparing("} {
		if strings.HasPrefix(cmpExpr, cmpPfx) && strings.HasSuffix(cmpExpr, ")") {
			keyFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(cmpExpr[len(cmpPfx):len(cmpExpr)-1]), 1)
			if arrowIdx := findNextUnquotedSubstr(keyFn, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(keyFn[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := strings.TrimSpace(keyFn[arrowIdx+2:])
					keys := make([]any, len(arr))
					prev, hadPrev := params[pName]
					for idx, item := range arr {
						params[pName] = item
						kv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return err
						}
						keys[idx] = kv
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					indices := make([]int, len(arr))
					for i := range indices {
						indices[i] = i
					}
					sort.SliceStable(indices, func(i, j int) bool {
						c := comparePainlessValues(keys[indices[i]], keys[indices[j]])
						if reversed {
							return c > 0
						}
						return c < 0
					})
					sorted := make([]any, len(arr))
					for i, origIdx := range indices {
						sorted[i] = arr[origIdx]
					}
					copy(arr, sorted)
					return nil
				}
			}
		}
	}
	cmpExpr = normalizeMethodReferenceToLambdaPainless(cmpExpr, 2)
	if arrowIdx := strings.Index(cmpExpr, "->"); arrowIdx > 0 {
		lhs := strings.TrimSpace(cmpExpr[:arrowIdx])
		lhs = strings.TrimPrefix(strings.TrimSuffix(lhs, ")"), "(")
		paramParts := strings.Split(lhs, ",")
		if len(paramParts) == 2 {
			fA := strings.Fields(paramParts[0])
			fB := strings.Fields(paramParts[1])
			if len(fA) > 0 && len(fB) > 0 {
				pA := fA[len(fA)-1]
				pB := fB[len(fB)-1]
				body := strings.TrimSpace(cmpExpr[arrowIdx+2:])
				preExistingKeys := make(map[string]bool, len(params))
				cmpParams := make(map[string]any, len(params)+2)
				for k, v := range params {
					preExistingKeys[k] = true
					cmpParams[k] = v
				}
				loopDeclared := make(map[string]bool)
				cmpParams["__loop_declared"] = loopDeclared
				var sortErr error
				sort.SliceStable(arr, func(i, j int) bool {
					if sortErr != nil {
						return false
					}
					if reversed {
						cmpParams[pA] = arr[j]
						cmpParams[pB] = arr[i]
					} else {
						cmpParams[pA] = arr[i]
						cmpParams[pB] = arr[j]
					}
					res, err := evalPainlessLambdaBody(body, sourceMap, cmpParams, depth+1)
					if err != nil {
						sortErr = err
						return false
					}
					if res == nil {
						return false
					}
					if f, ok := toFloat64(res); ok {
						return f < 0
					}
					if b, ok := res.(bool); ok {
						return b
					}
					return false
				})
				syncLoopScopeBack(params, cmpParams, preExistingKeys, map[string]bool{pA: true, pB: true}, loopDeclared)
				return sortErr
			}
		}
	}
	sort.SliceStable(arr, func(i, j int) bool {
		if reversed {
			return comparePainlessValues(arr[i], arr[j]) > 0
		}
		return comparePainlessValues(arr[i], arr[j]) < 0
	})
	return nil
}

func parseHexOrBinaryIntLiteralPainless(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 3 {
		return 0, false
	}
	sign := int64(1)
	switch s[0] {
	case '-':
		sign = -1
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if len(s) < 3 || s[0] != '0' {
		return 0, false
	}
	base := 0
	switch s[1] {
	case 'x', 'X':
		base = 16
	case 'b', 'B':
		base = 2
	default:
		return 0, false
	}
	digits := s[2:]
	if strings.HasSuffix(digits, "L") || strings.HasSuffix(digits, "l") {
		digits = digits[:len(digits)-1]
	}
	digits = strings.ReplaceAll(digits, "_", "")
	if digits == "" {
		return 0, false
	}
	if sign < 0 {
		if iv, err := strconv.ParseInt("-"+digits, base, 64); err == nil {
			return iv, true
		}
		return 0, false
	}
	if iv, err := strconv.ParseInt(digits, base, 64); err == nil {
		return iv, true
	}
	return 0, false
}

func parsePainlessLambdaHeader(lhs string) []string {
	lhs = strings.TrimSpace(lhs)
	lhs = strings.TrimPrefix(strings.TrimSuffix(lhs, ")"), "(")
	if strings.TrimSpace(lhs) == "" {
		return nil
	}
	parts := strings.Split(lhs, ",")
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) > 0 {
			names = append(names, fields[len(fields)-1])
		}
	}
	return names
}

func evalPainlessLambdaBody(body string, sourceMap, params map[string]any, depth int) (any, error) {
	budget := getOrInitEvalBudget(params)
	if err := budget.step(); err != nil {
		return nil, err
	}
	body = strings.TrimSpace(body)
	if (strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}")) || isTopLevelAssignmentStmt(body) {
		inner := body
		if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
			inner = strings.TrimSpace(body[1 : len(body)-1])
		}
		preExistingKeys := make(map[string]bool, len(params))
		lambdaParams := make(map[string]any, len(params)+2)
		for k, v := range params {
			if k == "_return_val" || k == "_last_expr_val" {
				continue
			}
			preExistingKeys[k] = true
			lambdaParams[k] = v
		}
		loopDeclared := make(map[string]bool)
		lambdaParams["__loop_declared"] = loopDeclared
		ctxOp := ""
		err := execBlock(sourceMap, inner, lambdaParams, &ctxOp, budget)
		if err != nil && !errors.Is(err, errPainlessReturn) {
			return nil, err
		}
		var retVal any
		if rv, hasRet := lambdaParams["_return_val"]; hasRet {
			retVal = rv
		} else {
			retVal = lambdaParams["_last_expr_val"]
		}
		delete(lambdaParams, "_return_val")
		delete(lambdaParams, "_last_expr_val")
		syncLoopScopeBack(params, lambdaParams, preExistingKeys, nil, loopDeclared)
		if ctxOp != "" {
			params["_ctx_op"] = ctxOp
		}
		return retVal, nil
	}
	body = strings.TrimSpace(strings.TrimSuffix(body, ";"))
	if strings.HasPrefix(body, "return ") || strings.HasPrefix(body, "return(") {
		body = strings.TrimSpace(strings.TrimPrefix(body, "return"))
	}
	return evalRHSExprDepth(sourceMap, body, params, depth+1)
}

func evalPainlessPredicateLambda(body string, sourceMap, params map[string]any, depth int) (bool, error) {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		val, err := evalPainlessLambdaBody(body, sourceMap, params, depth)
		if err != nil {
			return false, err
		}
		if b, ok := val.(bool); ok {
			return b, nil
		}
		if val != nil {
			return strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", val)), "true"), nil
		}
		return false, nil
	}
	condBody := strings.TrimSpace(strings.TrimSuffix(body, ";"))
	if strings.HasPrefix(condBody, "return ") || strings.HasPrefix(condBody, "return(") {
		condBody = strings.TrimSpace(strings.TrimPrefix(condBody, "return"))
	}
	return evalConditionDepth(sourceMap, condBody, params, depth), nil
}

func execPainlessListReplaceAll(recExpr, argExpr string, sourceMap, params map[string]any, depth int) (bool, error) {
	argExpr = normalizeMethodReferenceToLambdaPainless(argExpr, 1)
	arrowIdx := findNextUnquotedSubstr(argExpr, "->", 0)
	if arrowIdx <= 0 {
		return false, nil
	}
	pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
	if len(pNames) == 0 {
		return false, nil
	}
	pName := pNames[0]
	body := strings.TrimSpace(argExpr[arrowIdx+2:])

	var recVal any
	if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
		recVal = sourceMap
	} else {
		var err error
		recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil {
			return true, err
		}
	}
	if _, isMatcher := recVal.(*painlessMatcher); isMatcher {
		return false, nil
	}
	if recMap, isMap := recVal.(map[string]any); isMap && recMap != nil && len(pNames) >= 2 {
		kName, vName := pNames[0], pNames[1]
		prevK, hadK := params[kName]
		prevV, hadV := params[vName]
		keys := visiblePainlessMapKeys(recMap)
		for _, k := range keys {
			params[kName] = k
			params[vName] = recMap[k]
			newVal, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if err != nil {
				if hadK {
					params[kName] = prevK
				} else {
					delete(params, kName)
				}
				if hadV {
					params[vName] = prevV
				} else {
					delete(params, vName)
				}
				return true, err
			}
			recMap[k] = newVal
		}
		if hadK {
			params[kName] = prevK
		} else {
			delete(params, kName)
		}
		if hadV {
			params[vName] = prevV
		} else {
			delete(params, vName)
		}
		if recExpr == "ctx" || recExpr == "ctx?" || recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
			for _, k := range keys {
				sourceMap[k] = recMap[k]
				syncSourceAliasToLocalVars(sourceMap, params, k)
			}
			return true, nil
		}
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(recExpr, pfx) {
				relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
				syncSourceAliasToLocalVars(sourceMap, params, relPath)
				return true, nil
			}
		}
		cleanRec := strings.TrimSuffix(recExpr, "?")
		mapPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
		if len(mapPath) > 0 {
			syncLocalVarAlias(sourceMap, params, decodeBracketSeg(mapPath[0]))
		}
		return true, nil
	}
	arr, ok := recVal.([]any)
	if !ok {
		return true, nil
	}
	prevVal, hadPrev := params[pName]
	for i, item := range arr {
		params[pName] = item
		newVal, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
		if err != nil {
			if hadPrev {
				params[pName] = prevVal
			} else {
				delete(params, pName)
			}
			return true, err
		}
		arr[i] = newVal
	}
	if hadPrev {
		params[pName] = prevVal
	} else {
		delete(params, pName)
	}
	for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
		if strings.HasPrefix(recExpr, pfx) {
			relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
			syncSourceAliasToLocalVars(sourceMap, params, relPath)
			return true, nil
		}
	}
	cleanRec := strings.TrimSuffix(recExpr, "?")
	arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
	if len(arrPath) > 0 {
		syncLocalVarAlias(sourceMap, params, decodeBracketSeg(arrPath[0]))
	}
	return true, nil
}

func execPainlessForEach(recExpr, argExpr string, sourceMap, params map[string]any, depth int) error {
	argExpr = normalizeMethodReferenceToLambdaPainless(argExpr, 1)
	arrowIdx := findNextUnquotedSubstr(argExpr, "->", 0)
	if arrowIdx <= 0 {
		return nil
	}
	pNames := parsePainlessLambdaHeader(argExpr[:arrowIdx])
	if len(pNames) == 0 {
		return nil
	}
	body := strings.TrimSpace(argExpr[arrowIdx+2:])
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body = strings.TrimSpace(body[1 : len(body)-1])
	}

	var recVal any
	expRec := strings.TrimSpace(expandDynamicBrackets(recExpr, sourceMap, params, depth+1))
	if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
		recVal = sourceMap
	} else if (strings.HasPrefix(expRec, "doc.") || strings.HasPrefix(expRec, "doc?.")) &&
		!strings.HasSuffix(expRec, ".value") && !strings.Contains(expRec, ".value.") && !strings.Contains(expRec, ".values.") && !strings.Contains(expRec, "(") {
		docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expRec, "doc?."), "doc."), ".values")
		recVal = resolveDocValuesSlice(sourceMap, docPath)
	} else {
		var err error
		recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil {
			return err
		}
	}

	ctxOp := ""
	budget := getOrInitEvalBudget(params)
	preExistingKeys := make(map[string]bool, len(params))
	loopParams := make(map[string]any, len(params)+2)
	for k, v := range params {
		if k == "_return_val" || k == "_last_expr_val" {
			continue
		}
		preExistingKeys[k] = true
		loopParams[k] = v
	}
	excludedVars := make(map[string]bool, len(pNames))
	loopDeclared := make(map[string]bool)
	for _, n := range pNames {
		excludedVars[n] = true
		if !preExistingKeys[n] {
			loopDeclared[n] = true
		}
	}
	loopParams["__loop_declared"] = loopDeclared
	var loopErr error

	switch tv := recVal.(type) {
	case []any:
		snapshot := make([]any, len(tv))
		copy(snapshot, tv)
		for _, item := range snapshot {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
			loopParams[pNames[0]] = item
			if err := execBlock(sourceMap, body, loopParams, &ctxOp, budget); err != nil {
				if errors.Is(err, errPainlessReturn) {
					delete(loopParams, "_return_val")
					continue
				}
				loopErr = err
				break
			}
		}
	case map[string]any:
		keys := visiblePainlessMapKeys(tv)
		for _, k := range keys {
			if err := budget.step(); err != nil {
				loopErr = err
				break
			}
			v := tv[k]
			if len(pNames) >= 2 {
				loopParams[pNames[0]] = k
				loopParams[pNames[1]] = v
			} else {
				loopParams[pNames[0]] = map[string]any{"key": k, "value": v, "__parent_map": tv}
			}
			if err := execBlock(sourceMap, body, loopParams, &ctxOp, budget); err != nil {
				if errors.Is(err, errPainlessReturn) {
					delete(loopParams, "_return_val")
					continue
				}
				loopErr = err
				break
			}
		}
	}
	delete(loopParams, "_return_val")
	delete(loopParams, "_last_expr_val")
	syncLoopScopeBack(params, loopParams, preExistingKeys, excludedVars, loopDeclared)
	if ctxOp != "" {
		params["_ctx_op"] = ctxOp
	}
	return loopErr
}

func resolveMutableReceiverPainless(sourceMap map[string]any, recExpr string, params map[string]any, depth int) (any, func(any), error) {
	recExpr = strings.TrimSpace(recExpr)
	for len(recExpr) >= 2 && recExpr[0] == '(' && recExpr[len(recExpr)-1] == ')' && findMatchingDelimiter(recExpr, 0, '(', ')') == len(recExpr)-1 {
		recExpr = strings.TrimSpace(recExpr[1 : len(recExpr)-1])
	}
	if strings.HasSuffix(recExpr, ")") {
		openP := -1
		inQuotes := byte(0)
		inRegexClass := false
		for i := 0; i < len(recExpr)-1; i++ {
			if stepQuoteState(recExpr, i, &inQuotes, &inRegexClass) {
				continue
			}
			if recExpr[i] == '(' && findMatchingDelimiter(recExpr, i, '(', ')') == len(recExpr)-1 {
				openP = i
				break
			}
		}
		if openP > 1 {
			identEnd := openP
			identStart := identEnd
			for identStart > 0 && isIdentByte(recExpr[identStart-1]) {
				identStart--
			}
			if identStart < identEnd && identStart > 0 && recExpr[identStart-1] == '.' {
				dotIdx := identStart - 1
				if dotIdx > 0 && recExpr[dotIdx-1] == '?' {
					dotIdx--
				}
				mName := "." + recExpr[identStart:identEnd] + "("
				parentExpr := strings.TrimSpace(strings.TrimSuffix(recExpr[:dotIdx], "?"))
				argStr := strings.TrimSpace(recExpr[openP+1 : len(recExpr)-1])
				args := splitTopLevelCommaPainless(argStr)
				switch mName {
				case ".computeIfAbsent(", ".compute(", ".computeIfPresent(", ".merge(", ".get(", ".getOrDefault(":
					if len(args) >= 1 && parentExpr != "" {
						var parentVal any
						var err error
						if (parentExpr == "ctx" || parentExpr == "ctx?") && params["ctx"] == nil {
							parentVal = sourceMap
						} else if strings.Contains(parentExpr, "(") {
							parentVal, _, err = resolveMutableReceiverPainless(sourceMap, parentExpr, params, depth+1)
						} else {
							parentVal, err = evalRHSExprDepth(sourceMap, parentExpr, params, depth+1)
						}
						if err != nil {
							return nil, nil, err
						}
						kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
						if err != nil {
							return nil, nil, err
						}
						if parentMap, isMap := parentVal.(map[string]any); isMap && parentMap != nil && kVal != nil {
							keyStr := fmt.Sprintf("%v", kVal)
							val, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
							if err != nil {
								return nil, nil, err
							}
							writeBack := func(updated any) {
								parentMap[keyStr] = updated
								if parentExpr == "ctx" || parentExpr == "ctx?" || parentExpr == "ctx._source" || parentExpr == "ctx?._source" || parentExpr == "ctx._source?" || parentExpr == "ctx?._source?" {
									syncSourceAliasToLocalVars(sourceMap, params, keyStr)
									return
								}
								for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
									if strings.HasPrefix(parentExpr, pfx) {
										relPath := strings.TrimSuffix(strings.TrimPrefix(parentExpr, pfx), "?")
										syncSourceAliasToLocalVars(sourceMap, params, relPath)
										syncSourceAliasToLocalVars(sourceMap, params, relPath+"."+keyStr)
										return
									}
								}
								cleanPar := strings.TrimSuffix(parentExpr, "?")
								if !strings.Contains(cleanPar, "(") {
									rawPath := normalizeLocalLHSPath(strings.Split(cleanPar, "."), params)
									if len(rawPath) > 0 {
										syncLocalVarAlias(sourceMap, params, decodeBracketSeg(rawPath[0]))
									}
								}
							}
							return val, writeBack, nil
						}
						if parentSlice, isSlice := parentVal.([]any); isSlice && mName == ".get(" {
							if idxF, okF := toFloat64(kVal); okF {
								idx := int(idxF)
								if idx >= 0 && idx < len(parentSlice) {
									val := parentSlice[idx]
									writeBack := func(updated any) {
										parentSlice[idx] = updated
									}
									return val, writeBack, nil
								}
							}
						}
					}
				}
			}
		}
	}
	val, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
	return val, nil, err
}

func evalPainlessMapCompute(mName, recExpr, argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	args := splitTopLevelCommaPainless(argExpr)
	var recVal any
	if (recExpr == "ctx" || recExpr == "ctx?") && params["ctx"] == nil {
		recVal = sourceMap
	} else {
		var err error
		recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
		if err != nil {
			return nil, err
		}
	}
	m, ok := recVal.(map[string]any)
	if !ok || m == nil {
		return nil, nil
	}
	syncMutatedMap := func(mutatedKey string) {
		if recExpr == "ctx" || recExpr == "ctx?" || recExpr == "ctx._source" || recExpr == "ctx?._source" || recExpr == "ctx._source?" || recExpr == "ctx?._source?" {
			if mutatedKey != "" {
				syncSourceAliasToLocalVars(sourceMap, params, mutatedKey)
			}
			return
		}
		for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
			if strings.HasPrefix(recExpr, pfx) {
				relPath := strings.TrimSuffix(strings.TrimPrefix(recExpr, pfx), "?")
				syncSourceAliasToLocalVars(sourceMap, params, relPath)
				if mutatedKey != "" {
					syncSourceAliasToLocalVars(sourceMap, params, relPath+"."+mutatedKey)
				}
				return
			}
		}
		cleanRec := strings.TrimSuffix(recExpr, "?")
		if !strings.Contains(cleanRec, "(") {
			rawPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
			if len(rawPath) > 0 {
				syncLocalVarAlias(sourceMap, params, decodeBracketSeg(rawPath[0]))
			}
		}
	}

	switch mName {
	case ".computeIfAbsent(":
		if len(args) != 2 {
			return nil, nil
		}
		kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		if cur, exists := m[keyStr]; exists && cur != nil {
			return cur, nil
		}
		fnExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(args[1]), 1)
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx <= 0 {
			return nil, nil
		}
		pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
		var pName string
		if len(pNames) > 0 {
			pName = pNames[0]
		}
		prev, hadPrev := params[pName]
		if pName != "" {
			params[pName] = keyStr
		}
		newVal, err := evalPainlessLambdaBody(fnExpr[arrowIdx+2:], sourceMap, params, depth+1)
		if pName != "" {
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
		}
		if err != nil {
			return nil, err
		}
		if newVal != nil {
			m[keyStr] = newVal
			syncMutatedMap(keyStr)
		}
		return newVal, nil

	case ".compute(", ".computeIfPresent(":
		if len(args) != 2 {
			return nil, nil
		}
		kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		cur, exists := m[keyStr]
		if mName == ".computeIfPresent(" && (!exists || cur == nil) {
			return nil, nil
		}
		fnExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(args[1]), 2)
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx <= 0 {
			return cur, nil
		}
		pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
		if len(pNames) < 2 {
			return cur, nil
		}
		prevK, hadK := params[pNames[0]]
		prevV, hadV := params[pNames[1]]
		params[pNames[0]] = keyStr
		params[pNames[1]] = cur
		newVal, err := evalPainlessLambdaBody(fnExpr[arrowIdx+2:], sourceMap, params, depth+1)
		if hadK {
			params[pNames[0]] = prevK
		} else {
			delete(params, pNames[0])
		}
		if hadV {
			params[pNames[1]] = prevV
		} else {
			delete(params, pNames[1])
		}
		if err != nil {
			return nil, err
		}
		if newVal == nil {
			delete(m, keyStr)
		} else {
			m[keyStr] = newVal
		}
		syncMutatedMap(keyStr)
		return newVal, nil

	case ".merge(":
		if len(args) != 3 {
			return nil, nil
		}
		kVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		vVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if err != nil {
			return nil, err
		}
		keyStr := fmt.Sprintf("%v", kVal)
		cur, exists := m[keyStr]
		if !exists || cur == nil {
			if vVal != nil {
				m[keyStr] = vVal
				syncMutatedMap(keyStr)
			}
			return vVal, nil
		}
		fnExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(args[2]), 2)
		arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
		if arrowIdx <= 0 {
			return vVal, nil
		}
		pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
		if len(pNames) < 2 {
			return vVal, nil
		}
		prev1, had1 := params[pNames[0]]
		prev2, had2 := params[pNames[1]]
		params[pNames[0]] = cur
		params[pNames[1]] = vVal
		mergedVal, err := evalPainlessLambdaBody(fnExpr[arrowIdx+2:], sourceMap, params, depth+1)
		if had1 {
			params[pNames[0]] = prev1
		} else {
			delete(params, pNames[0])
		}
		if had2 {
			params[pNames[1]] = prev2
		} else {
			delete(params, pNames[1])
		}
		if err != nil {
			return nil, err
		}
		if mergedVal == nil {
			delete(m, keyStr)
		} else {
			m[keyStr] = mergedVal
		}
		syncMutatedMap(keyStr)
		return mergedVal, nil
	}
	return nil, nil
}

type painlessStreamStep struct {
	name string
	args string
}

func findTopLevelSubstrPainless(s, sub string) int {
	depth := 0
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i <= len(s)-len(sub); i++ {
		if stepQuoteState(s, i, &inQuotes, &inRegexClass) {
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+len(sub)] == sub {
				return i
			}
		}
	}
	return -1
}

func parseStreamChainStepsPainless(chain string) ([]painlessStreamStep, string, bool) {
	var steps []painlessStreamStep
	rem := strings.TrimSpace(chain)
	for strings.HasPrefix(rem, ".") || strings.HasPrefix(rem, "?.") {
		rem = strings.TrimPrefix(rem, "?")
		rem = strings.TrimPrefix(rem, ".")
		rem = strings.TrimSpace(rem)
		openP := strings.IndexByte(rem, '(')
		if openP <= 0 {
			return steps, "." + rem, len(steps) > 0
		}
		name := strings.TrimSpace(rem[:openP])
		for i := 0; i < len(name); i++ {
			if !isIdentByte(name[i]) {
				return nil, "", false
			}
		}
		closeP := findMatchingDelimiter(rem, openP, '(', ')')
		if closeP < 0 {
			return nil, "", false
		}
		argStr := strings.TrimSpace(rem[openP+1 : closeP])
		steps = append(steps, painlessStreamStep{name: name, args: argStr})
		rem = strings.TrimSpace(rem[closeP+1:])
	}
	if rem != "" {
		return steps, rem, len(steps) > 0
	}
	return steps, "", len(steps) > 0
}

func findStreamStartOutsideQuotesPainless(s string) (int, string) {
	bestIdx := -1
	bestSub := ""
	for _, sub := range []string{".stream()", ".lines()", ".chars()", ".codePoints()"} {
		idx := findTopLevelSubstrPainless(s, sub)
		if idx > 0 {
			rest := strings.TrimSpace(s[idx+len(sub):])
			if strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "?.") {
				if bestIdx < 0 || idx < bestIdx {
					bestIdx = idx
					bestSub = sub
				}
			}
		}
	}
	return bestIdx, bestSub
}

func evalStreamPipelinePainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	streamIdx, streamSub := findStreamStartOutsideQuotesPainless(rhs)
	var steps []painlessStreamStep
	var tailRest string
	var srcSlice []any
	if streamIdx > 0 {
		recExpr := strings.TrimSpace(strings.TrimSuffix(rhs[:streamIdx], "?"))
		chainRest := strings.TrimSpace(rhs[streamIdx+len(streamSub):])
		if chainRest == "" {
			return nil, false, nil
		}
		var ok bool
		steps, tailRest, ok = parseStreamChainStepsPainless(chainRest)
		if !ok || len(steps) == 0 {
			return nil, false, nil
		}

		var recVal any
		expRec := strings.TrimSpace(expandDynamicBrackets(recExpr, sourceMap, params, depth+1))
		if streamSub == ".stream()" && (strings.HasPrefix(expRec, "doc.") || strings.HasPrefix(expRec, "doc?.")) &&
			!strings.HasSuffix(expRec, ".value") && !strings.Contains(expRec, ".value.") && !strings.Contains(expRec, ".values.") && !strings.Contains(expRec, "(") {
			docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expRec, "doc?."), "doc."), ".values")
			recVal = resolveDocValuesSlice(sourceMap, docPath)
		} else {
			var err error
			recVal, err = evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
			if err != nil {
				return nil, true, err
			}
		}
		switch streamSub {
		case ".lines()":
			if recVal != nil {
				srcSlice = splitLinesPainless(fmt.Sprintf("%v", recVal))
			}
		case ".chars()", ".codePoints()":
			if recVal != nil {
				runes := []rune(fmt.Sprintf("%v", recVal))
				srcSlice = make([]any, len(runes))
				for i, r := range runes {
					srcSlice[i] = int64(r)
				}
			}
		default:
			if bs, isBS := recVal.(*painlessBitSet); isBS {
				srcSlice = bs.streamSlice()
			} else if s, ok := recVal.([]any); ok {
				srcSlice = s
			} else if !isEmptyOptionalOrNilPainless(recVal) {
				srcSlice = []any{recVal}
			} else {
				srcSlice = []any{}
			}
		}
	} else {
		matchedStaticStream := false
		if duIdx := findTopLevelSubstrPainless(rhs, ".datesUntil("); duIdx > 0 {
			openP := duIdx + len(".datesUntil(") - 1
			closeP := findMatchingDelimiter(rhs, openP, '(', ')')
			if closeP > openP && closeP < len(rhs)-1 {
				chainRest := strings.TrimSpace(rhs[closeP+1:])
				st, tr, ok := parseStreamChainStepsPainless(chainRest)
				if ok && len(st) > 0 && isStreamStepMethodPainless(st[0].name) {
					duVal, duErr := evalRHSExprDepth(sourceMap, rhs[:closeP+1], params, depth+1)
					if duErr != nil {
						return nil, true, duErr
					}
					if s, isSlice := duVal.([]any); isSlice {
						srcSlice = s
					} else {
						srcSlice = []any{}
					}
					steps = st
					tailRest = tr
					matchedStaticStream = true
				}
			}
		}
		for _, pfx := range []string{
			"Arrays.stream(", "Stream.of(", "IntStream.of(", "LongStream.of(", "DoubleStream.of(",
			"Stream.empty(", "IntStream.empty(", "LongStream.empty(", "DoubleStream.empty(",
			"Stream.concat(", "IntStream.concat(", "LongStream.concat(", "DoubleStream.concat(",
			"IntStream.rangeClosed(", "IntStream.range(", "LongStream.rangeClosed(", "LongStream.range(",
			"Stream.iterate(", "IntStream.iterate(", "LongStream.iterate(", "DoubleStream.iterate(",
			"Stream.generate(", "IntStream.generate(", "LongStream.generate(", "DoubleStream.generate(",
		} {
			if strings.HasPrefix(rhs, pfx) {
				openP := len(pfx) - 1
				closeP := findMatchingDelimiter(rhs, openP, '(', ')')
				if closeP > openP && closeP < len(rhs)-1 {
					chainRest := strings.TrimSpace(rhs[closeP+1:])
					var ok bool
					steps, tailRest, ok = parseStreamChainStepsPainless(chainRest)
					if ok && len(steps) > 0 {
						if strings.HasSuffix(pfx, ".iterate(") || strings.HasSuffix(pfx, ".generate(") {
							genSlice, gErr := evalStreamIterateOrGeneratePainless(pfx, rhs[openP+1:closeP], steps, sourceMap, params, depth+1)
							if gErr != nil {
								return nil, true, gErr
							}
							srcSlice = genSlice
							matchedStaticStream = true
						} else {
							initVal, sOk, sErr := evalStaticCallPainless(sourceMap, rhs[:closeP+1], params, depth+1)
							if sErr != nil {
								return nil, true, sErr
							}
							if sOk {
								if s, isSlice := initVal.([]any); isSlice {
									srcSlice = s
								} else {
									srcSlice = []any{}
								}
								matchedStaticStream = true
							}
						}
					}
				}
				break
			}
		}
		if !matchedStaticStream {
			dotIdx := strings.IndexByte(rhs, '.')
			if dotIdx > 0 {
				varIdent := strings.TrimSuffix(strings.TrimSpace(rhs[:dotIdx]), "?")
				if params != nil {
					if vVal, exists := params[varIdent]; exists {
						if vSlice, isSlice := vVal.([]any); isSlice {
							st, tr, ok := parseStreamChainStepsPainless(rhs[dotIdx:])
							if ok && len(st) > 0 && isStreamStepMethodPainless(st[0].name) && (st[0].name != "peek" || strings.TrimSpace(st[0].args) != "") {
								steps = st
								tailRest = tr
								srcSlice = vSlice
								matchedStaticStream = true
							}
						}
					}
				}
			}
		}
		if !matchedStaticStream {
			return nil, false, nil
		}
	}
	items := make([]any, len(srcSlice))
	copy(items, srcSlice)

	var terminalVal any
	hasTerminal := false
	isOptional := false

	for idx, step := range steps {
		if hasTerminal {
			if isOptional {
				switch step.name {
				case "map", "flatMap":
					if isEmptyOptionalOrNilPainless(terminalVal) {
						continue
					}
					normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
					if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
						if len(pNames) > 0 {
							pName := pNames[0]
							prev, hadPrev := params[pName]
							params[pName] = terminalVal
							mv, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							if err != nil {
								return nil, true, err
							}
							terminalVal = mv
						}
					}
					continue
				case "filter":
					if isEmptyOptionalOrNilPainless(terminalVal) {
						continue
					}
					normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
					if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
						pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
						if len(pNames) > 0 {
							pName := pNames[0]
							prev, hadPrev := params[pName]
							params[pName] = terminalVal
							matched, err := evalPainlessPredicateLambda(normArg[arrowIdx+2:], sourceMap, params, depth+1)
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							if err != nil {
								return nil, true, err
							}
							if !matched {
								terminalVal = painlessEmptyOptional
							}
						}
					}
					continue
				case "ifPresent":
					if !isEmptyOptionalOrNilPainless(terminalVal) {
						normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
						if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
							pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
							if len(pNames) > 0 {
								pName := pNames[0]
								prev, hadPrev := params[pName]
								params[pName] = terminalVal
								_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
								if hadPrev {
									params[pName] = prev
								} else {
									delete(params, pName)
								}
								if err != nil {
									return nil, true, err
								}
							}
						}
					}
					terminalVal = nil
					isOptional = false
					continue
				case "ifPresentOrElse":
					ieArgs := splitTopLevelCommaPainless(step.args)
					if !isEmptyOptionalOrNilPainless(terminalVal) {
						if len(ieArgs) >= 1 {
							normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(ieArgs[0]), 1)
							if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
								pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
								if len(pNames) > 0 {
									pName := pNames[0]
									prev, hadPrev := params[pName]
									params[pName] = terminalVal
									_, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
									if hadPrev {
										params[pName] = prev
									} else {
										delete(params, pName)
									}
									if err != nil {
										return nil, true, err
									}
								}
							}
						}
					} else if len(ieArgs) >= 2 {
						normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(ieArgs[1]), 0)
						if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
							if _, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1); err != nil {
								return nil, true, err
							}
						}
					}
					terminalVal = nil
					isOptional = false
					continue
				case "or":
					if isEmptyOptionalOrNilPainless(terminalVal) {
						normArg := normalizeMethodReferenceToLambdaPainless(step.args, 0)
						if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
							defVal, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
							if err != nil {
								return nil, true, err
							}
							terminalVal = defVal
						}
					}
					continue
				case "stream":
					if isEmptyOptionalOrNilPainless(terminalVal) {
						items = []any{}
					} else {
						items = []any{terminalVal}
					}
					hasTerminal = false
					isOptional = false
					continue
				case "orElseThrow":
					if isEmptyOptionalOrNilPainless(terminalVal) {
						if strings.TrimSpace(step.args) != "" {
							_, err := evalOptionalOrElseThrowSupplierPainless(step.args, sourceMap, params, depth+1)
							return nil, true, err
						}
						return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
					}
					isOptional = false
					continue
				case "orElse":
					if !isEmptyOptionalOrNilPainless(terminalVal) {
						isOptional = false
						continue
					}
					defVal, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1)
					if err != nil {
						return nil, true, err
					}
					terminalVal = defVal
					isOptional = false
					continue
				case "orElseGet":
					if !isEmptyOptionalOrNilPainless(terminalVal) {
						isOptional = false
						continue
					}
					normArg := normalizeMethodReferenceToLambdaPainless(step.args, 0)
					if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
						defVal, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
						if err != nil {
							return nil, true, err
						}
						terminalVal = defVal
					}
					isOptional = false
					continue
				case "get", "getAsInt", "getAsLong", "getAsDouble":
					if isEmptyOptionalOrNilPainless(terminalVal) {
						return nil, true, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
					}
					isOptional = false
					continue
				case "isPresent":
					terminalVal = !isEmptyOptionalOrNilPainless(terminalVal)
					isOptional = false
					continue
				case "isEmpty":
					terminalVal = isEmptyOptionalOrNilPainless(terminalVal)
					isOptional = false
					continue
				}
			}
			// Delegate remaining chained method calls on `terminalVal` via a temporary param
			var sb strings.Builder
			sb.WriteString("__stream_res")
			for _, remStep := range steps[idx:] {
				sb.WriteByte('.')
				sb.WriteString(remStep.name)
				sb.WriteByte('(')
				sb.WriteString(remStep.args)
				sb.WriteByte(')')
			}
			sb.WriteString(tailRest)
			prevTmp, hadTmp := params["__stream_res"]
			params["__stream_res"] = terminalVal
			res, err := evalRHSExprDepth(sourceMap, sb.String(), params, depth+1)
			if hadTmp {
				params["__stream_res"] = prevTmp
			} else {
				delete(params, "__stream_res")
			}
			return res, true, err
		}

		switch step.name {
		case "filter", "takeWhile", "dropWhile":
			normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
			arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					rawBody := strings.TrimSpace(normArg[arrowIdx+2:])
					budget := getOrInitEvalBudget(params)
					prev, hadPrev := params[pName]
					filtered := make([]any, 0, len(items))
					dropping := step.name == "dropWhile"
				filterLoop:
					for _, it := range items {
						if err := budget.step(); err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						if step.name == "dropWhile" && !dropping {
							filtered = append(filtered, it)
							continue
						}
						params[pName] = it
						matched, err := evalPainlessPredicateLambda(rawBody, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						switch step.name {
						case "filter":
							if matched {
								filtered = append(filtered, it)
							}
						case "takeWhile":
							if !matched {
								break filterLoop
							}
							filtered = append(filtered, it)
						case "dropWhile":
							if !matched {
								dropping = false
								filtered = append(filtered, it)
							}
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					items = filtered
				}
			}
		case "map", "mapToObj", "mapToInt", "mapToLong", "mapToDouble":
			normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
			arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := normArg[arrowIdx+2:]
					prev, hadPrev := params[pName]
					mapped := make([]any, 0, len(items))
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						switch step.name {
						case "mapToInt", "mapToLong":
							if f, ok := toFloat64(mv); ok {
								mv = int64(f)
							}
						case "mapToDouble":
							if f, ok := toFloat64(mv); ok {
								mv = f
							}
						}
						mapped = append(mapped, mv)
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					items = mapped
				}
			}
		case "flatMap", "flatMapToInt", "flatMapToLong", "flatMapToDouble":
			normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
			arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := strings.TrimSpace(normArg[arrowIdx+2:])
					body = strings.TrimSuffix(body, ".stream()")
					prev, hadPrev := params[pName]
					var flattened []any
					coerceElem := func(el any) any {
						switch step.name {
						case "flatMapToInt", "flatMapToLong":
							if f, ok := toFloat64(el); ok {
								return int64(f)
							}
						case "flatMapToDouble":
							if f, ok := toFloat64(el); ok {
								return f
							}
						}
						return el
					}
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
						if subArr, ok := mv.([]any); ok {
							for _, el := range subArr {
								if len(flattened) >= MaxPainlessSliceItems {
									break
								}
								flattened = append(flattened, coerceElem(el))
							}
						} else if mv != nil && len(flattened) < MaxPainlessSliceItems {
							flattened = append(flattened, coerceElem(mv))
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					items = flattened
				}
			}
		case "distinct":
			dedup := make([]any, 0, len(items))
			for _, it := range items {
				seen := false
				for _, ex := range dedup {
					if painlessValuesEqual(it, ex) {
						seen = true
						break
					}
				}
				if !seen {
					dedup = append(dedup, it)
				}
			}
			items = dedup
		case "sorted":
			if err := sortPainlessSliceInPlace(items, step.args, sourceMap, params, depth+1); err != nil {
				return nil, true, err
			}
		case "limit":
			if lv, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1); err == nil {
				if f, ok := toFloat64(lv); ok {
					lim := int(f)
					if lim < 0 {
						lim = 0
					}
					if lim < len(items) {
						items = items[:lim]
					}
				}
			}
		case "skip":
			if sv, err := evalRHSExprDepth(sourceMap, step.args, params, depth+1); err == nil {
				if f, ok := toFloat64(sv); ok {
					sk := int(f)
					if sk < 0 {
						sk = 0
					}
					if sk >= len(items) {
						items = []any{}
					} else {
						items = items[sk:]
					}
				}
			}
		case "boxed", "asDoubleStream", "asLongStream", "stream":
			// No-op intermediate stream conversion
		case "peek":
			normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
			if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					body := normArg[arrowIdx+2:]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						if _, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1); err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, true, err
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
		case "collect":
			hasTerminal = true
			cVal, cErr := evalStreamCollectorPainless(step.args, items, sourceMap, params, depth+1)
			if cErr != nil {
				return nil, true, cErr
			}
			if isOptionalCollectorExprPainless(step.args) {
				isOptional = true
			}
			terminalVal = cVal
		case "summaryStatistics":
			hasTerminal = true
			stats, sErr := computeSummaryStatsPainless(items, "", false, sourceMap, params, depth+1)
			if sErr != nil {
				return nil, true, sErr
			}
			terminalVal = stats
		case "toList", "toArray":
			hasTerminal = true
			terminalVal = items
		case "count":
			hasTerminal = true
			terminalVal = int64(len(items))
		case "sum":
			hasTerminal = true
			sum := 0.0
			allInt := true
			for _, it := range items {
				if f, ok := toFloat64(it); ok {
					sum += f
					if f != float64(int64(f)) {
						allInt = false
					}
				}
			}
			if allInt {
				terminalVal = int64(sum)
			} else {
				terminalVal = sum
			}
		case "average":
			hasTerminal = true
			isOptional = true
			if len(items) == 0 {
				terminalVal = nil
			} else {
				sum := 0.0
				for _, it := range items {
					if f, ok := toFloat64(it); ok {
						sum += f
					}
				}
				terminalVal = sum / float64(len(items))
			}
		case "min", "max":
			hasTerminal = true
			isOptional = true
			if len(items) == 0 {
				terminalVal = nil
			} else {
				cp := make([]any, len(items))
				copy(cp, items)
				if err := sortPainlessSliceInPlace(cp, step.args, sourceMap, params, depth+1); err != nil {
					return nil, true, err
				}
				if step.name == "min" {
					terminalVal = cp[0]
				} else {
					terminalVal = cp[len(cp)-1]
				}
			}
		case "findFirst", "findAny":
			hasTerminal = true
			isOptional = true
			if len(items) > 0 {
				terminalVal = items[0]
			} else {
				terminalVal = nil
			}
		case "anyMatch", "allMatch", "noneMatch":
			hasTerminal = true
			normArg := normalizeMethodReferenceToLambdaPainless(step.args, 1)
			arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
			if arrowIdx <= 0 {
				terminalVal = step.name != "anyMatch"
				continue
			}
			pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
			if len(pNames) == 0 {
				terminalVal = step.name != "anyMatch"
				continue
			}
			pName := pNames[0]
			rawBody := strings.TrimSpace(normArg[arrowIdx+2:])
			budget := getOrInitEvalBudget(params)
			prev, hadPrev := params[pName]
			resBool := step.name != "anyMatch"
			for _, it := range items {
				if err := budget.step(); err != nil {
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					return nil, true, err
				}
				params[pName] = it
				matched, err := evalPainlessPredicateLambda(rawBody, sourceMap, params, depth+1)
				if err != nil {
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					return nil, true, err
				}
				if step.name == "anyMatch" && matched {
					resBool = true
					break
				}
				if step.name == "allMatch" && !matched {
					resBool = false
					break
				}
				if step.name == "noneMatch" && matched {
					resBool = false
					break
				}
			}
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
			terminalVal = resBool
		case "reduce":
			hasTerminal = true
			rArgs := splitTopLevelCommaPainless(step.args)
			var acc any
			hasAcc := false
			fnExpr := step.args
			if len(rArgs) >= 2 {
				initVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(rArgs[0]), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				acc = initVal
				hasAcc = true
				fnExpr = strings.TrimSpace(rArgs[1])
			} else {
				isOptional = true
			}
			fnExpr = normalizeMethodReferenceToLambdaPainless(fnExpr, 2)
			arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
			if arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(fnExpr[:arrowIdx])
				if len(pNames) >= 2 {
					p1, p2 := pNames[0], pNames[1]
					body := fnExpr[arrowIdx+2:]
					prev1, had1 := params[p1]
					prev2, had2 := params[p2]
					for _, it := range items {
						if !hasAcc {
							acc = it
							hasAcc = true
							continue
						}
						params[p1] = acc
						params[p2] = it
						nextAcc, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
						if err != nil {
							if had1 {
								params[p1] = prev1
							} else {
								delete(params, p1)
							}
							if had2 {
								params[p2] = prev2
							} else {
								delete(params, p2)
							}
							return nil, true, err
						}
						acc = nextAcc
					}
					if had1 {
						params[p1] = prev1
					} else {
						delete(params, p1)
					}
					if had2 {
						params[p2] = prev2
					} else {
						delete(params, p2)
					}
				}
			}
			terminalVal = acc
		case "forEach":
			hasTerminal = true
			prevTmp, hadTmp := params["__stream_items"]
			params["__stream_items"] = items
			err := execPainlessForEach("__stream_items", step.args, sourceMap, params, depth+1)
			if hadTmp {
				params["__stream_items"] = prevTmp
			} else {
				delete(params, "__stream_items")
			}
			if err != nil {
				return nil, true, err
			}
			terminalVal = nil
		}
	}

	if !hasTerminal {
		terminalVal = items
	} else if isOptional && isEmptyOptionalOrNilPainless(terminalVal) {
		terminalVal = painlessEmptyOptional
	}
	if tailRest != "" {
		prevTmp, hadTmp := params["__stream_res"]
		params["__stream_res"] = terminalVal
		res, err := evalRHSExprDepth(sourceMap, "__stream_res"+tailRest, params, depth+1)
		if hadTmp {
			params["__stream_res"] = prevTmp
		} else {
			delete(params, "__stream_res")
		}
		return res, true, err
	}
	return terminalVal, true, nil
}

func evalStreamCollectorPainless(collectorExpr string, items []any, sourceMap, params map[string]any, depth int) (any, error) {
	cExpr := strings.TrimSpace(collectorExpr)
	if strings.HasPrefix(cExpr, "Collectors.joining(") && strings.HasSuffix(cExpr, ")") {
		joinArgStr := strings.TrimSpace(cExpr[len("Collectors.joining(") : len(cExpr)-1])
		joinArgs := splitTopLevelCommaPainless(joinArgStr)
		delim, prefix, suffix := "", "", ""
		if len(joinArgs) >= 1 {
			if dv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(joinArgs[0]), params, depth+1); err == nil && dv != nil {
				delim = fmt.Sprintf("%v", dv)
			}
		}
		if len(joinArgs) >= 3 {
			if pv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(joinArgs[1]), params, depth+1); err == nil && pv != nil {
				prefix = fmt.Sprintf("%v", pv)
			}
			if sv, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(joinArgs[2]), params, depth+1); err == nil && sv != nil {
				suffix = fmt.Sprintf("%v", sv)
			}
		}
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = fmt.Sprintf("%v", it)
		}
		return prefix + strings.Join(parts, delim) + suffix, nil
	}
	if cExpr == "Collectors.toSet()" {
		dedup := make([]any, 0, len(items))
		for _, it := range items {
			seen := false
			for _, ex := range dedup {
				if painlessValuesEqual(it, ex) {
					seen = true
					break
				}
			}
			if !seen {
				dedup = append(dedup, it)
			}
		}
		return dedup, nil
	}
	if cExpr == "Collectors.counting()" {
		return int64(len(items)), nil
	}
	for _, sumPfx := range []string{"Collectors.summingInt(", "Collectors.summingLong(", "Collectors.summingDouble(", "Collectors.averagingInt(", "Collectors.averagingLong(", "Collectors.averagingDouble("} {
		if strings.HasPrefix(cExpr, sumPfx) && strings.HasSuffix(cExpr, ")") {
			fnExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(cExpr[len(sumPfx):len(cExpr)-1]), 1)
			arrowIdx := findNextUnquotedSubstr(fnExpr, "->", 0)
			sum := 0.0
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
						if f, ok := toFloat64(mv); ok {
							sum += f
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
			if strings.HasPrefix(sumPfx, "Collectors.averaging") {
				if len(items) == 0 {
					return float64(0), nil
				}
				return sum / float64(len(items)), nil
			}
			if sumPfx == "Collectors.summingDouble(" {
				return sum, nil
			}
			return int64(sum), nil
		}
	}
	if (strings.HasPrefix(cExpr, "Collectors.toMap(") || strings.HasPrefix(cExpr, "Collectors.toUnmodifiableMap(")) && strings.HasSuffix(cExpr, ")") {
		isUnmod := strings.HasPrefix(cExpr, "Collectors.toUnmodifiableMap(")
		pfxLen := len("Collectors.toMap(")
		if isUnmod {
			pfxLen = len("Collectors.toUnmodifiableMap(")
		}
		mapArgStr := strings.TrimSpace(cExpr[pfxLen : len(cExpr)-1])
		mapArgs := splitTopLevelCommaPainless(mapArgStr)
		resMap := make(map[string]any, len(items))
		if len(mapArgs) >= 2 {
			kFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(mapArgs[0]), 1)
			vFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(mapArgs[1]), 1)
			kArrow := findNextUnquotedSubstr(kFn, "->", 0)
			vArrow := findNextUnquotedSubstr(vFn, "->", 0)
			if kArrow > 0 && vArrow > 0 {
				kp := parsePainlessLambdaHeader(kFn[:kArrow])
				vp := parsePainlessLambdaHeader(vFn[:vArrow])
				if len(kp) > 0 && len(vp) > 0 {
					for _, it := range items {
						prevK, hadK := params[kp[0]]
						params[kp[0]] = it
						kVal, err := evalPainlessLambdaBody(kFn[kArrow+2:], sourceMap, params, depth+1)
						if hadK {
							params[kp[0]] = prevK
						} else {
							delete(params, kp[0])
						}
						if err != nil {
							return nil, err
						}
						prevV, hadV := params[vp[0]]
						params[vp[0]] = it
						vVal, err := evalPainlessLambdaBody(vFn[vArrow+2:], sourceMap, params, depth+1)
						if hadV {
							params[vp[0]] = prevV
						} else {
							delete(params, vp[0])
						}
						if err != nil {
							return nil, err
						}
						kStr := fmt.Sprintf("%v", kVal)
						if prevEntry, exists := resMap[kStr]; exists {
							if len(mapArgs) < 3 {
								return nil, &painlessExceptionError{
									exType:  "IllegalStateException",
									message: fmt.Sprintf("Duplicate key %s (attempted merging values %v and %v)", kStr, prevEntry, vVal),
								}
							}
							mFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(mapArgs[2]), 2)
							if mArrow := findNextUnquotedSubstr(mFn, "->", 0); mArrow > 0 {
								mp := parsePainlessLambdaHeader(mFn[:mArrow])
								if len(mp) >= 2 {
									prev1, had1 := params[mp[0]]
									prev2, had2 := params[mp[1]]
									params[mp[0]] = prevEntry
									params[mp[1]] = vVal
									merged, mErr := evalPainlessLambdaBody(mFn[mArrow+2:], sourceMap, params, depth+1)
									if had1 {
										params[mp[0]] = prev1
									} else {
										delete(params, mp[0])
									}
									if had2 {
										params[mp[1]] = prev2
									} else {
										delete(params, mp[1])
									}
									if mErr != nil {
										return nil, mErr
									}
									vVal = merged
								}
							}
						}
						resMap[kStr] = vVal
					}
				}
			}
		}
		return resMap, nil
	}
	if strings.HasPrefix(cExpr, "Collectors.groupingBy(") && strings.HasSuffix(cExpr, ")") {
		grpArgStr := strings.TrimSpace(cExpr[len("Collectors.groupingBy(") : len(cExpr)-1])
		grpArgs := splitTopLevelCommaPainless(grpArgStr)
		groups := make(map[string][]any)
		var keyOrder []string
		if len(grpArgs) >= 1 {
			cFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(grpArgs[0]), 1)
			if cArrow := findNextUnquotedSubstr(cFn, "->", 0); cArrow > 0 {
				cp := parsePainlessLambdaHeader(cFn[:cArrow])
				if len(cp) > 0 {
					pName := cp[0]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						kVal, err := evalPainlessLambdaBody(cFn[cArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						kStr := fmt.Sprintf("%v", kVal)
						if _, exists := groups[kStr]; !exists {
							keyOrder = append(keyOrder, kStr)
						}
						groups[kStr] = append(groups[kStr], it)
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
		}
		resMap := make(map[string]any, len(groups))
		downstream := "Collectors.toList()"
		if len(grpArgs) >= 2 {
			downstream = strings.TrimSpace(grpArgs[1])
		}
		for _, kStr := range keyOrder {
			dsVal, err := evalStreamCollectorPainless(downstream, groups[kStr], sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			resMap[kStr] = dsVal
		}
		return resMap, nil
	}
	if strings.HasPrefix(cExpr, "Collectors.partitioningBy(") && strings.HasSuffix(cExpr, ")") {
		partArgStr := strings.TrimSpace(cExpr[len("Collectors.partitioningBy(") : len(cExpr)-1])
		partArgs := splitTopLevelCommaPainless(partArgStr)
		trueSlice := []any{}
		falseSlice := []any{}
		if len(partArgs) >= 1 {
			pFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(partArgs[0]), 1)
			if pArrow := findNextUnquotedSubstr(pFn, "->", 0); pArrow > 0 {
				pp := parsePainlessLambdaHeader(pFn[:pArrow])
				if len(pp) > 0 {
					pName := pp[0]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						matched, err := evalPainlessPredicateLambda(pFn[pArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						if matched {
							trueSlice = append(trueSlice, it)
						} else {
							falseSlice = append(falseSlice, it)
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
		}
		if len(partArgs) >= 2 {
			ds := strings.TrimSpace(partArgs[1])
			tv, err := evalStreamCollectorPainless(ds, trueSlice, sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			fv, err := evalStreamCollectorPainless(ds, falseSlice, sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			return map[string]any{"true": tv, "false": fv}, nil
		}
		return map[string]any{"true": trueSlice, "false": falseSlice}, nil
	}
	for _, statPfx := range []string{"Collectors.summarizingInt(", "Collectors.summarizingLong(", "Collectors.summarizingDouble("} {
		if strings.HasPrefix(cExpr, statPfx) && strings.HasSuffix(cExpr, ")") {
			fnExpr := strings.TrimSpace(cExpr[len(statPfx) : len(cExpr)-1])
			return computeSummaryStatsPainless(items, fnExpr, statPfx == "Collectors.summarizingDouble(", sourceMap, params, depth+1)
		}
	}
	if strings.HasPrefix(cExpr, "Collectors.collectingAndThen(") && strings.HasSuffix(cExpr, ")") {
		catArgStr := strings.TrimSpace(cExpr[len("Collectors.collectingAndThen(") : len(cExpr)-1])
		catArgs := splitTopLevelCommaPainless(catArgStr)
		if len(catArgs) >= 2 {
			dsVal, err := evalStreamCollectorPainless(strings.TrimSpace(catArgs[0]), items, sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			finExpr := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(catArgs[1]), 1)
			if arrowIdx := findNextUnquotedSubstr(finExpr, "->", 0); arrowIdx > 0 {
				pNames := parsePainlessLambdaHeader(finExpr[:arrowIdx])
				if len(pNames) > 0 {
					pName := pNames[0]
					prev, hadPrev := params[pName]
					params[pName] = dsVal
					res, err := evalPainlessLambdaBody(finExpr[arrowIdx+2:], sourceMap, params, depth+1)
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					return res, err
				}
			}
			return dsVal, nil
		}
	}
	if strings.HasPrefix(cExpr, "Collectors.reducing(") && strings.HasSuffix(cExpr, ")") {
		redArgStr := strings.TrimSpace(cExpr[len("Collectors.reducing(") : len(cExpr)-1])
		redArgs := splitTopLevelCommaPainless(redArgStr)
		var acc any
		hasAcc := false
		var mapExpr, opExpr string
		switch len(redArgs) {
		case 1:
			opExpr = strings.TrimSpace(redArgs[0])
		case 2:
			initVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(redArgs[0]), params, depth+1)
			if err != nil {
				return nil, err
			}
			acc = initVal
			hasAcc = true
			opExpr = strings.TrimSpace(redArgs[1])
		default:
			if len(redArgs) >= 3 {
				initVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(redArgs[0]), params, depth+1)
				if err != nil {
					return nil, err
				}
				acc = initVal
				hasAcc = true
				mapExpr = strings.TrimSpace(redArgs[1])
				opExpr = strings.TrimSpace(redArgs[2])
			}
		}
		workItems := items
		if mapExpr != "" {
			mapExpr = normalizeMethodReferenceToLambdaPainless(mapExpr, 1)
			if mArrow := findNextUnquotedSubstr(mapExpr, "->", 0); mArrow > 0 {
				mp := parsePainlessLambdaHeader(mapExpr[:mArrow])
				if len(mp) > 0 {
					pName := mp[0]
					prev, hadPrev := params[pName]
					mapped := make([]any, 0, len(items))
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(mapExpr[mArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						mapped = append(mapped, mv)
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
					workItems = mapped
				}
			}
		}
		opExpr = normalizeMethodReferenceToLambdaPainless(opExpr, 2)
		if oArrow := findNextUnquotedSubstr(opExpr, "->", 0); oArrow > 0 {
			opNames := parsePainlessLambdaHeader(opExpr[:oArrow])
			if len(opNames) >= 2 {
				p1, p2 := opNames[0], opNames[1]
				body := opExpr[oArrow+2:]
				prev1, had1 := params[p1]
				prev2, had2 := params[p2]
				for _, it := range workItems {
					if !hasAcc {
						acc = it
						hasAcc = true
						continue
					}
					params[p1] = acc
					params[p2] = it
					nextAcc, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
					if err != nil {
						if had1 {
							params[p1] = prev1
						} else {
							delete(params, p1)
						}
						if had2 {
							params[p2] = prev2
						} else {
							delete(params, p2)
						}
						return nil, err
					}
					acc = nextAcc
				}
				if had1 {
					params[p1] = prev1
				} else {
					delete(params, p1)
				}
				if had2 {
					params[p2] = prev2
				} else {
					delete(params, p2)
				}
			}
		}
		return acc, nil
	}
	if strings.HasPrefix(cExpr, "Collectors.mapping(") && strings.HasSuffix(cExpr, ")") {
		mapArgStr := strings.TrimSpace(cExpr[len("Collectors.mapping(") : len(cExpr)-1])
		mapArgs := splitTopLevelCommaPainless(mapArgStr)
		if len(mapArgs) >= 2 {
			mFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(mapArgs[0]), 1)
			ds := strings.TrimSpace(mapArgs[1])
			mapped := make([]any, 0, len(items))
			if mArrow := findNextUnquotedSubstr(mFn, "->", 0); mArrow > 0 {
				mp := parsePainlessLambdaHeader(mFn[:mArrow])
				if len(mp) > 0 {
					pName := mp[0]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						mv, err := evalPainlessLambdaBody(mFn[mArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						mapped = append(mapped, mv)
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
			return evalStreamCollectorPainless(ds, mapped, sourceMap, params, depth+1)
		}
	}
	if strings.HasPrefix(cExpr, "Collectors.filtering(") && strings.HasSuffix(cExpr, ")") {
		fArgStr := strings.TrimSpace(cExpr[len("Collectors.filtering(") : len(cExpr)-1])
		fArgs := splitTopLevelCommaPainless(fArgStr)
		if len(fArgs) >= 2 {
			pFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(fArgs[0]), 1)
			ds := strings.TrimSpace(fArgs[1])
			filtered := make([]any, 0, len(items))
			if pArrow := findNextUnquotedSubstr(pFn, "->", 0); pArrow > 0 {
				pp := parsePainlessLambdaHeader(pFn[:pArrow])
				if len(pp) > 0 {
					pName := pp[0]
					prev, hadPrev := params[pName]
					for _, it := range items {
						params[pName] = it
						matched, err := evalPainlessPredicateLambda(pFn[pArrow+2:], sourceMap, params, depth+1)
						if err != nil {
							if hadPrev {
								params[pName] = prev
							} else {
								delete(params, pName)
							}
							return nil, err
						}
						if matched {
							filtered = append(filtered, it)
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
			return evalStreamCollectorPainless(ds, filtered, sourceMap, params, depth+1)
		}
	}
	if strings.HasPrefix(cExpr, "Collectors.flatMapping(") && strings.HasSuffix(cExpr, ")") {
		fmArgStr := strings.TrimSpace(cExpr[len("Collectors.flatMapping(") : len(cExpr)-1])
		fmArgs := splitTopLevelCommaPainless(fmArgStr)
		if len(fmArgs) >= 2 {
			mFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(fmArgs[0]), 1)
			ds := strings.TrimSpace(fmArgs[1])
			var flattened []any
			if mArrow := findNextUnquotedSubstr(mFn, "->", 0); mArrow > 0 {
				mp := parsePainlessLambdaHeader(mFn[:mArrow])
				if len(mp) > 0 {
					pName := mp[0]
					body := strings.TrimSpace(mFn[mArrow+2:])
					body = strings.TrimSuffix(body, ".stream()")
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
						if subArr, ok := mv.([]any); ok {
							for _, el := range subArr {
								if len(flattened) >= MaxPainlessSliceItems {
									break
								}
								flattened = append(flattened, el)
							}
						} else if mv != nil && len(flattened) < MaxPainlessSliceItems {
							flattened = append(flattened, mv)
						}
					}
					if hadPrev {
						params[pName] = prev
					} else {
						delete(params, pName)
					}
				}
			}
			return evalStreamCollectorPainless(ds, flattened, sourceMap, params, depth+1)
		}
	}
	if strings.HasPrefix(cExpr, "Collectors.teeing(") && strings.HasSuffix(cExpr, ")") {
		tArgStr := strings.TrimSpace(cExpr[len("Collectors.teeing(") : len(cExpr)-1])
		tArgs := splitTopLevelCommaPainless(tArgStr)
		if len(tArgs) >= 3 {
			r1, err1 := evalStreamCollectorPainless(strings.TrimSpace(tArgs[0]), items, sourceMap, params, depth+1)
			if err1 != nil {
				return nil, err1
			}
			r2, err2 := evalStreamCollectorPainless(strings.TrimSpace(tArgs[1]), items, sourceMap, params, depth+1)
			if err2 != nil {
				return nil, err2
			}
			mFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(tArgs[2]), 2)
			if mArrow := findNextUnquotedSubstr(mFn, "->", 0); mArrow > 0 {
				mp := parsePainlessLambdaHeader(mFn[:mArrow])
				if len(mp) >= 2 {
					prev1, had1 := params[mp[0]]
					prev2, had2 := params[mp[1]]
					params[mp[0]] = r1
					params[mp[1]] = r2
					merged, err := evalPainlessLambdaBody(mFn[mArrow+2:], sourceMap, params, depth+1)
					if had1 {
						params[mp[0]] = prev1
					} else {
						delete(params, mp[0])
					}
					if had2 {
						params[mp[1]] = prev2
					} else {
						delete(params, mp[1])
					}
					return merged, err
				}
			}
		}
	}
	for _, mmPfx := range []string{"Collectors.minBy(", "Collectors.maxBy("} {
		if strings.HasPrefix(cExpr, mmPfx) && strings.HasSuffix(cExpr, ")") {
			if len(items) == 0 {
				return nil, nil
			}
			cmpArg := strings.TrimSpace(cExpr[len(mmPfx) : len(cExpr)-1])
			cp := make([]any, len(items))
			copy(cp, items)
			if err := sortPainlessSliceInPlace(cp, cmpArg, sourceMap, params, depth+1); err != nil {
				return nil, err
			}
			if mmPfx == "Collectors.minBy(" {
				return cp[0], nil
			}
			return cp[len(cp)-1], nil
		}
	}
	if strings.Contains(cExpr, "toSet") {
		return evalStreamCollectorPainless("Collectors.toSet()", items, sourceMap, params, depth)
	}
	return items, nil
}

func isOptionalCollectorExprPainless(collectorExpr string) bool {
	cExpr := strings.TrimSpace(collectorExpr)
	if strings.HasPrefix(cExpr, "Collectors.minBy(") || strings.HasPrefix(cExpr, "Collectors.maxBy(") {
		return true
	}
	if strings.HasPrefix(cExpr, "Collectors.reducing(") && strings.HasSuffix(cExpr, ")") {
		redArgStr := strings.TrimSpace(cExpr[len("Collectors.reducing(") : len(cExpr)-1])
		return len(splitTopLevelCommaPainless(redArgStr)) == 1
	}
	return false
}

func isStreamStepMethodPainless(name string) bool {
	switch name {
	case "filter", "takeWhile", "dropWhile", "map", "mapToObj", "mapToInt", "mapToLong", "mapToDouble",
		"flatMap", "flatMapToInt", "flatMapToLong", "flatMapToDouble",
		"distinct", "sorted", "limit", "skip", "peek", "boxed", "asDoubleStream", "asLongStream",
		"collect", "toList", "count", "sum", "average", "min", "max", "findFirst", "findAny",
		"anyMatch", "allMatch", "noneMatch", "reduce", "summaryStatistics":
		return true
	}
	return false
}

func computeSummaryStatsPainless(items []any, fnExpr string, forceDouble bool, sourceMap, params map[string]any, depth int) (map[string]any, error) {
	allInt := !forceDouble
	var vals []float64
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
					if f, ok := toFloat64(mv); ok {
						vals = append(vals, f)
					}
				}
				if hadPrev {
					params[pName] = prev
				} else {
					delete(params, pName)
				}
			}
		}
	} else {
		for _, it := range items {
			if f, ok := toFloat64(it); ok {
				vals = append(vals, f)
			}
		}
	}
	var count int64
	var sum, minVal, maxVal float64
	for i, f := range vals {
		count++
		sum += f
		if f != float64(int64(f)) {
			allInt = false
		}
		if i == 0 || f < minVal {
			minVal = f
		}
		if i == 0 || f > maxVal {
			maxVal = f
		}
	}
	avg := 0.0
	if count > 0 {
		avg = sum / float64(count)
	}
	if allInt {
		if count == 0 {
			return map[string]any{
				"count":   int64(0),
				"sum":     int64(0),
				"min":     int64(math.MaxInt32),
				"max":     int64(math.MinInt32),
				"average": float64(0),
			}, nil
		}
		return map[string]any{
			"count":   count,
			"sum":     int64(sum),
			"min":     int64(minVal),
			"max":     int64(maxVal),
			"average": avg,
		}, nil
	}
	if count == 0 {
		return map[string]any{
			"count":   int64(0),
			"sum":     float64(0),
			"min":     math.Inf(1),
			"max":     math.Inf(-1),
			"average": float64(0),
		}, nil
	}
	return map[string]any{
		"count":   count,
		"sum":     sum,
		"min":     minVal,
		"max":     maxVal,
		"average": avg,
	}, nil
}

func splitLinesPainless(s string) []any {
	if s == "" {
		return []any{}
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSuffix(s, "\n")
	parts := strings.Split(s, "\n")
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out
}

func resolveStringSearchNeedlePainless(subVal any) (string, bool) {
	if subVal == nil {
		return "", false
	}
	switch tv := subVal.(type) {
	case int:
		if tv < 0 || tv > 0x10FFFF {
			return "", false
		}
		return string(rune(tv)), true // #nosec G115 -- bounds checked in 0..0x10FFFF
	case int64:
		if tv < 0 || tv > 0x10FFFF {
			return "", false
		}
		return string(rune(tv)), true // #nosec G115 -- bounds checked in 0..0x10FFFF
	case float64:
		if tv == float64(int64(tv)) {
			cp := int64(tv)
			if cp < 0 || cp > 0x10FFFF {
				return "", false
			}
			return string(rune(cp)), true // #nosec G115 -- bounds checked in 0..0x10FFFF
		}
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			if iv < 0 || iv > 0x10FFFF {
				return "", false
			}
			return string(rune(iv)), true // #nosec G115 -- bounds checked in 0..0x10FFFF
		}
	}
	return fmt.Sprintf("%v", subVal), true
}

func toBytesPainless(v any) []byte {
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case []byte:
		return tv
	case string:
		return []byte(tv)
	case []any:
		out := make([]byte, len(tv))
		for i, item := range tv {
			if f, ok := toFloat64(item); ok {
				out[i] = byte(int64(f)) // #nosec G115 -- intentional Java byte array element truncation
			} else if s, ok := item.(string); ok && len(s) > 0 {
				out[i] = s[0]
			}
		}
		return out
	default:
		return []byte(fmt.Sprintf("%v", v))
	}
}

func syncMutatedListExprPainless(listExpr string, arr []any, sourceMap, params map[string]any) {
	listExpr = strings.TrimSpace(expandDynamicBrackets(listExpr, sourceMap, params, 0))
	for _, pfx := range []string{"ctx?._source?.", "ctx?._source.", "ctx._source?.", "ctx._source."} {
		if strings.HasPrefix(listExpr, pfx) {
			relPath := strings.TrimSuffix(strings.TrimPrefix(listExpr, pfx), "?")
			setValueAtPath(sourceMap, strings.Split(relPath, "."), arr)
			syncSourceAliasToLocalVars(sourceMap, params, relPath)
			return
		}
	}
	cleanRec := strings.TrimSuffix(listExpr, "?")
	arrPath := normalizeLocalLHSPath(strings.Split(cleanRec, "."), params)
	if len(arrPath) > 0 {
		rootVar := decodeBracketSeg(arrPath[0])
		if _, exists := params[rootVar]; exists {
			setValueAtPath(params, arrPath, arr)
			syncLocalVarAlias(sourceMap, params, rootVar)
		}
	}
}

func lookupCtxMapKeyPainless(kStr string, sourceMap, params map[string]any) (any, bool) {
	switch kStr {
	case "_index":
		if v, ok := params["_ctx_index"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["__reindex_index"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["_index"]; ok {
			return v, v != nil
		}
		return nil, false
	case "_id":
		if v, ok := params["_ctx_id"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["__reindex_id"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["_id"]; ok {
			return v, v != nil
		}
		return nil, false
	case "_routing":
		if v, ok := params["_ctx_routing"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["_routing"]; ok {
			return v, v != nil
		}
		return nil, false
	case "_version":
		if v, ok := params["_ctx_version"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["__reindex_version"]; ok {
			return v, v != nil
		}
		if v, ok := sourceMap["_version"]; ok {
			return v, v != nil
		}
		return nil, false
	case "op":
		if v, ok := params["_ctx_op"]; ok {
			return v, true
		}
		return "index", true
	case "_now":
		if v, ok := params["_now"]; ok && v != nil {
			if f, fOk := toFloat64(v); fOk {
				return int64(f), true
			}
			return v, true
		}
		return getOrInitEvalBudget(params).nowMillis, true
	case "_source":
		return sourceMap, sourceMap != nil
	default:
		if sourceMap != nil && !isInternalPainlessMapKey(sourceMap, kStr) {
			v, exists := sourceMap[kStr]
			return v, exists
		}
		return nil, false
	}
}

func translateJavaDateTimePatternToGo(pattern string) string {
	var sb strings.Builder
	n := len(pattern)
	for i := 0; i < n; {
		c := pattern[i]
		if c == '\'' {
			if i+1 < n && pattern[i+1] == '\'' {
				sb.WriteByte('\'')
				i += 2
				continue
			}
			j := i + 1
			for j < n {
				if pattern[j] == '\'' {
					if j+1 < n && pattern[j+1] == '\'' {
						sb.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				sb.WriteByte(pattern[j])
				j++
			}
			if j < n && pattern[j] == '\'' {
				j++
			}
			i = j
			continue
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			j := i + 1
			for j < n && pattern[j] == c {
				j++
			}
			tok := pattern[i:j]
			switch c {
			case 'y', 'u':
				if len(tok) == 2 {
					sb.WriteString("06")
				} else {
					sb.WriteString("2006")
				}
			case 'M':
				switch len(tok) {
				case 1:
					sb.WriteString("1")
				case 2:
					sb.WriteString("01")
				case 3:
					sb.WriteString("Jan")
				default:
					sb.WriteString("January")
				}
			case 'd':
				if len(tok) == 1 {
					sb.WriteString("2")
				} else {
					sb.WriteString("02")
				}
			case 'H':
				sb.WriteString("15")
			case 'h':
				if len(tok) == 1 {
					sb.WriteString("3")
				} else {
					sb.WriteString("03")
				}
			case 'm':
				if len(tok) == 1 {
					sb.WriteString("4")
				} else {
					sb.WriteString("04")
				}
			case 's':
				if len(tok) == 1 {
					sb.WriteString("5")
				} else {
					sb.WriteString("05")
				}
			case 'S':
				sb.WriteString(strings.Repeat("0", len(tok)))
			case 'n', 'N':
				sb.WriteString("999999999")
			case 'a':
				sb.WriteString("PM")
			case 'E':
				if len(tok) <= 3 {
					sb.WriteString("Mon")
				} else {
					sb.WriteString("Monday")
				}
			case 'X':
				switch len(tok) {
				case 1:
					sb.WriteString("Z07")
				case 2:
					sb.WriteString("Z0700")
				default:
					sb.WriteString("Z07:00")
				}
			case 'x':
				switch len(tok) {
				case 1:
					sb.WriteString("-07")
				case 2:
					sb.WriteString("-0700")
				default:
					sb.WriteString("-07:00")
				}
			case 'Z':
				if len(tok) >= 4 {
					sb.WriteString("Z07:00")
				} else {
					sb.WriteString("-0700")
				}
			case 'z', 'V':
				sb.WriteString("MST")
			default:
				sb.WriteString(tok)
			}
			i = j
			continue
		}
		sb.WriteByte(c)
		i++
	}
	return sb.String()
}

func resolveDateTimeFormatterLayoutPainless(fmtVal any) string {
	if fmtVal == nil {
		return time.RFC3339Nano
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", fmtVal))
	if idx := strings.Index(s, "@@"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	switch s {
	case "ISO_LOCAL_DATE", "ISO_DATE", "DateTimeFormatter.ISO_LOCAL_DATE", "DateTimeFormatter.ISO_DATE":
		return "2006-01-02"
	case "ISO_LOCAL_TIME", "ISO_TIME", "DateTimeFormatter.ISO_LOCAL_TIME", "DateTimeFormatter.ISO_TIME":
		return "15:04:05"
	case "BASIC_ISO_DATE", "DateTimeFormatter.BASIC_ISO_DATE":
		return "20060102"
	case "ISO_LOCAL_DATE_TIME", "DateTimeFormatter.ISO_LOCAL_DATE_TIME":
		return "2006-01-02T15:04:05"
	case "ISO_OFFSET_DATE_TIME", "ISO_ZONED_DATE_TIME", "ISO_INSTANT", "ISO_DATE_TIME",
		"DateTimeFormatter.ISO_OFFSET_DATE_TIME", "DateTimeFormatter.ISO_ZONED_DATE_TIME",
		"DateTimeFormatter.ISO_INSTANT", "DateTimeFormatter.ISO_DATE_TIME":
		return time.RFC3339Nano
	}
	if !strings.Contains(s, "2006") && !strings.Contains(s, "01") && !strings.Contains(s, "02") && !strings.Contains(s, "15") {
		return translateJavaDateTimePatternToGo(s)
	}
	return s
}

func parseDateTimeWithFormatterPainless(val, fmtVal any) (time.Time, bool) {
	if val == nil {
		return time.Time{}, false
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", val))
	if idx := strings.IndexByte(s, '['); idx > 0 && strings.HasSuffix(s, "]") {
		s = strings.TrimSpace(s[:idx])
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
	tm, ok := parsePainlessDateTime(s)
	if ok && zLoc != nil {
		tm = tm.In(zLoc)
	}
	return tm, ok
}

func parseZoneLocationPainless(zVal any) *time.Location {
	if zVal == nil {
		return time.UTC
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", zVal))
	if s == "" || strings.EqualFold(s, "Z") || strings.EqualFold(s, "UTC") || strings.EqualFold(s, "GMT") || s == "ZoneOffset.UTC" {
		return time.UTC
	}
	if strings.HasPrefix(s, "UTC+") || strings.HasPrefix(s, "UTC-") || strings.HasPrefix(s, "GMT+") || strings.HasPrefix(s, "GMT-") {
		s = s[3:]
	}
	if len(s) >= 2 && (s[0] == '+' || s[0] == '-') {
		sign := 1
		if s[0] == '-' {
			sign = -1
		}
		rest := s[1:]
		var hrs, mins int
		if strings.Contains(rest, ":") {
			parts := strings.SplitN(rest, ":", 2)
			hrs, _ = strconv.Atoi(parts[0])
			mins, _ = strconv.Atoi(parts[1])
		} else if len(rest) == 4 {
			hrs, _ = strconv.Atoi(rest[:2])
			mins, _ = strconv.Atoi(rest[2:])
		} else {
			hrs, _ = strconv.Atoi(rest)
		}
		offsetSec := sign * (hrs*3600 + mins*60)
		return time.FixedZone(s, offsetSec)
	}
	if loc, err := time.LoadLocation(s); err == nil {
		return loc
	}
	return time.UTC
}

func parsePainlessDuration(v any) (time.Duration, bool) {
	switch tv := v.(type) {
	case time.Duration:
		return tv, true
	case string:
		return parseISO8601DurationPainless(tv)
	}
	return 0, false
}

func parseISO8601DurationPainless(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, false
	}
	neg := false
	switch s[0] {
	case '-':
		neg = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if !strings.HasPrefix(s, "P") || len(s) < 2 {
		return 0, false
	}
	s = s[1:]
	inTime := false
	var total time.Duration
	parsedAny := false
	for i := 0; i < len(s); {
		if s[i] == 'T' {
			inTime = true
			i++
			continue
		}
		partNeg := false
		switch s[i] {
		case '-':
			partNeg = true
			i++
		case '+':
			i++
		}
		start := i
		for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == ',') {
			i++
		}
		if i == start || i >= len(s) {
			return 0, false
		}
		numStr := strings.ReplaceAll(s[start:i], ",", ".")
		val, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			return 0, false
		}
		if partNeg {
			val = -val
		}
		unit := s[i]
		i++
		var d time.Duration
		if !inTime && unit == 'D' {
			d = time.Duration(val * float64(24*time.Hour))
		} else if inTime {
			switch unit {
			case 'H':
				d = time.Duration(val * float64(time.Hour))
			case 'M':
				d = time.Duration(val * float64(time.Minute))
			case 'S':
				d = time.Duration(val * float64(time.Second))
			default:
				return 0, false
			}
		} else {
			return 0, false
		}
		total += d
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

func isNumericValuePainless(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number, *painlessBigDecimal, *painlessBigInteger, *big.Float, *big.Int:
		return true
	default:
		return false
	}
}

func toInt64Painless(v any) (int64, bool) {
	switch tv := v.(type) {
	case *painlessBigDecimal:
		if tv == nil {
			return 0, false
		}
		return tv.longValue(), true
	case *painlessBigInteger:
		if tv == nil {
			return 0, false
		}
		return tv.longValue(), true
	case int:
		return int64(tv), true
	case int64:
		return tv, true
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		return int64(tv), true
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv, true
		}
		if fv, err := tv.Float64(); err == nil {
			return int64(fv), true
		}
	case string:
		s := strings.TrimSpace(tv)
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		if f, ok := toFloat64(tv); ok {
			return int64(f), true
		}
	}
	return 0, false
}

func normalizeJavaNamedGroupsPainless(pat string) string {
	if !strings.Contains(pat, "(?<") {
		return pat
	}
	var sb strings.Builder
	sb.Grow(len(pat) + 8)
	inClass := false
	for i := 0; i < len(pat); i++ {
		if pat[i] == '\\' && i+1 < len(pat) {
			sb.WriteByte(pat[i])
			sb.WriteByte(pat[i+1])
			i++
			continue
		}
		if pat[i] == '[' {
			inClass = true
			sb.WriteByte(pat[i])
			continue
		}
		if pat[i] == ']' && inClass {
			inClass = false
			sb.WriteByte(pat[i])
			continue
		}
		if !inClass && i+3 < len(pat) && pat[i] == '(' && pat[i+1] == '?' && pat[i+2] == '<' && pat[i+3] != '=' && pat[i+3] != '!' {
			sb.WriteString("(?P<")
			i += 2
			continue
		}
		sb.WriteByte(pat[i])
	}
	return sb.String()
}

func compilePainlessRegexp(pat string) (*regexp.Regexp, error) {
	return regexp.Compile(normalizeJavaNamedGroupsPainless(pat))
}

func inspectStartAnchorPainless(pat string) (anchorType byte, multiline bool) {
	s := pat
	for len(s) > 0 {
		if strings.HasPrefix(s, "(?") {
			idx := 2
			neg := false
			localM := multiline
			validFlags := true
			for idx < len(s) && s[idx] != ')' && s[idx] != ':' {
				ch := s[idx]
				switch ch {
				case '-':
					neg = true
				case 'm':
					localM = !neg
				case 'i', 's', 'U':
				default:
					validFlags = false
				}
				if !validFlags {
					break
				}
				idx++
			}
			if validFlags && idx < len(s) && (s[idx] == ')' || s[idx] == ':') {
				multiline = localM
				s = s[idx+1:]
				continue
			}
		}
		if strings.HasPrefix(s, "(") && !strings.HasPrefix(s, "(?") {
			s = s[1:]
			continue
		}
		break
	}
	branches := splitTopLevelRegexBranchesPainless(s)
	if len(branches) == 0 {
		return 0, multiline
	}
	var commonAnchor byte
	for _, br := range branches {
		var bAnchor byte
		if strings.HasPrefix(br, `\A`) {
			bAnchor = 'A'
		} else if strings.HasPrefix(br, "^") {
			bAnchor = '^'
		} else {
			return 0, multiline
		}
		if commonAnchor == 0 {
			commonAnchor = bAnchor
		} else if commonAnchor != bAnchor {
			commonAnchor = '^'
		}
	}
	return commonAnchor, multiline
}

func splitTopLevelRegexBranchesPainless(s string) []string {
	var out []string
	depth := 0
	inClass := false
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if s[i] == '[' {
			inClass = true
			continue
		}
		if s[i] == ']' && inClass {
			inClass = false
			continue
		}
		if inClass {
			continue
		}
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

func findSubmatchIndexFromPosPainless(re *regexp.Regexp, input string, pos int) []int {
	if re == nil || pos < 0 || pos > len(input) {
		return nil
	}
	if pos > 0 {
		anchor, multiline := inspectStartAnchorPainless(re.String())
		if anchor == 'A' {
			return nil
		}
		if anchor == '^' {
			if !multiline {
				return nil
			}
			if input[pos-1] != '\n' {
				nlIdx := strings.IndexByte(input[pos:], '\n')
				if nlIdx < 0 {
					return nil
				}
				pos += nlIdx + 1
			}
		}
	}
	loc := re.FindStringSubmatchIndex(input[pos:])
	if loc == nil {
		return nil
	}
	shifted := make([]int, len(loc))
	for i, v := range loc {
		if v >= 0 {
			shifted[i] = v + pos
		} else {
			shifted[i] = -1
		}
	}
	return shifted
}

func formatArraysToStringPainless(arr []any, deep bool) string {
	if arr == nil {
		return "null"
	}
	parts := make([]string, len(arr))
	for i, el := range arr {
		if el == nil {
			parts[i] = "null"
			continue
		}
		if sub, ok := el.([]any); ok && deep {
			parts[i] = formatArraysToStringPainless(sub, true)
			continue
		}
		parts[i] = fmt.Sprintf("%v", el)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func parsePainlessPeriod(v any) (painlessPeriod, bool) {
	switch tv := v.(type) {
	case painlessPeriod:
		return tv, true
	case string:
		return parseISO8601PeriodPainless(tv)
	}
	return painlessPeriod{}, false
}

func parseISO8601PeriodPainless(s string) (painlessPeriod, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || strings.Contains(s, "T") {
		return painlessPeriod{}, false
	}
	neg := 1
	switch s[0] {
	case '-':
		neg = -1
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if !strings.HasPrefix(s, "P") || len(s) < 2 {
		return painlessPeriod{}, false
	}
	s = s[1:]
	var years, months, days int
	parsedAny := false
	for i := 0; i < len(s); {
		partSign := 1
		switch s[i] {
		case '-':
			partSign = -1
			i++
		case '+':
			i++
		}
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start || i >= len(s) {
			return painlessPeriod{}, false
		}
		val, err := strconv.Atoi(s[start:i])
		if err != nil {
			return painlessPeriod{}, false
		}
		val *= neg * partSign
		unit := s[i]
		i++
		switch unit {
		case 'Y':
			years += val
		case 'M':
			months += val
		case 'W':
			days += val * 7
		case 'D':
			days += val
		default:
			return painlessPeriod{}, false
		}
		parsedAny = true
	}
	if !parsedAny {
		return painlessPeriod{}, false
	}
	return painlessPeriod{years: years, months: months, days: days}, true
}

func daysInMonthPainless(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func addMonthsClampedPainless(tm time.Time, months int) time.Time {
	year, month, day := tm.Date()
	totalMonths := int(month) - 1 + months
	targetYear := year + totalMonths/12
	targetMonth := totalMonths % 12
	if targetMonth < 0 {
		targetYear--
		targetMonth += 12
	}
	m := time.Month(targetMonth + 1)
	maxDay := daysInMonthPainless(targetYear, m)
	if day > maxDay {
		day = maxDay
	}
	return time.Date(targetYear, m, day, tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location())
}

func attachZoneToFormatterPainless(fmtVal, zVal any) string {
	base := "ISO_ZONED_DATE_TIME"
	if fmtVal != nil {
		base = strings.TrimSpace(fmt.Sprintf("%v", fmtVal))
		if idx := strings.Index(base, "@@"); idx >= 0 {
			base = strings.TrimSpace(base[:idx])
		}
	}
	zStr := "UTC"
	if zVal != nil {
		zStr = strings.TrimSpace(fmt.Sprintf("%v", zVal))
	}
	return base + "@@" + zStr
}

func splitFormatterAndZonePainless(fmtVal any) (string, *time.Location) {
	layout := resolveDateTimeFormatterLayoutPainless(fmtVal)
	if fmtVal == nil {
		return layout, nil
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", fmtVal))
	if idx := strings.Index(s, "@@"); idx >= 0 {
		zPart := strings.TrimSpace(s[idx+2:])
		if zPart != "" {
			return layout, parseZoneLocationPainless(zPart)
		}
	}
	return layout, nil
}

func parseAndFormatUUIDPainless(s string) (string, bool) {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return "", false
	}
	maxLens := []int{8, 4, 4, 4, 12}
	var out [5]string
	for i, p := range parts {
		if len(p) == 0 || len(p) > maxLens[i] {
			return "", false
		}
		val, err := strconv.ParseUint(p, 16, 64)
		if err != nil {
			return "", false
		}
		out[i] = fmt.Sprintf("%0*x", maxLens[i], val)
	}
	return strings.Join(out[:], "-"), true
}

func evalOptionalOrElseThrowSupplierPainless(argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	trimmed := strings.TrimSpace(argExpr)
	if trimmed == "" {
		return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
	}
	if strings.HasSuffix(trimmed, "::new") {
		exType := strings.TrimSpace(strings.TrimSuffix(trimmed, "::new"))
		for _, pfx := range []string{"java.util.", "java.lang."} {
			exType = strings.TrimPrefix(exType, pfx)
		}
		if exType == "" {
			exType = "NoSuchElementException"
		}
		return nil, &painlessExceptionError{exType: exType, message: ""}
	}
	normArg := normalizeMethodReferenceToLambdaPainless(trimmed, 0)
	if arrowIdx := findNextUnquotedSubstr(normArg, "->", 0); arrowIdx >= 0 {
		body := strings.TrimSpace(normArg[arrowIdx+2:])
		if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
			body = strings.TrimSpace(body[1 : len(body)-1])
		}
		body = strings.TrimSuffix(strings.TrimSpace(body), ";")
		if strings.HasPrefix(body, "return ") {
			body = strings.TrimSpace(strings.TrimPrefix(body, "return "))
		} else if strings.HasPrefix(body, "throw ") {
			body = strings.TrimSpace(strings.TrimPrefix(body, "throw "))
		}
		if strings.HasPrefix(body, "new ") {
			rest := strings.TrimSpace(body[4:])
			if openP := strings.IndexByte(rest, '('); openP > 0 {
				if closeP := findMatchingDelimiter(rest, openP, '(', ')'); closeP > openP {
					exType := strings.TrimSpace(rest[:openP])
					for _, pfx := range []string{"java.util.", "java.lang."} {
						exType = strings.TrimPrefix(exType, pfx)
					}
					msgArg := strings.TrimSpace(rest[openP+1 : closeP])
					msgStr := ""
					if msgArg != "" {
						mv, err := evalRHSExprDepth(sourceMap, msgArg, params, depth+1)
						if err != nil {
							return nil, err
						}
						if mv != nil {
							msgStr = fmt.Sprintf("%v", mv)
						}
					}
					return nil, &painlessExceptionError{exType: exType, message: msgStr}
				}
			}
		}
		val, err := evalPainlessLambdaBody(normArg[arrowIdx+2:], sourceMap, params, depth+1)
		if err != nil {
			return nil, err
		}
		if m, ok := val.(map[string]any); ok {
			if exType, hasEx := m["__exc_type"].(string); hasEx && exType != "" {
				msg, _ := m["message"].(string)
				return nil, &painlessExceptionError{exType: exType, message: msg}
			}
		}
	}
	return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "No value present"}
}

func translateEscapesPainless(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	n := len(s)
	for i := 0; i < n; i++ {
		if s[i] != '\\' || i+1 >= n {
			sb.WriteByte(s[i])
			continue
		}
		i++
		c := s[i]
		switch c {
		case 'b':
			sb.WriteByte('\b')
		case 'f':
			sb.WriteByte('\f')
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 's':
			sb.WriteByte(' ')
		case 't':
			sb.WriteByte('\t')
		case '\'':
			sb.WriteByte('\'')
		case '"':
			sb.WriteByte('"')
		case '\\':
			sb.WriteByte('\\')
		case '\n':
			// Line continuation: discard backslash and newline
		case '\r':
			if i+1 < n && s[i+1] == '\n' {
				i++
			}
		default:
			if c >= '0' && c <= '7' {
				maxDigits := 3
				if c > '3' {
					maxDigits = 2
				}
				octVal := int(c - '0')
				digits := 1
				for digits < maxDigits && i+1 < n && s[i+1] >= '0' && s[i+1] <= '7' {
					i++
					octVal = octVal*8 + int(s[i]-'0')
					digits++
				}
				sb.WriteByte(byte(octVal)) // #nosec G115 -- octal escape in 0..255
			} else {
				sb.WriteByte(c)
			}
		}
	}
	return sb.String()
}

func evalUUIDZeroArgMethodPainless(mSuffix string, recVal any) (any, error) {
	s, ok := parseAndFormatUUIDPainless(strings.TrimSpace(fmt.Sprintf("%v", recVal)))
	if !ok {
		return int64(0), nil
	}
	parts := strings.Split(s, "-")
	p0, _ := strconv.ParseUint(parts[0], 16, 64)
	p1, _ := strconv.ParseUint(parts[1], 16, 64)
	p2, _ := strconv.ParseUint(parts[2], 16, 64)
	p3, _ := strconv.ParseUint(parts[3], 16, 64)
	p4, _ := strconv.ParseUint(parts[4], 16, 64)
	msb := (p0 << 32) | (p1 << 16) | p2
	lsb := (p3 << 48) | p4
	switch mSuffix {
	case ".getMostSignificantBits()":
		return int64(msb), nil // #nosec G115 -- intentional 64-bit signed UUID MSB
	case ".getLeastSignificantBits()":
		return int64(lsb), nil // #nosec G115 -- intentional 64-bit signed UUID LSB
	case ".version()":
		return int64((msb >> 12) & 0x0f), nil // #nosec G115 -- 4-bit version
	case ".variant()":
		if (lsb >> 63) == 0 {
			return int64(0), nil
		}
		if ((lsb >> 62) & 0x3) == 2 {
			return int64(2), nil
		}
		return int64((lsb >> 61) & 0x7), nil // #nosec G115 -- 3-bit variant
	}
	return int64(0), nil
}

func evalHexFormatMethodPainless(mName string, recVal any, argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	hf, ok := recVal.(painlessHexFormat)
	if !ok {
		hf = painlessHexFormat{}
	}
	args := splitTopLevelCommaPainless(argExpr)
	switch mName {
	case ".withPrefix(":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, err
			}
			hf.prefix = fmt.Sprintf("%v", v)
		}
		return hf, nil
	case ".withSuffix(":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, err
			}
			hf.suffix = fmt.Sprintf("%v", v)
		}
		return hf, nil
	case ".withDelimiter(":
		if len(args) >= 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, err
			}
			hf.delimiter = fmt.Sprintf("%v", v)
		}
		return hf, nil
	case ".formatHex(":
		if len(args) == 0 {
			return "", nil
		}
		v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return "", err
		}
		raw := toBytesPainless(v0)
		if len(args) >= 3 {
			fVal, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err1 != nil {
				return "", err1
			}
			tVal, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
			if err2 != nil {
				return "", err2
			}
			fromIdx, _ := toInt64Painless(fVal)
			toIdx, _ := toInt64Painless(tVal)
			if fromIdx < 0 || toIdx < fromIdx || int(toIdx) > len(raw) {
				return "", &painlessExceptionError{
					exType:  "IndexOutOfBoundsException",
					message: fmt.Sprintf("Range [%d, %d) out of bounds for length %d", fromIdx, toIdx, len(raw)),
				}
			}
			raw = raw[int(fromIdx):int(toIdx)]
		}
		if len(raw) == 0 {
			return "", nil
		}
		parts := make([]string, len(raw))
		for i, b := range raw {
			var h string
			if hf.upperCase {
				h = fmt.Sprintf("%02X", b)
			} else {
				h = fmt.Sprintf("%02x", b)
			}
			parts[i] = hf.prefix + h + hf.suffix
		}
		return strings.Join(parts, hf.delimiter), nil
	case ".parseHex(":
		if len(args) == 0 {
			return []any{}, nil
		}
		v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return nil, err
		}
		s := fmt.Sprintf("%v", v0)
		if len(args) >= 3 {
			fVal, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err1 != nil {
				return nil, err1
			}
			tVal, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
			if err2 != nil {
				return nil, err2
			}
			fromIdx, _ := toInt64Painless(fVal)
			toIdx, _ := toInt64Painless(tVal)
			if fromIdx < 0 || toIdx < fromIdx || int(toIdx) > len(s) {
				return nil, &painlessExceptionError{
					exType:  "IndexOutOfBoundsException",
					message: fmt.Sprintf("Range [%d, %d) out of bounds for length %d", fromIdx, toIdx, len(s)),
				}
			}
			s = s[int(fromIdx):int(toIdx)]
		}
		if s == "" {
			return []any{}, nil
		}
		parseTwoHex := func(pair string) (int64, error) {
			if len(pair) != 2 {
				return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid hex pair"}
			}
			bv, pErr := strconv.ParseUint(pair, 16, 8)
			if pErr != nil {
				return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: pErr.Error()}
			}
			return int64(bv), nil
		}
		if hf.delimiter != "" {
			tokens := strings.Split(s, hf.delimiter)
			out := make([]any, 0, len(tokens))
			for _, tok := range tokens {
				if !strings.HasPrefix(tok, hf.prefix) || !strings.HasSuffix(tok, hf.suffix) || len(tok) != len(hf.prefix)+2+len(hf.suffix) {
					return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid hex token"}
				}
				hexPair := tok[len(hf.prefix) : len(tok)-len(hf.suffix)]
				bv, pErr := parseTwoHex(hexPair)
				if pErr != nil {
					return nil, pErr
				}
				out = append(out, bv)
			}
			return out, nil
		}
		stepLen := len(hf.prefix) + 2 + len(hf.suffix)
		if len(s)%stepLen != 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid hex string length"}
		}
		out := make([]any, 0, len(s)/stepLen)
		for i := 0; i < len(s); i += stepLen {
			tok := s[i : i+stepLen]
			if !strings.HasPrefix(tok, hf.prefix) || !strings.HasSuffix(tok, hf.suffix) {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid hex affix"}
			}
			hexPair := tok[len(hf.prefix) : len(tok)-len(hf.suffix)]
			bv, pErr := parseTwoHex(hexPair)
			if pErr != nil {
				return nil, pErr
			}
			out = append(out, bv)
		}
		return out, nil
	case ".toHexDigits(":
		if len(args) == 0 {
			return "", nil
		}
		raw0 := strings.TrimSpace(args[0])
		v0, err := evalRHSExprDepth(sourceMap, raw0, params, depth+1)
		if err != nil {
			return "", err
		}
		digits := 8
		if len(args) >= 2 {
			dVal, errD := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if errD != nil {
				return "", errD
			}
			if dInt, okD := toInt64Painless(dVal); okD {
				if dInt < 0 || dInt > 16 {
					return "", &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("digits out of range: %d", dInt)}
				}
				digits = int(dInt)
			}
		} else if strings.HasPrefix(raw0, "(byte)") {
			digits = 2
		} else if strings.HasPrefix(raw0, "(short)") || strings.HasPrefix(raw0, "(char)") {
			digits = 4
		} else if strings.HasPrefix(raw0, "(long)") || strings.HasSuffix(strings.ToUpper(raw0), "L") {
			digits = 16
		} else if s, okS := v0.(string); okS && utf8.RuneCountInString(s) == 1 {
			r, _ := utf8.DecodeRuneInString(s)
			if hf.upperCase {
				return fmt.Sprintf("%04X", uint16(r)), nil // #nosec G115 -- char code unit
			}
			return fmt.Sprintf("%04x", uint16(r)), nil // #nosec G115 -- char code unit
		} else if iv, okI := toInt64Painless(v0); okI && (iv > math.MaxInt32 || iv < math.MinInt32) {
			digits = 16
		}
		if digits == 0 {
			return "", nil
		}
		iv, _ := toInt64Painless(v0)
		uVal := uint64(iv) // #nosec G115 -- bit pattern formatting
		if digits < 16 {
			uVal &= (uint64(1) << (digits * 4)) - 1
		}
		if hf.upperCase {
			return fmt.Sprintf("%0*X", digits, uVal), nil
		}
		return fmt.Sprintf("%0*x", digits, uVal), nil
	case ".fromHexDigits(", ".fromHexDigitsToLong(":
		if len(args) == 0 {
			return int64(0), nil
		}
		v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return int64(0), err
		}
		s := fmt.Sprintf("%v", v0)
		if len(args) >= 3 {
			fVal, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err1 != nil {
				return int64(0), err1
			}
			tVal, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
			if err2 != nil {
				return int64(0), err2
			}
			fromIdx, _ := toInt64Painless(fVal)
			toIdx, _ := toInt64Painless(tVal)
			if fromIdx < 0 || toIdx < fromIdx || int(toIdx) > len(s) {
				return int64(0), &painlessExceptionError{
					exType:  "IndexOutOfBoundsException",
					message: fmt.Sprintf("Range [%d, %d) out of bounds for length %d", fromIdx, toIdx, len(s)),
				}
			}
			s = s[int(fromIdx):int(toIdx)]
		}
		maxLen := 8
		if mName == ".fromHexDigitsToLong(" {
			maxLen = 16
		}
		if len(s) == 0 || len(s) > maxLen {
			return int64(0), &painlessExceptionError{exType: "NumberFormatException", message: fmt.Sprintf("For input string: %q", s)}
		}
		uVal, pErr := strconv.ParseUint(s, 16, 64)
		if pErr != nil {
			return int64(0), &painlessExceptionError{exType: "NumberFormatException", message: fmt.Sprintf("For input string: %q", s)}
		}
		if mName == ".fromHexDigits(" {
			return int64(int32(uint32(uVal))), nil // #nosec G115 -- Java 32-bit int result
		}
		return int64(uVal), nil // #nosec G115 -- Java 64-bit long result
	case ".isHexDigit(":
		if len(args) == 0 {
			return false, nil
		}
		v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return false, err
		}
		var ch rune
		if s, okS := v0.(string); okS && len(s) > 0 {
			ch, _ = utf8.DecodeRuneInString(s)
		} else if iv, okI := toInt64Painless(v0); okI {
			ch = rune(iv) // #nosec G115 -- char code point
		}
		return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'), nil
	case ".fromHexDigit(":
		if len(args) == 0 {
			return int64(0), &painlessExceptionError{exType: "NumberFormatException", message: "empty"}
		}
		v0, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err != nil {
			return int64(0), err
		}
		var ch rune
		if s, okS := v0.(string); okS && len(s) > 0 {
			ch, _ = utf8.DecodeRuneInString(s)
		} else if iv, okI := toInt64Painless(v0); okI {
			ch = rune(iv) // #nosec G115 -- char code point
		}
		switch {
		case ch >= '0' && ch <= '9':
			return int64(ch - '0'), nil
		case ch >= 'a' && ch <= 'f':
			return int64(ch - 'a' + 10), nil
		case ch >= 'A' && ch <= 'F':
			return int64(ch - 'A' + 10), nil
		default:
			return int64(0), &painlessExceptionError{exType: "NumberFormatException", message: fmt.Sprintf("not a hexadecimal digit: %q", ch)}
		}
	}
	return recVal, nil
}

func evalCollectionZeroArgMethodPainless(mSuffix, recExpr string, recVal any, sourceMap, params map[string]any) (any, error) {
	switch tv := recVal.(type) {
	case map[string]any:
		keys := visiblePainlessMapKeys(tv)
		switch mSuffix {
		case ".firstKey()":
			if len(keys) == 0 {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "TreeMap is empty"}
			}
			return keys[0], nil
		case ".lastKey()":
			if len(keys) == 0 {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "TreeMap is empty"}
			}
			return keys[len(keys)-1], nil
		case ".firstEntry()":
			if len(keys) == 0 {
				return nil, nil
			}
			k := keys[0]
			return map[string]any{"key": k, "value": tv[k], "__parent_map": tv}, nil
		case ".lastEntry()":
			if len(keys) == 0 {
				return nil, nil
			}
			k := keys[len(keys)-1]
			return map[string]any{"key": k, "value": tv[k], "__parent_map": tv}, nil
		case ".pollFirstEntry()":
			if len(keys) == 0 {
				return nil, nil
			}
			k := keys[0]
			v := tv[k]
			delete(tv, k)
			return map[string]any{"key": k, "value": v}, nil
		case ".pollLastEntry()":
			if len(keys) == 0 {
				return nil, nil
			}
			k := keys[len(keys)-1]
			v := tv[k]
			delete(tv, k)
			return map[string]any{"key": k, "value": v}, nil
		case ".navigableKeySet()":
			out := make([]any, len(keys))
			for i, k := range keys {
				out[i] = k
			}
			return out, nil
		case ".descendingKeySet()":
			out := make([]any, len(keys))
			for i, k := range keys {
				out[len(keys)-1-i] = k
			}
			return out, nil
		case ".descendingMap()":
			cp := make(map[string]any, len(tv)+1)
			for k, v := range tv {
				if !isInternalPainlessMapKey(tv, k) {
					cp[k] = v
				}
			}
			desc, _ := tv["__descending"].(bool)
			cp["__descending"] = !desc
			return cp, nil
		}
	case []any:
		switch mSuffix {
		case ".first()", ".getFirst()", ".element()":
			if len(tv) == 0 {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "Collection is empty"}
			}
			return tv[0], nil
		case ".last()", ".getLast()":
			if len(tv) == 0 {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "Collection is empty"}
			}
			return tv[len(tv)-1], nil
		case ".peekFirst()", ".peek()":
			if len(tv) == 0 {
				return nil, nil
			}
			return tv[0], nil
		case ".peekLast()":
			if len(tv) == 0 {
				return nil, nil
			}
			return tv[len(tv)-1], nil
		case ".pollFirst()", ".poll()":
			if len(tv) == 0 {
				return nil, nil
			}
			first := tv[0]
			next := make([]any, len(tv)-1)
			copy(next, tv[1:])
			syncMutatedListExprPainless(recExpr, next, sourceMap, params)
			return first, nil
		case ".pollLast()":
			if len(tv) == 0 {
				return nil, nil
			}
			last := tv[len(tv)-1]
			next := make([]any, len(tv)-1)
			copy(next, tv[:len(tv)-1])
			syncMutatedListExprPainless(recExpr, next, sourceMap, params)
			return last, nil
		case ".removeFirst()", ".pop()":
			if len(tv) == 0 {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "Collection is empty"}
			}
			first := tv[0]
			next := make([]any, len(tv)-1)
			copy(next, tv[1:])
			syncMutatedListExprPainless(recExpr, next, sourceMap, params)
			return first, nil
		case ".removeLast()":
			if len(tv) == 0 {
				return nil, &painlessExceptionError{exType: "NoSuchElementException", message: "Collection is empty"}
			}
			last := tv[len(tv)-1]
			next := make([]any, len(tv)-1)
			copy(next, tv[:len(tv)-1])
			syncMutatedListExprPainless(recExpr, next, sourceMap, params)
			return last, nil
		case ".descendingSet()":
			out := make([]any, len(tv))
			for i, el := range tv {
				out[len(tv)-1-i] = el
			}
			return out, nil
		}
	}
	return nil, nil
}

func evalNavigableOrDequeMethodPainless(mName, recExpr string, recVal any, argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	args := splitTopLevelCommaPainless(argExpr)
	evalArg := func(idx int) (any, error) {
		if idx >= len(args) {
			return nil, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
	}
	switch tv := recVal.(type) {
	case map[string]any:
		keys := visiblePainlessMapKeys(tv)
		switch mName {
		case ".floorKey(", ".ceilingKey(", ".lowerKey(", ".higherKey(",
			".floorEntry(", ".ceilingEntry(", ".lowerEntry(", ".higherEntry(":
			targetVal, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			isEntry := strings.HasSuffix(mName, "Entry(")
			matchedKey := ""
			found := false
			for _, k := range keys {
				cmp := comparePainlessValues(k, targetVal)
				switch mName {
				case ".lowerKey(", ".lowerEntry(":
					if cmp < 0 {
						matchedKey = k
						found = true
					}
				case ".floorKey(", ".floorEntry(":
					if cmp <= 0 {
						matchedKey = k
						found = true
					}
				case ".ceilingKey(", ".ceilingEntry(":
					if cmp >= 0 && !found {
						matchedKey = k
						found = true
					}
				case ".higherKey(", ".higherEntry(":
					if cmp > 0 && !found {
						matchedKey = k
						found = true
					}
				}
			}
			if !found {
				return nil, nil
			}
			if isEntry {
				return map[string]any{"key": matchedKey, "value": tv[matchedKey], "__parent_map": tv}, nil
			}
			return matchedKey, nil
		case ".headMap(":
			toKey, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			inclusive := false
			if len(args) >= 2 {
				incVal, err2 := evalArg(1)
				if err2 != nil {
					return nil, err2
				}
				inclusive, _ = incVal.(bool)
			}
			out := map[string]any{}
			for _, k := range keys {
				cmp := comparePainlessValues(k, toKey)
				if cmp < 0 || (inclusive && cmp == 0) {
					out[k] = tv[k]
				}
			}
			return out, nil
		case ".tailMap(":
			fromKey, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			inclusive := true
			if len(args) >= 2 {
				incVal, err2 := evalArg(1)
				if err2 != nil {
					return nil, err2
				}
				inclusive, _ = incVal.(bool)
			}
			out := map[string]any{}
			for _, k := range keys {
				cmp := comparePainlessValues(k, fromKey)
				if cmp > 0 || (inclusive && cmp == 0) {
					out[k] = tv[k]
				}
			}
			return out, nil
		case ".subMap(":
			var fromKey, toKey any
			fromInc, toInc := true, false
			if len(args) >= 4 {
				var err error
				if fromKey, err = evalArg(0); err != nil {
					return nil, err
				}
				inc1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				fromInc, _ = inc1.(bool)
				if toKey, err = evalArg(2); err != nil {
					return nil, err
				}
				inc2, err2 := evalArg(3)
				if err2 != nil {
					return nil, err2
				}
				toInc, _ = inc2.(bool)
			} else if len(args) >= 2 {
				var err error
				if fromKey, err = evalArg(0); err != nil {
					return nil, err
				}
				if toKey, err = evalArg(1); err != nil {
					return nil, err
				}
			}
			out := map[string]any{}
			for _, k := range keys {
				cFrom := comparePainlessValues(k, fromKey)
				cTo := comparePainlessValues(k, toKey)
				okFrom := cFrom > 0 || (fromInc && cFrom == 0)
				okTo := cTo < 0 || (toInc && cTo == 0)
				if okFrom && okTo {
					out[k] = tv[k]
				}
			}
			return out, nil
		}
	case []any:
		switch mName {
		case ".floor(", ".ceiling(", ".lower(", ".higher(":
			targetVal, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			sorted := make([]any, len(tv))
			copy(sorted, tv)
			_ = sortPainlessSliceInPlace(sorted, "", sourceMap, params, depth+1)
			var matched any
			found := false
			for _, item := range sorted {
				cmp := comparePainlessValues(item, targetVal)
				switch mName {
				case ".lower(":
					if cmp < 0 {
						matched = item
						found = true
					}
				case ".floor(":
					if cmp <= 0 {
						matched = item
						found = true
					}
				case ".ceiling(":
					if cmp >= 0 && !found {
						matched = item
						found = true
					}
				case ".higher(":
					if cmp > 0 && !found {
						matched = item
						found = true
					}
				}
			}
			if !found {
				return nil, nil
			}
			return matched, nil
		case ".headSet(":
			toVal, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			inclusive := false
			if len(args) >= 2 {
				incVal, err2 := evalArg(1)
				if err2 != nil {
					return nil, err2
				}
				inclusive, _ = incVal.(bool)
			}
			out := []any{}
			for _, item := range tv {
				cmp := comparePainlessValues(item, toVal)
				if cmp < 0 || (inclusive && cmp == 0) {
					out = append(out, item)
				}
			}
			return out, nil
		case ".tailSet(":
			fromVal, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			inclusive := true
			if len(args) >= 2 {
				incVal, err2 := evalArg(1)
				if err2 != nil {
					return nil, err2
				}
				inclusive, _ = incVal.(bool)
			}
			out := []any{}
			for _, item := range tv {
				cmp := comparePainlessValues(item, fromVal)
				if cmp > 0 || (inclusive && cmp == 0) {
					out = append(out, item)
				}
			}
			return out, nil
		case ".subSet(":
			var fromVal, toVal any
			fromInc, toInc := true, false
			if len(args) >= 4 {
				var err error
				if fromVal, err = evalArg(0); err != nil {
					return nil, err
				}
				inc1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				fromInc, _ = inc1.(bool)
				if toVal, err = evalArg(2); err != nil {
					return nil, err
				}
				inc2, err2 := evalArg(3)
				if err2 != nil {
					return nil, err2
				}
				toInc, _ = inc2.(bool)
			} else if len(args) >= 2 {
				var err error
				if fromVal, err = evalArg(0); err != nil {
					return nil, err
				}
				if toVal, err = evalArg(1); err != nil {
					return nil, err
				}
			}
			out := []any{}
			for _, item := range tv {
				cFrom := comparePainlessValues(item, fromVal)
				cTo := comparePainlessValues(item, toVal)
				okFrom := cFrom > 0 || (fromInc && cFrom == 0)
				okTo := cTo < 0 || (toInc && cTo == 0)
				if okFrom && okTo {
					out = append(out, item)
				}
			}
			return out, nil
		case ".offerFirst(", ".addFirst(", ".push(":
			v, err := evalArg(0)
			if err != nil {
				return false, err
			}
			next := make([]any, 0, len(tv)+1)
			next = append(next, v)
			next = append(next, tv...)
			syncMutatedListExprPainless(recExpr, next, sourceMap, params)
			if mName == ".offerFirst(" {
				return true, nil
			}
			return nil, nil
		case ".offerLast(", ".offer(", ".addLast(":
			v, err := evalArg(0)
			if err != nil {
				return false, err
			}
			next := make([]any, len(tv), len(tv)+1)
			copy(next, tv)
			next = append(next, v)
			if params != nil && params["__col_kind_"+strings.TrimSpace(recExpr)] == "PriorityQueue" && len(next) > 1 {
				_ = sortPainlessSliceInPlace(next, "", sourceMap, params, depth+1)
			}
			syncMutatedListExprPainless(recExpr, next, sourceMap, params)
			if mName == ".addLast(" {
				return nil, nil
			}
			return true, nil
		case ".removeFirstOccurrence(":
			v, err := evalArg(0)
			if err != nil {
				return false, err
			}
			for i, item := range tv {
				if painlessValuesEqual(item, v) {
					next := make([]any, 0, len(tv)-1)
					next = append(next, tv[:i]...)
					next = append(next, tv[i+1:]...)
					syncMutatedListExprPainless(recExpr, next, sourceMap, params)
					return true, nil
				}
			}
			return false, nil
		case ".removeLastOccurrence(":
			v, err := evalArg(0)
			if err != nil {
				return false, err
			}
			for i := len(tv) - 1; i >= 0; i-- {
				if painlessValuesEqual(tv[i], v) {
					next := make([]any, 0, len(tv)-1)
					next = append(next, tv[:i]...)
					next = append(next, tv[i+1:]...)
					syncMutatedListExprPainless(recExpr, next, sourceMap, params)
					return true, nil
				}
			}
			return false, nil
		}
	}
	return nil, nil
}

func evalStreamIterateOrGeneratePainless(pfx, argStr string, steps []painlessStreamStep, sourceMap, params map[string]any, depth int) ([]any, error) {
	maxItems := MaxPainlessSliceItems
	skipAccum := 0
	for _, st := range steps {
		if st.name == "skip" {
			if sv, err := evalRHSExprDepth(sourceMap, st.args, params, depth+1); err == nil {
				if sk, ok := toInt64Painless(sv); ok && sk > 0 {
					skipAccum += int(sk)
					continue
				}
			}
			break
		} else if st.name == "limit" {
			if lv, err := evalRHSExprDepth(sourceMap, st.args, params, depth+1); err == nil {
				if lim, ok := toInt64Painless(lv); ok && lim >= 0 && skipAccum+int(lim) < maxItems {
					maxItems = skipAccum + int(lim)
					break
				}
			}
		} else if st.name == "filter" || st.name == "takeWhile" || st.name == "dropWhile" {
			break
		}
	}
	budget := getOrInitEvalBudget(params)
	if strings.HasSuffix(pfx, ".generate(") {
		normSup := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(argStr), 0)
		arrowIdx := findNextUnquotedSubstr(normSup, "->", 0)
		if arrowIdx < 0 {
			return []any{}, nil
		}
		body := normSup[arrowIdx+2:]
		out := make([]any, 0, maxItems)
		for len(out) < maxItems {
			if err := budget.step(); err != nil {
				return nil, err
			}
			v, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	iArgs := splitTopLevelCommaPainless(argStr)
	if len(iArgs) < 2 {
		return []any{}, nil
	}
	seedVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(iArgs[0]), params, depth+1)
	if err != nil {
		return nil, err
	}
	var hasNextExpr, nextExpr string
	if len(iArgs) >= 3 {
		hasNextExpr = normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(iArgs[1]), 1)
		nextExpr = normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(iArgs[2]), 1)
	} else {
		nextExpr = normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(iArgs[1]), 1)
	}
	nextArrow := findNextUnquotedSubstr(nextExpr, "->", 0)
	if nextArrow <= 0 {
		return []any{seedVal}, nil
	}
	nextParams := parsePainlessLambdaHeader(nextExpr[:nextArrow])
	if len(nextParams) == 0 {
		return []any{seedVal}, nil
	}
	nextParam := nextParams[0]
	nextBody := nextExpr[nextArrow+2:]

	var hasNextParam, hasNextBody string
	if hasNextExpr != "" {
		if hnArrow := findNextUnquotedSubstr(hasNextExpr, "->", 0); hnArrow > 0 {
			if hnp := parsePainlessLambdaHeader(hasNextExpr[:hnArrow]); len(hnp) > 0 {
				hasNextParam = hnp[0]
				hasNextBody = hasNextExpr[hnArrow+2:]
			}
		}
	}

	out := make([]any, 0, 16)
	cur := seedVal
	for len(out) < maxItems {
		if err := budget.step(); err != nil {
			return nil, err
		}
		if hasNextParam != "" {
			prevHN, hadHN := params[hasNextParam]
			params[hasNextParam] = cur
			okNext, pErr := evalPainlessPredicateLambda(hasNextBody, sourceMap, params, depth+1)
			if hadHN {
				params[hasNextParam] = prevHN
			} else {
				delete(params, hasNextParam)
			}
			if pErr != nil {
				return nil, pErr
			}
			if !okNext {
				break
			}
		}
		out = append(out, cur)
		if len(out) >= maxItems {
			break
		}
		prevN, hadN := params[nextParam]
		params[nextParam] = cur
		nextVal, nErr := evalPainlessLambdaBody(nextBody, sourceMap, params, depth+1)
		if hadN {
			params[nextParam] = prevN
		} else {
			delete(params, nextParam)
		}
		if nErr != nil {
			return nil, nErr
		}
		cur = nextVal
	}
	return out, nil
}

func evalNumericBitSetJoinerComparatorMethodPainless(mName string, recVal any, argExpr string, sourceMap, params map[string]any, depth int) (any, error) {
	args := splitTopLevelCommaPainless(argExpr)
	evalArg := func(idx int) (any, error) {
		if idx < 0 || idx >= len(args) {
			return nil, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
	}
	// BigDecimal methods
	if bd, ok := recVal.(*painlessBigDecimal); ok && bd != nil && bd.unscaled != nil {
		switch mName {
		case ".subtract(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			res := bd.sub(other)
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				if mc, okMC := a1.(painlessMathContext); okMC {
					return applyMathContextPainless(res, mc)
				}
			}
			return res, nil
		case ".multiply(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			res := bd.mul(other)
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				if mc, okMC := a1.(painlessMathContext); okMC {
					return applyMathContextPainless(res, mc)
				}
			}
			return res, nil
		case ".divide(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			if other.unscaled.Sign() == 0 {
				return nil, fmt.Errorf("ArithmeticException: Division by zero")
			}
			if len(args) == 1 {
				return bd.div(other, bd.scale, "UNNECESSARY")
			}
			a1, err1 := evalArg(1)
			if err1 != nil {
				return nil, err1
			}
			if mc, okMC := a1.(painlessMathContext); okMC {
				return divideBigDecimalWithMathContextPainless(bd, other, mc)
			}
			if len(args) == 2 {
				if modeStr, isStr := a1.(string); isStr {
					return bd.div(other, bd.scale, normalizeRoundingModePainless(modeStr))
				}
				scF, okSc := toFloat64(a1)
				if okSc {
					return bd.div(other, int(scF), "HALF_UP")
				}
			}
			if len(args) >= 3 {
				scF, _ := toFloat64(a1)
				a2, err2 := evalArg(2)
				if err2 != nil {
					return nil, err2
				}
				return bd.div(other, int(scF), normalizeRoundingModePainless(a2))
			}
			return bd.div(other, bd.scale, "HALF_UP")
		case ".remainder(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			if other.unscaled.Sign() == 0 {
				return nil, fmt.Errorf("ArithmeticException: Division by zero")
			}
			_, rem, errD := bd.divideAndRemainder(other)
			if errD != nil {
				return nil, errD
			}
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				if mc, okMC := a1.(painlessMathContext); okMC {
					return applyMathContextPainless(rem, mc)
				}
			}
			return rem, nil
		case ".divideToIntegralValue(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			q, _, errD := bd.divideAndRemainder(other)
			if errD != nil {
				return nil, errD
			}
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				if mc, okMC := a1.(painlessMathContext); okMC {
					return applyMathContextPainless(q, mc)
				}
			}
			return q, nil
		case ".divideAndRemainder(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			q, rem, errD := bd.divideAndRemainder(other)
			if errD != nil {
				return nil, errD
			}
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				if mc, okMC := a1.(painlessMathContext); okMC {
					var errMC error
					q, errMC = applyMathContextPainless(q, mc)
					if errMC != nil {
						return nil, errMC
					}
					rem, errMC = applyMathContextPainless(rem, mc)
					if errMC != nil {
						return nil, errMC
					}
				}
			}
			return []any{q, rem}, nil
		case ".pow(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			nf, okN := toFloat64(a0)
			if !okN {
				return nil, nil
			}
			n := int(nf)
			if n < 0 || n > 999999999 {
				return nil, fmt.Errorf("ArithmeticException: Invalid operation")
			}
			res := &painlessBigDecimal{
				unscaled: new(big.Int).Exp(bd.unscaled, big.NewInt(int64(n)), nil),
				scale:    bd.scale * n,
			}
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				if mc, okMC := a1.(painlessMathContext); okMC {
					return applyMathContextPainless(res, mc)
				}
			}
			return res, nil
		case ".setScale(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			scF, okSc := toFloat64(a0)
			if !okSc {
				return nil, nil
			}
			mode := "UNNECESSARY"
			if len(args) >= 2 {
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				mode = normalizeRoundingModePainless(a1)
			}
			return bd.setScale(int(scF), mode)
		case ".min(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			if bd.cmp(other) <= 0 {
				return bd, nil
			}
			return other, nil
		case ".max(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			other, okO := parsePainlessBigDecimal(a0)
			if !okO {
				return nil, nil
			}
			if bd.cmp(other) >= 0 {
				return bd, nil
			}
			return other, nil
		case ".movePointLeft(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			nf, okN := toFloat64(a0)
			if !okN {
				return nil, nil
			}
			return &painlessBigDecimal{
				unscaled: new(big.Int).Set(bd.unscaled),
				scale:    bd.scale + int(nf),
			}, nil
		case ".movePointRight(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			nf, okN := toFloat64(a0)
			if !okN {
				return nil, nil
			}
			return &painlessBigDecimal{
				unscaled: new(big.Int).Set(bd.unscaled),
				scale:    bd.scale - int(nf),
			}, nil
		case ".scaleByPowerOfTen(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			nf, okN := toFloat64(a0)
			if !okN {
				return nil, nil
			}
			return &painlessBigDecimal{
				unscaled: new(big.Int).Set(bd.unscaled),
				scale:    bd.scale - int(nf),
			}, nil
		case ".round(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if mc, okMC := a0.(painlessMathContext); okMC {
				return applyMathContextPainless(bd, mc)
			}
			return bd, nil
		case ".abs(":
			res := &painlessBigDecimal{unscaled: new(big.Int).Abs(bd.unscaled), scale: bd.scale}
			if len(args) >= 1 && strings.TrimSpace(argExpr) != "" {
				a0, err := evalArg(0)
				if err != nil {
					return nil, err
				}
				if mc, okMC := a0.(painlessMathContext); okMC {
					return applyMathContextPainless(res, mc)
				}
			}
			return res, nil
		case ".negate(":
			res := &painlessBigDecimal{unscaled: new(big.Int).Neg(bd.unscaled), scale: bd.scale}
			if len(args) >= 1 && strings.TrimSpace(argExpr) != "" {
				a0, err := evalArg(0)
				if err != nil {
					return nil, err
				}
				if mc, okMC := a0.(painlessMathContext); okMC {
					return applyMathContextPainless(res, mc)
				}
			}
			return res, nil
		case ".toString(":
			return bd.String(), nil
		}
	}

	// BigInteger methods
	if bi, ok := recVal.(*painlessBigInteger); ok && bi != nil && bi.val != nil {
		switch mName {
		case ".subtract(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				return newPainlessBigInteger(new(big.Int).Sub(bi.val, other.val)), nil
			}
		case ".multiply(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				return newPainlessBigInteger(new(big.Int).Mul(bi.val, other.val)), nil
			}
		case ".divide(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				if other.val.Sign() == 0 {
					return nil, fmt.Errorf("ArithmeticException: BigInteger divide by zero")
				}
				return newPainlessBigInteger(new(big.Int).Quo(bi.val, other.val)), nil
			}
		case ".remainder(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				if other.val.Sign() == 0 {
					return nil, fmt.Errorf("ArithmeticException: BigInteger divide by zero")
				}
				return newPainlessBigInteger(new(big.Int).Rem(bi.val, other.val)), nil
			}
		case ".divideAndRemainder(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				if other.val.Sign() == 0 {
					return nil, fmt.Errorf("ArithmeticException: BigInteger divide by zero")
				}
				q, r := new(big.Int).QuoRem(bi.val, other.val, new(big.Int))
				return []any{newPainlessBigInteger(q), newPainlessBigInteger(r)}, nil
			}
		case ".mod(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				if other.val.Sign() <= 0 {
					return nil, fmt.Errorf("ArithmeticException: BigInteger: modulus not positive")
				}
				return newPainlessBigInteger(new(big.Int).Mod(bi.val, other.val)), nil
			}
		case ".modPow(":
			if len(args) >= 2 {
				a0, err0 := evalArg(0)
				if err0 != nil {
					return nil, err0
				}
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				expBI, okE := parsePainlessBigInteger(a0)
				modBI, okM := parsePainlessBigInteger(a1)
				if okE && okM {
					if modBI.val.Sign() <= 0 {
						return nil, fmt.Errorf("ArithmeticException: BigInteger: modulus not positive")
					}
					if modBI.val.Cmp(big.NewInt(1)) == 0 {
						return newPainlessBigInteger(big.NewInt(0)), nil
					}
					base := new(big.Int).Set(bi.val)
					exp := new(big.Int).Set(expBI.val)
					if exp.Sign() < 0 {
						inv := new(big.Int).ModInverse(base, modBI.val)
						if inv == nil {
							return nil, fmt.Errorf("ArithmeticException: BigInteger not invertible")
						}
						base = inv
						exp.Neg(exp)
					}
					return newPainlessBigInteger(new(big.Int).Exp(base, exp, modBI.val)), nil
				}
			}
		case ".modInverse(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if modBI, okM := parsePainlessBigInteger(a0); okM {
				if modBI.val.Sign() <= 0 {
					return nil, fmt.Errorf("ArithmeticException: BigInteger: modulus not positive")
				}
				if modBI.val.Cmp(big.NewInt(1)) == 0 {
					return newPainlessBigInteger(big.NewInt(0)), nil
				}
				inv := new(big.Int).ModInverse(bi.val, modBI.val)
				if inv == nil {
					return nil, fmt.Errorf("ArithmeticException: BigInteger not invertible")
				}
				return newPainlessBigInteger(inv), nil
			}
		case ".gcd(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				aAbs := new(big.Int).Abs(bi.val)
				bAbs := new(big.Int).Abs(other.val)
				if aAbs.Sign() == 0 {
					return newPainlessBigInteger(bAbs), nil
				}
				if bAbs.Sign() == 0 {
					return newPainlessBigInteger(aAbs), nil
				}
				return newPainlessBigInteger(new(big.Int).GCD(nil, nil, aAbs, bAbs)), nil
			}
		case ".pow(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				exp := int64(nf)
				if exp < 0 {
					return nil, fmt.Errorf("ArithmeticException: Negative exponent")
				}
				return newPainlessBigInteger(new(big.Int).Exp(bi.val, big.NewInt(exp), nil)), nil
			}
		case ".min(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				if bi.val.Cmp(other.val) <= 0 {
					return bi, nil
				}
				return other, nil
			}
		case ".max(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				if bi.val.Cmp(other.val) >= 0 {
					return bi, nil
				}
				return other, nil
			}
		case ".and(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				return newPainlessBigInteger(new(big.Int).And(bi.val, other.val)), nil
			}
		case ".xor(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				return newPainlessBigInteger(new(big.Int).Xor(bi.val, other.val)), nil
			}
		case ".andNot(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := parsePainlessBigInteger(a0); okO {
				return newPainlessBigInteger(new(big.Int).AndNot(bi.val, other.val)), nil
			}
		case ".shiftLeft(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				n := int(nf)
				if n >= 0 {
					return newPainlessBigInteger(new(big.Int).Lsh(bi.val, uint(n))), nil // #nosec G115 -- checked n >= 0
				}
				return newPainlessBigInteger(new(big.Int).Rsh(bi.val, uint(-n))), nil // #nosec G115 -- checked n < 0
			}
		case ".shiftRight(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				n := int(nf)
				if n >= 0 {
					return newPainlessBigInteger(new(big.Int).Rsh(bi.val, uint(n))), nil // #nosec G115 -- checked n >= 0
				}
				return newPainlessBigInteger(new(big.Int).Lsh(bi.val, uint(-n))), nil // #nosec G115 -- checked n < 0
			}
		case ".testBit(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				n := int(nf)
				if n < 0 {
					return nil, fmt.Errorf("ArithmeticException: Negative bit address")
				}
				return bi.val.Bit(n) == 1, nil
			}
		case ".setBit(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				n := int(nf)
				if n < 0 {
					return nil, fmt.Errorf("ArithmeticException: Negative bit address")
				}
				return newPainlessBigInteger(new(big.Int).SetBit(bi.val, n, 1)), nil
			}
		case ".clearBit(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				n := int(nf)
				if n < 0 {
					return nil, fmt.Errorf("ArithmeticException: Negative bit address")
				}
				return newPainlessBigInteger(new(big.Int).SetBit(bi.val, n, 0)), nil
			}
		case ".flipBit(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				n := int(nf)
				if n < 0 {
					return nil, fmt.Errorf("ArithmeticException: Negative bit address")
				}
				b := uint(1)
				if bi.val.Bit(n) == 1 {
					b = 0
				}
				return newPainlessBigInteger(new(big.Int).SetBit(bi.val, n, b)), nil
			}
		case ".isProbablePrime(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				certainty := int(nf)
				if certainty <= 0 {
					return true, nil
				}
				if bi.val.Sign() <= 0 {
					return false, nil
				}
				reps := (certainty + 1) / 2
				if reps < 1 {
					reps = 1
				}
				if reps > 50 {
					reps = 50
				}
				return bi.val.ProbablyPrime(reps), nil
			}
		case ".toString(":
			if strings.TrimSpace(argExpr) == "" {
				return bi.val.String(), nil
			}
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if nf, okN := toFloat64(a0); okN {
				radix := int(nf)
				if radix < 2 || radix > 36 {
					radix = 10
				}
				return bi.val.Text(radix), nil
			}
		}
	}

	// BitSet methods
	if bs, ok := recVal.(*painlessBitSet); ok && bs != nil {
		switch mName {
		case ".and(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := a0.(*painlessBitSet); okO {
				bs.and(other)
				return nil, nil
			}
		case ".xor(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := a0.(*painlessBitSet); okO {
				bs.xor(other)
				return nil, nil
			}
		case ".andNot(":
			a0, err := evalArg(0)
			if err != nil {
				return nil, err
			}
			if other, okO := a0.(*painlessBitSet); okO {
				bs.andNot(other)
				return nil, nil
			}
		case ".clear(":
			if strings.TrimSpace(argExpr) == "" {
				bs.words = nil
				return nil, nil
			}
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			f0, _ := toFloat64(a0)
			if len(args) == 1 {
				if err := bs.clearBit(int(f0)); err != nil {
					return nil, err
				}
				return nil, nil
			}
			a1, err1 := evalArg(1)
			if err1 != nil {
				return nil, err1
			}
			f1, _ := toFloat64(a1)
			if err := bs.setRange(int(f0), int(f1), false); err != nil {
				return nil, err
			}
			return nil, nil
		case ".flip(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			f0, _ := toFloat64(a0)
			if len(args) == 1 {
				if err := bs.flip(int(f0)); err != nil {
					return nil, err
				}
				return nil, nil
			}
			a1, err1 := evalArg(1)
			if err1 != nil {
				return nil, err1
			}
			f1, _ := toFloat64(a1)
			if err := bs.flipRange(int(f0), int(f1)); err != nil {
				return nil, err
			}
			return nil, nil
		case ".nextSetBit(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			f0, _ := toFloat64(a0)
			return bs.nextSetBit(int(f0))
		case ".nextClearBit(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			f0, _ := toFloat64(a0)
			return bs.nextClearBit(int(f0))
		case ".previousSetBit(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			f0, _ := toFloat64(a0)
			return bs.previousSetBit(int(f0))
		case ".previousClearBit(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			f0, _ := toFloat64(a0)
			return bs.previousClearBit(int(f0))
		case ".intersects(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			if other, okO := a0.(*painlessBitSet); okO {
				return bs.intersects(other), nil
			}
			return false, nil
		case ".toString(":
			return bs.String(), nil
		}
	}

	// StringJoiner methods
	if sj, ok := recVal.(*painlessStringJoiner); ok && sj != nil {
		switch mName {
		case ".setEmptyValue(":
			a0, err0 := evalArg(0)
			if err0 != nil {
				return nil, err0
			}
			if a0 == nil {
				return nil, fmt.Errorf("NullPointerException: The empty value must not be null")
			}
			ev := fmt.Sprintf("%v", a0)
			sj.emptyVal = &ev
			return sj, nil
		case ".toString(":
			return sj.String(), nil
		}
	}

	// Comparator methods
	if pc, ok := recVal.(*painlessComparator); ok && pc != nil {
		switch mName {
		case ".thenComparing(", ".thenComparingInt(", ".thenComparingLong(", ".thenComparingDouble(":
			if len(args) == 0 {
				return pc, nil
			}
			arg0Raw := strings.TrimSpace(args[0])
			var nextCmp *painlessComparator
			if len(args) >= 2 {
				cVal, errC := evalArg(1)
				if errC != nil {
					return nil, errC
				}
				var keySubCmp *painlessComparator
				if subC, okSub := cVal.(*painlessComparator); okSub {
					keySubCmp = subC
				} else {
					keySubCmp = &painlessComparator{kind: "lambda", lambdaExpr: strings.TrimSpace(args[1])}
				}
				nextCmp = &painlessComparator{
					kind:    "comparing",
					keyExpr: arg0Raw,
					keyCmp:  keySubCmp,
				}
			} else if mName == ".thenComparing(" {
				// Could be a Comparator object or a key extractor lambda/method ref
				if findTopLevelSubstrPainless(arg0Raw, "->") < 0 && findTopLevelSubstrPainless(arg0Raw, "::") < 0 {
					if v0, err0 := evalArg(0); err0 == nil {
						if subC, okSub := v0.(*painlessComparator); okSub {
							nextCmp = subC
						}
					}
				}
				if nextCmp == nil {
					nextCmp = &painlessComparator{
						kind:    "comparing",
						keyExpr: arg0Raw,
					}
				}
			} else {
				nextCmp = &painlessComparator{
					kind:    "comparing",
					keyExpr: arg0Raw,
				}
			}
			cloned := pc.clone()
			cloned.thenList = append(cloned.thenList, nextCmp)
			return cloned, nil
		case ".compare(":
			if len(args) >= 2 {
				a0, err0 := evalArg(0)
				if err0 != nil {
					return nil, err0
				}
				a1, err1 := evalArg(1)
				if err1 != nil {
					return nil, err1
				}
				cRes, errC := evalComparatorObjectPairPainless(pc, a0, a1, sourceMap, params, depth+1)
				if errC != nil {
					return nil, errC
				}
				return int64(cRes), nil
			}
		}
	}

	if mName == ".toString(" && strings.TrimSpace(argExpr) == "" && recVal != nil {
		return fmt.Sprintf("%v", recVal), nil
	}
	return nil, nil
}

func formatDateLikeReceiverPainless(recVal any, nt time.Time) any {
	if s, ok := recVal.(string); ok {
		switch classifyTemporalStringKindPainless(s) {
		case "YearMonth":
			return fmt.Sprintf("%04d-%02d", nt.Year(), int(nt.Month()))
		case "LocalDate":
			return nt.Format("2006-01-02")
		case "LocalTime":
			return formatLocalTimePainless(nt.Hour(), nt.Minute(), nt.Second(), nt.Nanosecond())
		case "LocalDateTime":
			if nt.Nanosecond() > 0 {
				return nt.Format("2006-01-02T15:04:05.999999999")
			}
			return nt.Format("2006-01-02T15:04:05")
		}
	}
	return nt.Format(time.RFC3339Nano)
}

func setDateComponentClampedPainless(t time.Time, year, month, day int) time.Time {
	maxD := daysInMonthPainless(year, time.Month(month))
	if day > maxD {
		day = maxD
	}
	if day < 1 {
		day = 1
	}
	return time.Date(year, time.Month(month), day, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
}

func evalWithTemporalAdjusterPainless(recVal, adjVal any) (any, error) {
	isDateOnly := false
	isTimeOnly := false
	if s, ok := recVal.(string); ok {
		st := strings.TrimSpace(s)
		if len(st) == 10 && st[4] == '-' && st[7] == '-' {
			isDateOnly = true
		} else if !strings.Contains(st, "-") && strings.Contains(st, ":") {
			isTimeOnly = true
		}
	}
	t, ok := parsePainlessDateTime(recVal)
	if !ok {
		return recVal, nil
	}
	formatResult := func(nt time.Time) any {
		if isDateOnly {
			return nt.Format("2006-01-02")
		}
		if isTimeOnly {
			if nt.Nanosecond() == 0 {
				return nt.Format("15:04:05")
			}
			return nt.Format("15:04:05.999999999")
		}
		return formatDateLikeReceiverPainless(recVal, nt)
	}
	isoDow := func(tm time.Time) int {
		w := int(tm.Weekday())
		if w == 0 {
			return 7
		}
		return w
	}
	daysInMonth := func(year int, month time.Month) int {
		return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	}

	if ta, okTA := adjVal.(*painlessTemporalAdjuster); okTA && ta != nil {
		y, m, d := t.Date()
		hr, min, sec, nsec, loc := t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location()
		switch ta.kind {
		case "firstDayOfMonth":
			return formatResult(time.Date(y, m, 1, hr, min, sec, nsec, loc)), nil
		case "lastDayOfMonth":
			return formatResult(time.Date(y, m, daysInMonth(y, m), hr, min, sec, nsec, loc)), nil
		case "firstDayOfNextMonth":
			return formatResult(time.Date(y, m+1, 1, hr, min, sec, nsec, loc)), nil
		case "firstDayOfYear":
			return formatResult(time.Date(y, time.January, 1, hr, min, sec, nsec, loc)), nil
		case "lastDayOfYear":
			return formatResult(time.Date(y, time.December, 31, hr, min, sec, nsec, loc)), nil
		case "firstDayOfNextYear":
			return formatResult(time.Date(y+1, time.January, 1, hr, min, sec, nsec, loc)), nil
		case "next":
			cur := isoDow(t)
			diff := (ta.dow - cur + 7) % 7
			if diff == 0 {
				diff = 7
			}
			return formatResult(time.Date(y, m, d+diff, hr, min, sec, nsec, loc)), nil
		case "nextOrSame":
			cur := isoDow(t)
			diff := (ta.dow - cur + 7) % 7
			return formatResult(time.Date(y, m, d+diff, hr, min, sec, nsec, loc)), nil
		case "previous":
			cur := isoDow(t)
			diff := (cur - ta.dow + 7) % 7
			if diff == 0 {
				diff = 7
			}
			return formatResult(time.Date(y, m, d-diff, hr, min, sec, nsec, loc)), nil
		case "previousOrSame":
			cur := isoDow(t)
			diff := (cur - ta.dow + 7) % 7
			return formatResult(time.Date(y, m, d-diff, hr, min, sec, nsec, loc)), nil
		case "firstInMonth":
			first := time.Date(y, m, 1, hr, min, sec, nsec, loc)
			diff := (ta.dow - isoDow(first) + 7) % 7
			return formatResult(time.Date(y, m, 1+diff, hr, min, sec, nsec, loc)), nil
		case "lastInMonth":
			lastDay := daysInMonth(y, m)
			last := time.Date(y, m, lastDay, hr, min, sec, nsec, loc)
			diff := (isoDow(last) - ta.dow + 7) % 7
			return formatResult(time.Date(y, m, lastDay-diff, hr, min, sec, nsec, loc)), nil
		case "dayOfWeekInMonth":
			if ta.ordinal > 0 {
				first := time.Date(y, m, 1, hr, min, sec, nsec, loc)
				diff := (ta.dow - isoDow(first) + 7) % 7
				targetDay := 1 + diff + (ta.ordinal-1)*7
				return formatResult(time.Date(y, m, targetDay, hr, min, sec, nsec, loc)), nil
			} else if ta.ordinal == 0 {
				first := time.Date(y, m, 1, hr, min, sec, nsec, loc)
				diff := (ta.dow - isoDow(first) + 7) % 7
				targetDay := 1 + diff - 7
				return formatResult(time.Date(y, m, targetDay, hr, min, sec, nsec, loc)), nil
			} else {
				lastDay := daysInMonth(y, m)
				last := time.Date(y, m, lastDay, hr, min, sec, nsec, loc)
				diff := (isoDow(last) - ta.dow + 7) % 7
				targetDay := lastDay - diff + (ta.ordinal+1)*7
				return formatResult(time.Date(y, m, targetDay, hr, min, sec, nsec, loc)), nil
			}
		}
	}

	if yr, okY := adjVal.(painlessYear); okY {
		return formatResult(setDateComponentClampedPainless(t, int(yr.year), int(t.Month()), t.Day())), nil
	}
	if md, okMD := adjVal.(painlessMonthDay); okMD {
		return formatResult(setDateComponentClampedPainless(t, t.Year(), md.month, md.day)), nil
	}
	if dow, okD := parseDayOfWeekNumberPainless(adjVal); okD {
		cur := isoDow(t)
		return formatResult(time.Date(t.Year(), t.Month(), t.Day()+(dow-cur), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())), nil
	}
	if sAdj, okS := adjVal.(string); okS {
		st := strings.TrimSpace(sAdj)
		switch strings.ToUpper(st) {
		case "JANUARY":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 1, t.Day())), nil
		case "FEBRUARY":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 2, t.Day())), nil
		case "MARCH":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 3, t.Day())), nil
		case "APRIL":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 4, t.Day())), nil
		case "MAY":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 5, t.Day())), nil
		case "JUNE":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 6, t.Day())), nil
		case "JULY":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 7, t.Day())), nil
		case "AUGUST":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 8, t.Day())), nil
		case "SEPTEMBER":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 9, t.Day())), nil
		case "OCTOBER":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 10, t.Day())), nil
		case "NOVEMBER":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 11, t.Day())), nil
		case "DECEMBER":
			return formatResult(setDateComponentClampedPainless(t, t.Year(), 12, t.Day())), nil
		}
		// Check YearMonth "YYYY-MM"
		if len(st) == 7 && st[4] == '-' {
			if ymT, errYM := time.Parse("2006-01", st); errYM == nil {
				return formatResult(setDateComponentClampedPainless(t, ymT.Year(), int(ymT.Month()), t.Day())), nil
			}
		}
		// Check LocalDate "YYYY-MM-DD"
		if len(st) == 10 && st[4] == '-' && st[7] == '-' {
			if ldT, errLD := time.Parse("2006-01-02", st); errLD == nil {
				return formatResult(time.Date(ldT.Year(), ldT.Month(), ldT.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())), nil
			}
		}
		// Check LocalTime "HH:mm..."
		if !strings.Contains(st, "-") && strings.Contains(st, ":") {
			if ltT, okLT := parsePainlessDateTime(st); okLT {
				return formatResult(time.Date(t.Year(), t.Month(), t.Day(), ltT.Hour(), ltT.Minute(), ltT.Second(), ltT.Nanosecond(), t.Location())), nil
			}
		}
	}
	return recVal, nil
}

func parseDayOfWeekNumberPainless(v any) (int, bool) {
	if s, ok := v.(string); ok {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "MONDAY":
			return 1, true
		case "TUESDAY":
			return 2, true
		case "WEDNESDAY":
			return 3, true
		case "THURSDAY":
			return 4, true
		case "FRIDAY":
			return 5, true
		case "SATURDAY":
			return 6, true
		case "SUNDAY":
			return 7, true
		}
	}
	if f, ok := toFloat64(v); ok {
		n := int(f)
		if n >= 1 && n <= 7 {
			return n, true
		}
	}
	return 0, false
}

func evalLocalDateUntilPeriodPainless(recVal, endVal any) painlessPeriod {
	t1, ok1 := parsePainlessDateTime(recVal)
	t2, ok2 := parsePainlessDateTime(endVal)
	if !ok1 || !ok2 {
		return painlessPeriod{}
	}
	totalMonths := (t2.Year()-t1.Year())*12 + int(t2.Month()-t1.Month())
	days := t2.Day() - t1.Day()
	if totalMonths > 0 && days < 0 {
		totalMonths--
		shifted := addMonthsClampedPainless(t1, totalMonths)
		days = int(t2.Sub(shifted).Hours() / 24)
	} else if totalMonths < 0 && days > 0 {
		totalMonths++
		shifted := addMonthsClampedPainless(t1, totalMonths)
		days = -int(shifted.Sub(t2).Hours() / 24)
	}
	return painlessPeriod{
		years:  totalMonths / 12,
		months: totalMonths % 12,
		days:   days,
	}
}

func evalTemporalBetweenUnitPainless(unitVal, v1, v2 any) int64 {
	unit := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", unitVal)))
	unit = strings.TrimPrefix(unit, "CHRONOUNIT.")
	if yr1, okY1 := v1.(painlessYear); okY1 {
		if yr2, okY2 := v2.(painlessYear); okY2 {
			diffY := yr2.year - yr1.year
			switch unit {
			case "YEARS":
				return diffY
			case "DECADES":
				return diffY / 10
			case "CENTURIES":
				return diffY / 100
			case "MILLENNIA":
				return diffY / 1000
			}
		}
	}
	t1, ok1 := parsePainlessDateTime(v1)
	t2, ok2 := parsePainlessDateTime(v2)
	if !ok1 || !ok2 {
		return 0
	}
	switch unit {
	case "NANOS":
		return t2.Sub(t1).Nanoseconds()
	case "MICROS":
		return t2.Sub(t1).Microseconds()
	case "MILLIS":
		return t2.Sub(t1).Milliseconds()
	case "SECONDS":
		return int64(t2.Sub(t1) / time.Second)
	case "MINUTES":
		return int64(t2.Sub(t1) / time.Minute)
	case "HOURS":
		return int64(t2.Sub(t1) / time.Hour)
	case "HALF_DAYS":
		return int64(t2.Sub(t1) / (12 * time.Hour))
	case "DAYS":
		d1 := time.Date(t1.Year(), t1.Month(), t1.Day(), 0, 0, 0, 0, time.UTC)
		d2 := time.Date(t2.Year(), t2.Month(), t2.Day(), 0, 0, 0, 0, time.UTC)
		return int64(d2.Sub(d1).Hours() / 24)
	case "WEEKS":
		d1 := time.Date(t1.Year(), t1.Month(), t1.Day(), 0, 0, 0, 0, time.UTC)
		d2 := time.Date(t2.Year(), t2.Month(), t2.Day(), 0, 0, 0, 0, time.UTC)
		return int64(d2.Sub(d1).Hours() / (24 * 7))
	case "MONTHS", "YEARS", "DECADES", "CENTURIES", "MILLENNIA":
		p := evalLocalDateUntilPeriodPainless(t1, t2)
		totalM := int64(p.years*12 + p.months)
		switch unit {
		case "MONTHS":
			return totalM
		case "YEARS":
			return totalM / 12
		case "DECADES":
			return totalM / 120
		case "CENTURIES":
			return totalM / 1200
		case "MILLENNIA":
			return totalM / 12000
		}
	}
	return 0
}

func evalLocalDateDatesUntilPainless(recVal, endVal, stepVal any) ([]any, error) {
	t1, ok1 := parsePainlessDateTime(recVal)
	t2, ok2 := parsePainlessDateTime(endVal)
	if !ok1 || !ok2 {
		return []any{}, nil
	}
	d1 := time.Date(t1.Year(), t1.Month(), t1.Day(), 0, 0, 0, 0, time.UTC)
	d2 := time.Date(t2.Year(), t2.Month(), t2.Day(), 0, 0, 0, 0, time.UTC)
	if d2.Before(d1) {
		return nil, fmt.Errorf("IllegalArgumentException: %s < %s", d2.Format("2006-01-02"), d1.Format("2006-01-02"))
	}
	const maxDates = 10000
	if stepVal == nil {
		out := []any{}
		for cur := d1; cur.Before(d2) && len(out) < maxDates; cur = cur.AddDate(0, 0, 1) {
			out = append(out, cur.Format("2006-01-02"))
		}
		return out, nil
	}
	var per painlessPeriod
	switch p := stepVal.(type) {
	case painlessPeriod:
		per = p
	case string:
		if parsed, okP := parseISO8601PeriodPainless(p); okP {
			per = parsed
		}
	}
	totalMonths := per.years*12 + per.months
	if (totalMonths == 0 && per.days == 0) || totalMonths < 0 || per.days < 0 {
		return nil, fmt.Errorf("IllegalArgumentException: step is zero or negative")
	}
	out := []any{}
	for stepIdx := 0; len(out) < maxDates; stepIdx++ {
		cur := addMonthsClampedPainless(d1, totalMonths*stepIdx).AddDate(0, 0, per.days*stepIdx)
		if !cur.Before(d2) {
			break
		}
		out = append(out, cur.Format("2006-01-02"))
	}
	return out, nil
}

func evalTemporalAdjustersStaticPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, error) {
	fnName = strings.TrimPrefix(fnName, "TemporalAdjusters.")
	switch fnName {
	case "firstDayOfMonth", "lastDayOfMonth", "firstDayOfNextMonth", "firstDayOfYear", "lastDayOfYear", "firstDayOfNextYear":
		return &painlessTemporalAdjuster{kind: fnName}, nil
	case "next", "nextOrSame", "previous", "previousOrSame", "firstInMonth", "lastInMonth":
		if len(args) < 1 {
			return nil, nil
		}
		v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err0 != nil {
			return nil, err0
		}
		dow, okD := parseDayOfWeekNumberPainless(v0)
		if !okD {
			return nil, nil
		}
		return &painlessTemporalAdjuster{kind: fnName, dow: dow}, nil
	case "dayOfWeekInMonth":
		if len(args) < 2 {
			return nil, nil
		}
		v0, err0 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
		if err0 != nil {
			return nil, err0
		}
		v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if err1 != nil {
			return nil, err1
		}
		ordF, okO := toFloat64(v0)
		dow, okD := parseDayOfWeekNumberPainless(v1)
		if !okO || !okD {
			return nil, nil
		}
		return &painlessTemporalAdjuster{kind: fnName, ordinal: int(ordF), dow: dow}, nil
	}
	return nil, nil
}

func evalComparatorStaticPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, error) {
	fnName = strings.TrimPrefix(strings.TrimPrefix(fnName, "Comparator."), "Collections.")
	switch fnName {
	case "naturalOrder":
		return &painlessComparator{kind: "natural"}, nil
	case "reverseOrder":
		return &painlessComparator{kind: "reverse"}, nil
	case "nullsFirst", "nullsLast":
		var inner *painlessComparator
		if len(args) >= 1 && strings.TrimSpace(args[0]) != "" {
			arg0Raw := strings.TrimSpace(args[0])
			if v0, err0 := evalRHSExprDepth(sourceMap, arg0Raw, params, depth+1); err0 == nil {
				if subC, okSub := v0.(*painlessComparator); okSub {
					inner = subC
				}
			}
			if inner == nil && arg0Raw != "null" {
				inner = &painlessComparator{kind: "lambda", lambdaExpr: arg0Raw}
			}
		}
		return &painlessComparator{kind: fnName, inner: inner}, nil
	case "comparing", "comparingInt", "comparingLong", "comparingDouble":
		if len(args) < 1 {
			return &painlessComparator{kind: "natural"}, nil
		}
		keyExpr := strings.TrimSpace(args[0])
		var keyCmp *painlessComparator
		if len(args) >= 2 {
			arg1Raw := strings.TrimSpace(args[1])
			if v1, err1 := evalRHSExprDepth(sourceMap, arg1Raw, params, depth+1); err1 == nil {
				if subC, okSub := v1.(*painlessComparator); okSub {
					keyCmp = subC
				}
			}
			if keyCmp == nil && arg1Raw != "null" {
				keyCmp = &painlessComparator{kind: "lambda", lambdaExpr: arg1Raw}
			}
		}
		return &painlessComparator{
			kind:    "comparing",
			keyExpr: keyExpr,
			keyCmp:  keyCmp,
		}, nil
	}
	return nil, nil
}

func evalComparatorKeyExtractPainless(keyExpr string, item any, sourceMap, params map[string]any, depth int) (any, error) {
	keyFn := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(keyExpr), 1)
	if arrowIdx := findNextUnquotedSubstr(keyFn, "->", 0); arrowIdx > 0 {
		pNames := parsePainlessLambdaHeader(keyFn[:arrowIdx])
		if len(pNames) > 0 {
			pName := pNames[0]
			body := strings.TrimSpace(keyFn[arrowIdx+2:])
			prev, hadPrev := params[pName]
			params[pName] = item
			kv, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
			if hadPrev {
				params[pName] = prev
			} else {
				delete(params, pName)
			}
			return kv, err
		}
	}
	return item, nil
}

func evalComparatorObjectPairPainless(pc *painlessComparator, a, b any, sourceMap, params map[string]any, depth int) (int, error) {
	if pc == nil {
		return comparePainlessValues(a, b), nil
	}
	var c int
	switch pc.kind {
	case "natural":
		if a == nil || b == nil {
			return 0, fmt.Errorf("NullPointerException: Cannot compare null with naturalOrder")
		}
		c = comparePainlessValues(a, b)
	case "reverse":
		if a == nil || b == nil {
			return 0, fmt.Errorf("NullPointerException: Cannot compare null with reverseOrder")
		}
		c = -comparePainlessValues(a, b)
	case "caseInsensitive":
		if a == nil || b == nil {
			return 0, fmt.Errorf("NullPointerException: Cannot compare null with CASE_INSENSITIVE_ORDER")
		}
		sa := strings.ToLower(fmt.Sprintf("%v", a))
		sb := strings.ToLower(fmt.Sprintf("%v", b))
		if sa < sb {
			c = -1
		} else if sa > sb {
			c = 1
		}
	case "nullsFirst":
		if a == nil && b == nil {
			c = 0
		} else if a == nil {
			return -1, nil
		} else if b == nil {
			return 1, nil
		} else if pc.inner != nil {
			var err error
			c, err = evalComparatorObjectPairPainless(pc.inner, a, b, sourceMap, params, depth+1)
			if err != nil {
				return 0, err
			}
		}
	case "nullsLast":
		if a == nil && b == nil {
			c = 0
		} else if a == nil {
			return 1, nil
		} else if b == nil {
			return -1, nil
		} else if pc.inner != nil {
			var err error
			c, err = evalComparatorObjectPairPainless(pc.inner, a, b, sourceMap, params, depth+1)
			if err != nil {
				return 0, err
			}
		}
	case "comparing":
		ka, errA := evalComparatorKeyExtractPainless(pc.keyExpr, a, sourceMap, params, depth+1)
		if errA != nil {
			return 0, errA
		}
		kb, errB := evalComparatorKeyExtractPainless(pc.keyExpr, b, sourceMap, params, depth+1)
		if errB != nil {
			return 0, errB
		}
		if pc.keyCmp != nil {
			var errK error
			c, errK = evalComparatorObjectPairPainless(pc.keyCmp, ka, kb, sourceMap, params, depth+1)
			if errK != nil {
				return 0, errK
			}
		} else {
			c = comparePainlessValues(ka, kb)
		}
	case "lambda":
		var errL error
		c, errL = evalPainlessComparatorPair(pc.lambdaExpr, a, b, sourceMap, params, depth+1)
		if errL != nil {
			return 0, errL
		}
	default:
		c = comparePainlessValues(a, b)
	}
	if pc.reversed {
		c = -c
	}
	if c != 0 {
		return c, nil
	}
	for _, nextCmp := range pc.thenList {
		nc, errN := evalComparatorObjectPairPainless(nextCmp, a, b, sourceMap, params, depth+1)
		if errN != nil {
			return 0, errN
		}
		if nc != 0 {
			return nc, nil
		}
	}
	return 0, nil
}

func evalCharacterStaticPainless(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, error) {
	fnName = strings.TrimPrefix(fnName, "Character.")
	evalArg := func(idx int) (any, error) {
		if idx < 0 || idx >= len(args) {
			return nil, nil
		}
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
	}
	toCodePoint := func(v any) (int32, bool) {
		if s, ok := v.(string); ok {
			rs := []rune(s)
			if len(rs) == 1 {
				return rs[0], true
			}
			// UTF-16 code unit if surrogate
			u16 := utf16.Encode(rs)
			if len(u16) == 1 {
				return int32(u16[0]), true
			}
		}
		if f, ok := toFloat64(v); ok {
			return int32(f), true // #nosec G115 -- code point fits int32
		}
		return 0, false
	}
	a0, err0 := evalArg(0)
	if err0 != nil {
		return nil, err0
	}
	switch fnName {
	case "charCount":
		cp, ok := toCodePoint(a0)
		if !ok {
			return nil, nil
		}
		if cp >= 0x10000 {
			return int64(2), nil
		}
		return int64(1), nil
	case "toChars":
		cp, ok := toCodePoint(a0)
		if !ok {
			return nil, nil
		}
		if cp < 0 || cp > 0x10FFFF {
			return nil, fmt.Errorf("IllegalArgumentException: Not a valid Unicode code point: 0x%X", cp)
		}
		if cp < 0x10000 {
			return []any{string(rune(cp))}, nil
		}
		r1, r2 := utf16.EncodeRune(rune(cp))
		return []any{fmt.Sprintf("\\u%04x", uint16(r1)), fmt.Sprintf("\\u%04x", uint16(r2))}, nil // #nosec G115 -- surrogate fits uint16
	case "toString", "valueOf":
		cp, ok := toCodePoint(a0)
		if !ok {
			return fmt.Sprintf("%v", a0), nil
		}
		if cp < 0 || cp > 0x10FFFF {
			return nil, fmt.Errorf("IllegalArgumentException: Not a valid Unicode code point: 0x%X", cp)
		}
		return string(rune(cp)), nil
	case "isValidCodePoint":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		return cp >= 0 && cp <= 0x10FFFF, nil
	case "isBmpCodePoint":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		return cp >= 0 && cp <= 0xFFFF, nil
	case "isSupplementaryCodePoint":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		return cp >= 0x10000 && cp <= 0x10FFFF, nil
	case "isHighSurrogate":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		return cp >= 0xD800 && cp <= 0xDBFF, nil
	case "isLowSurrogate":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		return cp >= 0xDC00 && cp <= 0xDFFF, nil
	case "isSurrogate":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		return cp >= 0xD800 && cp <= 0xDFFF, nil
	case "isSurrogatePair":
		if len(args) < 2 {
			return false, nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		hi, okH := toCodePoint(a0)
		lo, okL := toCodePoint(a1)
		if !okH || !okL {
			return false, nil
		}
		return hi >= 0xD800 && hi <= 0xDBFF && lo >= 0xDC00 && lo <= 0xDFFF, nil
	case "toCodePoint":
		if len(args) < 2 {
			return int64(0), nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		hi, okH := toCodePoint(a0)
		lo, okL := toCodePoint(a1)
		if !okH || !okL {
			return int64(0), nil
		}
		return int64(utf16.DecodeRune(rune(hi), rune(lo))), nil
	case "codePointAt":
		if len(args) < 2 {
			return int64(0), nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		idxF, _ := toFloat64(a1)
		idx := int(idxF)
		u16 := utf16.Encode([]rune(fmt.Sprintf("%v", a0)))
		if idx < 0 || idx >= len(u16) {
			return nil, fmt.Errorf("StringIndexOutOfBoundsException: index %d, length %d", idx, len(u16))
		}
		c1 := u16[idx]
		if c1 >= 0xD800 && c1 <= 0xDBFF && idx+1 < len(u16) {
			c2 := u16[idx+1]
			if c2 >= 0xDC00 && c2 <= 0xDFFF {
				return int64(utf16.DecodeRune(rune(c1), rune(c2))), nil
			}
		}
		return int64(c1), nil
	case "codePointBefore":
		if len(args) < 2 {
			return int64(0), nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		idxF, _ := toFloat64(a1)
		idx := int(idxF)
		u16 := utf16.Encode([]rune(fmt.Sprintf("%v", a0)))
		if idx <= 0 || idx > len(u16) {
			return nil, fmt.Errorf("StringIndexOutOfBoundsException: index %d, length %d", idx, len(u16))
		}
		c2 := u16[idx-1]
		if c2 >= 0xDC00 && c2 <= 0xDFFF && idx-2 >= 0 {
			c1 := u16[idx-2]
			if c1 >= 0xD800 && c1 <= 0xDBFF {
				return int64(utf16.DecodeRune(rune(c1), rune(c2))), nil
			}
		}
		return int64(c2), nil
	case "codePointCount":
		if len(args) < 3 {
			return int64(0), nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		a2, err2 := evalArg(2)
		if err2 != nil {
			return nil, err2
		}
		bF, _ := toFloat64(a1)
		eF, _ := toFloat64(a2)
		beginIdx, endIdx := int(bF), int(eF)
		u16 := utf16.Encode([]rune(fmt.Sprintf("%v", a0)))
		if beginIdx < 0 || endIdx > len(u16) || beginIdx > endIdx {
			return nil, fmt.Errorf("IndexOutOfBoundsException: beginIndex %d, endIndex %d, length %d", beginIdx, endIdx, len(u16))
		}
		n := endIdx - beginIdx
		for i := beginIdx; i < endIdx; {
			if u16[i] >= 0xD800 && u16[i] <= 0xDBFF {
				i++
				if i < endIdx && u16[i] >= 0xDC00 && u16[i] <= 0xDFFF {
					n--
					i++
				}
			} else {
				i++
			}
		}
		return int64(n), nil
	case "getNumericValue":
		cp, ok := toCodePoint(a0)
		if !ok {
			return int64(-1), nil
		}
		r := rune(cp)
		if r >= '0' && r <= '9' {
			return int64(r - '0'), nil
		}
		if r >= 'a' && r <= 'z' {
			return int64(r - 'a' + 10), nil
		}
		if r >= 'A' && r <= 'Z' {
			return int64(r - 'A' + 10), nil
		}
		if r >= 0xFF10 && r <= 0xFF19 {
			return int64(r - 0xFF10), nil
		}
		if r >= 0xFF21 && r <= 0xFF3A {
			return int64(r - 0xFF21 + 10), nil
		}
		if r >= 0xFF41 && r <= 0xFF5A {
			return int64(r - 0xFF41 + 10), nil
		}
		if r >= 0x0660 && r <= 0x0669 {
			return int64(r - 0x0660), nil
		}
		if unicode.IsNumber(r) {
			return int64(-2), nil
		}
		return int64(-1), nil
	case "getType":
		cp, ok := toCodePoint(a0)
		if !ok {
			return int64(0), nil
		}
		r := rune(cp)
		switch {
		case unicode.Is(unicode.Lu, r):
			return int64(1), nil // UPPERCASE_LETTER
		case unicode.Is(unicode.Ll, r):
			return int64(2), nil // LOWERCASE_LETTER
		case unicode.Is(unicode.Lt, r):
			return int64(3), nil // TITLECASE_LETTER
		case unicode.Is(unicode.Lm, r):
			return int64(4), nil // MODIFIER_LETTER
		case unicode.Is(unicode.Lo, r):
			return int64(5), nil // OTHER_LETTER
		case unicode.Is(unicode.Mn, r):
			return int64(6), nil // NON_SPACING_MARK
		case unicode.Is(unicode.Me, r):
			return int64(7), nil // ENCLOSING_MARK
		case unicode.Is(unicode.Mc, r):
			return int64(8), nil // COMBINING_SPACING_MARK
		case unicode.Is(unicode.Nd, r):
			return int64(9), nil // DECIMAL_DIGIT_NUMBER
		case unicode.Is(unicode.Nl, r):
			return int64(10), nil // LETTER_NUMBER
		case unicode.Is(unicode.No, r):
			return int64(11), nil // OTHER_NUMBER
		case unicode.Is(unicode.Zs, r):
			return int64(12), nil // SPACE_SEPARATOR
		case unicode.Is(unicode.Zl, r):
			return int64(13), nil // LINE_SEPARATOR
		case unicode.Is(unicode.Zp, r):
			return int64(14), nil // PARAGRAPH_SEPARATOR
		case unicode.Is(unicode.Cc, r):
			return int64(15), nil // CONTROL
		case unicode.Is(unicode.Cf, r):
			return int64(16), nil // FORMAT
		case unicode.Is(unicode.Co, r):
			return int64(18), nil // PRIVATE_USE
		case unicode.Is(unicode.Cs, r):
			return int64(19), nil // SURROGATE
		case unicode.Is(unicode.Pd, r):
			return int64(20), nil // DASH_PUNCTUATION
		case unicode.Is(unicode.Ps, r):
			return int64(21), nil // START_PUNCTUATION
		case unicode.Is(unicode.Pe, r):
			return int64(22), nil // END_PUNCTUATION
		case unicode.Is(unicode.Pc, r):
			return int64(23), nil // CONNECTOR_PUNCTUATION
		case unicode.Is(unicode.Po, r):
			return int64(24), nil // OTHER_PUNCTUATION
		case unicode.Is(unicode.Sm, r):
			return int64(25), nil // MATH_SYMBOL
		case unicode.Is(unicode.Sc, r):
			return int64(26), nil // CURRENCY_SYMBOL
		case unicode.Is(unicode.Sk, r):
			return int64(27), nil // MODIFIER_SYMBOL
		case unicode.Is(unicode.So, r):
			return int64(28), nil // OTHER_SYMBOL
		case unicode.Is(unicode.Pi, r):
			return int64(29), nil // INITIAL_QUOTE_PUNCTUATION
		case unicode.Is(unicode.Pf, r):
			return int64(30), nil // FINAL_QUOTE_PUNCTUATION
		default:
			return int64(0), nil // UNASSIGNED
		}
	case "compare":
		if len(args) < 2 {
			return int64(0), nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		c1, _ := toCodePoint(a0)
		c2, _ := toCodePoint(a1)
		return int64(c1 - c2), nil
	case "isDigit":
		cp, ok := toCodePoint(a0)
		return ok && unicode.IsDigit(rune(cp)), nil
	case "isLetter":
		cp, ok := toCodePoint(a0)
		return ok && unicode.IsLetter(rune(cp)), nil
	case "isLetterOrDigit":
		cp, ok := toCodePoint(a0)
		return ok && (unicode.IsLetter(rune(cp)) || unicode.IsDigit(rune(cp))), nil
	case "isAlphabetic":
		cp, ok := toCodePoint(a0)
		return ok && (unicode.IsLetter(rune(cp)) || unicode.Is(unicode.Nl, rune(cp)) || unicode.Is(unicode.Other_Alphabetic, rune(cp))), nil
	case "isWhitespace":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		r := rune(cp)
		if r == 0x00A0 || r == 0x2007 || r == 0x202F {
			return false, nil
		}
		return unicode.IsSpace(r) || r == 0x001C || r == 0x001D || r == 0x001E || r == 0x001F, nil
	case "isSpaceChar":
		cp, ok := toCodePoint(a0)
		return ok && (unicode.Is(unicode.Zs, rune(cp)) || unicode.Is(unicode.Zl, rune(cp)) || unicode.Is(unicode.Zp, rune(cp))), nil
	case "isUpperCase":
		cp, ok := toCodePoint(a0)
		return ok && unicode.IsUpper(rune(cp)), nil
	case "isLowerCase":
		cp, ok := toCodePoint(a0)
		return ok && unicode.IsLower(rune(cp)), nil
	case "isTitleCase":
		cp, ok := toCodePoint(a0)
		return ok && unicode.IsTitle(rune(cp)), nil
	case "toUpperCase":
		cp, ok := toCodePoint(a0)
		if !ok {
			return a0, nil
		}
		if _, isStr := a0.(string); isStr {
			return string(unicode.ToUpper(rune(cp))), nil
		}
		return int64(unicode.ToUpper(rune(cp))), nil
	case "toLowerCase":
		cp, ok := toCodePoint(a0)
		if !ok {
			return a0, nil
		}
		if _, isStr := a0.(string); isStr {
			return string(unicode.ToLower(rune(cp))), nil
		}
		return int64(unicode.ToLower(rune(cp))), nil
	case "toTitleCase":
		cp, ok := toCodePoint(a0)
		if !ok {
			return a0, nil
		}
		if _, isStr := a0.(string); isStr {
			return string(unicode.ToTitle(rune(cp))), nil
		}
		return int64(unicode.ToTitle(rune(cp))), nil
	case "isIdeographic":
		cp, ok := toCodePoint(a0)
		return ok && unicode.Is(unicode.Ideographic, rune(cp)), nil
	case "isJavaIdentifierStart":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		r := rune(cp)
		return unicode.IsLetter(r) || unicode.Is(unicode.Nl, r) || unicode.Is(unicode.Sc, r) || unicode.Is(unicode.Pc, r), nil
	case "isJavaIdentifierPart":
		cp, ok := toCodePoint(a0)
		if !ok {
			return false, nil
		}
		r := rune(cp)
		return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Nl, r) ||
			unicode.Is(unicode.Sc, r) || unicode.Is(unicode.Pc, r) || unicode.Is(unicode.Mc, r) ||
			unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) ||
			(r >= 0x0000 && r <= 0x0008) || (r >= 0x000E && r <= 0x001B) || (r >= 0x007F && r <= 0x009F), nil
	case "isISOControl":
		cp, ok := toCodePoint(a0)
		return ok && ((cp >= 0x0000 && cp <= 0x001F) || (cp >= 0x007F && cp <= 0x009F)), nil
	case "isDefined":
		cp, ok := toCodePoint(a0)
		return ok && cp >= 0 && cp <= 0x10FFFF && !unicode.Is(unicode.Co, rune(cp)), nil
	case "digit":
		if len(args) < 2 {
			return int64(-1), nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		cp, ok := toCodePoint(a0)
		rf, okR := toFloat64(a1)
		if !ok || !okR {
			return int64(-1), nil
		}
		radix := int32(rf) // #nosec G115 -- radix fits int32
		if radix < 2 || radix > 36 {
			return int64(-1), nil
		}
		var d int32 = -1
		switch {
		case cp >= '0' && cp <= '9':
			d = cp - '0'
		case cp >= 'a' && cp <= 'z':
			d = cp - 'a' + 10
		case cp >= 'A' && cp <= 'Z':
			d = cp - 'A' + 10
		}
		if d >= 0 && d < radix {
			return int64(d), nil
		}
		return int64(-1), nil
	case "forDigit":
		if len(args) < 2 {
			return "\x00", nil
		}
		a1, err1 := evalArg(1)
		if err1 != nil {
			return nil, err1
		}
		df, okD := toFloat64(a0)
		rf, okR := toFloat64(a1)
		if !okD || !okR {
			return "\x00", nil
		}
		d, radix := int(df), int(rf)
		if d < 0 || d >= radix || radix < 2 || radix > 36 {
			return "\x00", nil
		}
		if d < 10 {
			return string(rune('0' + d)), nil // #nosec G115 -- d bounded to [0, 9]
		}
		return string(rune('a' + d - 10)), nil // #nosec G115 -- d bounded to [10, 35]
	case "reverseBytes":
		cp, ok := toCodePoint(a0)
		if !ok {
			return int64(0), nil
		}
		u := uint16(cp) // #nosec G115 -- char is 16-bit
		rev := (u >> 8) | (u << 8)
		return int64(rev), nil
	}
	return nil, nil
}

func evalArraysCompareOrMismatchPainless(args []string, isMismatch bool, sourceMap, params map[string]any, depth int) (int64, error) {
	if len(args) < 2 {
		return 0, nil
	}
	evalArg := func(idx int) (any, error) {
		return evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
	}
	v0, err0 := evalArg(0)
	if err0 != nil {
		return 0, err0
	}
	var aSlice, bSlice []any
	var cmpArg string
	var cmpObj *painlessComparator
	if len(args) >= 6 {
		// Range overload: (a, aFromIndex, aToIndex, b, bFromIndex, bToIndex[, cmp])
		aFull, okA := v0.([]any)
		if !okA {
			return 0, fmt.Errorf("NullPointerException: array is null")
		}
		afV, err := evalArg(1)
		if err != nil {
			return 0, err
		}
		atV, err := evalArg(2)
		if err != nil {
			return 0, err
		}
		v3, err := evalArg(3)
		if err != nil {
			return 0, err
		}
		bFull, okB := v3.([]any)
		if !okB {
			return 0, fmt.Errorf("NullPointerException: array is null")
		}
		bfV, err := evalArg(4)
		if err != nil {
			return 0, err
		}
		btV, err := evalArg(5)
		if err != nil {
			return 0, err
		}
		afF, _ := toFloat64(afV)
		atF, _ := toFloat64(atV)
		bfF, _ := toFloat64(bfV)
		btF, _ := toFloat64(btV)
		af, at, bf, bt := int(afF), int(atF), int(bfF), int(btF)
		if af > at || bf > bt {
			return 0, fmt.Errorf("IllegalArgumentException: fromIndex > toIndex")
		}
		if af < 0 || at > len(aFull) || bf < 0 || bt > len(bFull) {
			return 0, fmt.Errorf("ArrayIndexOutOfBoundsException: range out of bounds")
		}
		aSlice = aFull[af:at]
		bSlice = bFull[bf:bt]
		if len(args) >= 7 {
			cmpArg = strings.TrimSpace(args[6])
			if cv, errC := evalArg(6); errC == nil {
				if pc, okPC := cv.(*painlessComparator); okPC {
					cmpObj = pc
				}
			}
		}
	} else {
		v1, err1 := evalArg(1)
		if err1 != nil {
			return 0, err1
		}
		if v0 == nil && v1 == nil {
			if isMismatch {
				return -1, nil
			}
			return 0, nil
		}
		if v0 == nil {
			if isMismatch {
				return 0, fmt.Errorf("NullPointerException: Cannot read the array length because \"a\" is null")
			}
			return -1, nil
		}
		if v1 == nil {
			if isMismatch {
				return 0, fmt.Errorf("NullPointerException: Cannot read the array length because \"b\" is null")
			}
			return 1, nil
		}
		aOk, okA := v0.([]any)
		bOk, okB := v1.([]any)
		if !okA || !okB {
			return 0, nil
		}
		aSlice = aOk
		bSlice = bOk
		if len(args) >= 3 {
			cmpArg = strings.TrimSpace(args[2])
			if cv, errC := evalArg(2); errC == nil {
				if pc, okPC := cv.(*painlessComparator); okPC {
					cmpObj = pc
				}
			}
		}
	}

	minLen := len(aSlice)
	if len(bSlice) < minLen {
		minLen = len(bSlice)
	}
	for i := 0; i < minLen; i++ {
		var c int
		var errC error
		if cmpObj != nil {
			c, errC = evalComparatorObjectPairPainless(cmpObj, aSlice[i], bSlice[i], sourceMap, params, depth+1)
		} else if cmpArg != "" && cmpArg != "null" {
			c, errC = evalPainlessComparatorPair(cmpArg, aSlice[i], bSlice[i], sourceMap, params, depth+1)
		} else {
			c = comparePainlessValues(aSlice[i], bSlice[i])
		}
		if errC != nil {
			return 0, errC
		}
		if c != 0 {
			if isMismatch {
				return int64(i), nil
			}
			if c < 0 {
				return -1, nil
			}
			return 1, nil
		}
	}
	if len(aSlice) == len(bSlice) {
		if isMismatch {
			return -1, nil
		}
		return 0, nil
	}
	if isMismatch {
		return int64(minLen), nil
	}
	if len(aSlice) < len(bSlice) {
		return -1, nil
	}
	return 1, nil
}

func instantiateUserClassPainless(cls *painlessUserClass, argStr string, sourceMap, params map[string]any, depth int) (*painlessUserObject, error) {
	uo := &painlessUserObject{
		class:  cls,
		fields: make(map[string]any, len(cls.fields)),
	}
	localScope := make(map[string]any, len(params)+len(cls.fields)+4)
	for k, v := range params {
		localScope[k] = v
	}
	localScope["this"] = uo
	// Initialize fields with defaults
	for _, f := range cls.fields {
		if f.initExpr != "" {
			val, err := evalRHSExprDepth(sourceMap, f.initExpr, localScope, depth+1)
			if err != nil {
				return nil, err
			}
			uo.fields[f.name] = val
		} else {
			switch f.typeName {
			case "int", "long", "short", "byte":
				uo.fields[f.name] = int64(0)
			case "double", "float":
				uo.fields[f.name] = float64(0)
			case "boolean":
				uo.fields[f.name] = false
			default:
				uo.fields[f.name] = nil
			}
		}
	}
	// Evaluate constructor arguments
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
	// Find matching constructor by arity
	var matchedCtor *painlessUserFunc
	for _, ctor := range cls.constructors {
		if len(ctor.paramNames) == len(argVals) {
			matchedCtor = ctor
			break
		}
	}
	if matchedCtor != nil {
		budget := getOrInitEvalBudget(params)
		ctorScope := make(map[string]any, len(params)+len(matchedCtor.paramNames)+4)
		for k, v := range params {
			ctorScope[k] = v
		}
		ctorScope["this"] = uo
		methodParams := make(map[string]bool, len(matchedCtor.paramNames))
		for i, pName := range matchedCtor.paramNames {
			ctorScope[pName] = argVals[i]
			methodParams[pName] = true
		}
		ctorScope["__method_params"] = methodParams
		ctorScope["__script_locals"] = make(map[string]bool)
		ctxOp := ""
		if err := execBlock(sourceMap, matchedCtor.body, ctorScope, &ctxOp, budget); err != nil && !errors.Is(err, errPainlessReturn) {
			return nil, err
		}
	}
	return uo, nil
}

func evalTrailingUserObjectMethodCallPainless(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	if !strings.HasSuffix(rhs, ")") {
		return nil, false, nil
	}
	openIdx := -1
	inQuotes := byte(0)
	inRegexClass := false
	for i := 0; i < len(rhs)-1; i++ {
		if stepQuoteState(rhs, i, &inQuotes, &inRegexClass) {
			continue
		}
		if rhs[i] == '(' && findMatchingDelimiter(rhs, i, '(', ')') == len(rhs)-1 {
			openIdx = i
			break
		}
	}
	if openIdx <= 0 {
		return nil, false, nil
	}
	prefix := strings.TrimSpace(rhs[:openIdx])
	dotIdx := -1
	pDepth := 0
	pQuotes := byte(0)
	pRegex := false
	for i := 0; i < len(prefix); i++ {
		if stepQuoteState(prefix, i, &pQuotes, &pRegex) {
			continue
		}
		switch prefix[i] {
		case '(', '[', '{':
			pDepth++
		case ')', ']', '}':
			if pDepth > 0 {
				pDepth--
			}
		case '.':
			if pDepth == 0 {
				dotIdx = i
			}
		}
	}
	if dotIdx <= 0 {
		return nil, false, nil
	}
	recExpr := strings.TrimSpace(strings.TrimSuffix(prefix[:dotIdx], "?"))
	methodName := strings.TrimSpace(prefix[dotIdx+1:])
	if methodName == "" {
		return nil, false, nil
	}
	for i := 0; i < len(methodName); i++ {
		if !isIdentByte(methodName[i]) {
			return nil, false, nil
		}
	}
	recVal, err := evalRHSExprDepth(sourceMap, recExpr, params, depth+1)
	if err != nil {
		return nil, false, nil
	}
	uo, ok := recVal.(*painlessUserObject)
	if !ok || uo == nil || uo.class == nil {
		return nil, false, nil
	}
	if len(uo.class.methods[methodName]) == 0 {
		return nil, false, nil
	}
	argStr := strings.TrimSpace(rhs[openIdx+1 : len(rhs)-1])
	res, errM := evalUserObjectMethodPainless(uo, methodName, argStr, sourceMap, params, depth+1)
	return res, true, errM
}

func evalUserObjectMethodPainless(uo *painlessUserObject, methodName, argStr string, sourceMap, params map[string]any, depth int) (any, error) {
	if uo == nil || uo.class == nil {
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
	var fn *painlessUserFunc
	if overloads := uo.class.methods[methodName]; len(overloads) > 0 {
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
	mScope["this"] = uo
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
