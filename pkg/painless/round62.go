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
	"container/list"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DenseVectorMissingMessage matches Elasticsearch 8's exact exception message
	// when accessing `.vector`, `.dims`, `.magnitude`, or similarity methods on an
	// empty `DenseVector` returned by `field('vec').get()`.
	DenseVectorMissingMessage = "Dense vector value missing for a field, use isEmpty() to check for a missing vector value"

	// DenseVectorIterateErrorMessage matches Elasticsearch 8's exact exception message
	// when iterating over a `DenseVectorField` (`for (def v : field('vec'))`).
	DenseVectorIterateErrorMessage = "Cannot iterate over single valued dense_vector field, use get() instead"

	// MaxGrokDissectCacheCapacity bounds the global compiled Grok and Dissect caches.
	MaxGrokDissectCacheCapacity = 512
)

// DenseVectorDocValue aliases DenseVectorVal for callers inspecting `field('vec').get()` doc values.
type DenseVectorDocValue = DenseVectorVal

// ============================================================================
// Round 62 Deliverable 2: `DayOfWeekEnum` & `MonthEnum` Display Names + Locales
// ============================================================================

// MonthEnum models `java.time.Month` (January=1 .. December=12).
type MonthEnum struct {
	Value   int64
	NameStr string
}

var isoMonthNamesUpper = [13]string{
	"",
	"JANUARY", "FEBRUARY", "MARCH", "APRIL", "MAY", "JUNE",
	"JULY", "AUGUST", "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER",
}

func newMonthEnumRound62(m time.Month) MonthEnum {
	idx := int64(m)
	if idx < 1 || idx > 12 {
		idx = 1
	}
	return MonthEnum{
		Value:   idx,
		NameStr: isoMonthNamesUpper[idx],
	}
}

func parseMonthEnumReceiverRound62(v any) (MonthEnum, bool, bool) {
	switch tv := v.(type) {
	case MonthEnum:
		if tv.Value >= 1 && tv.Value <= 12 {
			return newMonthEnumRound62(time.Month(tv.Value)), false, true
		}
	case *MonthEnum:
		if tv != nil && tv.Value >= 1 && tv.Value <= 12 {
			return newMonthEnumRound62(time.Month(tv.Value)), false, true
		}
	case string:
		if idx := parseMonthIndexPainless(tv); idx >= 1 && idx <= 12 && strings.EqualFold(strings.TrimSpace(tv), isoMonthNamesUpper[idx]) {
			return newMonthEnumRound62(time.Month(idx)), true, true
		}
	}
	return MonthEnum{}, false, false
}

func parseDayOfWeekEnumReceiverRound62(v any) (DayOfWeekEnum, bool, bool) {
	switch tv := v.(type) {
	case DayOfWeekEnum:
		if tv.Value >= 1 && tv.Value <= 7 {
			return newDayOfWeekEnumFromIndexRound62(tv.Value), false, true
		}
	case *DayOfWeekEnum:
		if tv != nil && tv.Value >= 1 && tv.Value <= 7 {
			return newDayOfWeekEnumFromIndexRound62(tv.Value), false, true
		}
	case string:
		if idx := parseDayOfWeekIndexPainless(tv); idx >= 1 && idx <= 7 && strings.EqualFold(strings.TrimSpace(tv), dayOfWeekNamePainless(idx)) {
			return newDayOfWeekEnumFromIndexRound62(int64(idx)), true, true
		}
	}
	return DayOfWeekEnum{}, false, false
}

func newDayOfWeekEnumFromIndexRound62(idx int64) DayOfWeekEnum {
	n := ((idx-1)%7 + 7) % 7
	names := [7]string{"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"}
	return DayOfWeekEnum{
		Value:   n + 1,
		NameStr: names[n],
	}
}

// Plus returns the DayOfWeek that is the specified number of days after this one.
func (d DayOfWeekEnum) Plus(days int64) DayOfWeekEnum {
	return newDayOfWeekEnumFromIndexRound62(d.Value + days)
}

// Minus returns the DayOfWeek that is the specified number of days before this one.
func (d DayOfWeekEnum) Minus(days int64) DayOfWeekEnum {
	return newDayOfWeekEnumFromIndexRound62(d.Value - days)
}

func (m MonthEnum) GetValue() int64 { return m.Value }
func (m MonthEnum) Name() string    { return m.String() }
func (m MonthEnum) String() string {
	if m.NameStr != "" {
		return m.NameStr
	}
	if m.Value >= 1 && m.Value <= 12 {
		return isoMonthNamesUpper[m.Value]
	}
	return "JANUARY"
}

func (m MonthEnum) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

func (m MonthEnum) Plus(months int64) MonthEnum {
	n := ((m.Value-1+months)%12 + 12) % 12
	return newMonthEnumRound62(time.Month(n + 1))
}

func (m MonthEnum) Minus(months int64) MonthEnum {
	return m.Plus(-months)
}

func (m MonthEnum) MinLength() int64 {
	switch m.Value {
	case 2:
		return 28
	case 4, 6, 9, 11:
		return 30
	default:
		return 31
	}
}

func (m MonthEnum) MaxLength() int64 {
	switch m.Value {
	case 2:
		return 29
	case 4, 6, 9, 11:
		return 30
	default:
		return 31
	}
}

func (m MonthEnum) Length(leapYear bool) int64 {
	if m.Value == 2 {
		if leapYear {
			return 29
		}
		return 28
	}
	return m.MaxLength()
}

func (m MonthEnum) FirstMonthOfQuarter() MonthEnum {
	qStart := ((m.Value - 1) / 3) * 3
	return newMonthEnumRound62(time.Month(qStart + 1))
}

func (m MonthEnum) GetDisplayName(style, locale string) string {
	return MonthDisplayName(m.Value, style, locale)
}

func normalizeLocaleLangRound62(locale string) string {
	loc := strings.TrimSpace(locale)
	loc = strings.TrimPrefix(loc, "java.util.")
	loc = strings.TrimPrefix(loc, "Locale.")
	upper := strings.ToUpper(strings.ReplaceAll(loc, "-", "_"))
	switch {
	case upper == "" || upper == "ROOT" || upper == "ENGLISH" || upper == "US" || upper == "UK" || upper == "CANADA" || strings.HasPrefix(upper, "EN"):
		return "en"
	case upper == "FRENCH" || upper == "FRANCE" || upper == "CANADA_FRENCH" || strings.HasPrefix(upper, "FR"):
		return "fr"
	case upper == "GERMAN" || upper == "GERMANY" || strings.HasPrefix(upper, "DE"):
		return "de"
	case upper == "ITALIAN" || upper == "ITALY" || strings.HasPrefix(upper, "IT"):
		return "it"
	case upper == "JAPANESE" || upper == "JAPAN" || strings.HasPrefix(upper, "JA"):
		return "ja"
	case upper == "CHINESE" || upper == "CHINA" || upper == "PRC" || upper == "TAIWAN" ||
		upper == "SIMPLIFIED_CHINESE" || upper == "TRADITIONAL_CHINESE" || strings.HasPrefix(upper, "ZH"):
		return "zh"
	case upper == "SPANISH" || strings.HasPrefix(upper, "ES"):
		return "es"
	case upper == "KOREAN" || upper == "KOREA" || strings.HasPrefix(upper, "KO"):
		return "ko"
	default:
		return "en"
	}
}

func normalizeTextStyleRound62(style string) (string, bool) {
	st := strings.TrimSpace(style)
	st = strings.TrimPrefix(st, "java.time.format.")
	st = strings.TrimPrefix(st, "TextStyle.")
	st = strings.ToUpper(st)
	switch st {
	case "FULL", "FULL_STANDALONE", "SHORT", "SHORT_STANDALONE", "NARROW", "NARROW_STANDALONE":
		return st, true
	default:
		return "FULL", false
	}
}

// DayOfWeekDisplayName formats an ISO-8601 day-of-week (1=Monday .. 7=Sunday)
// matching `java.time.DayOfWeek.getDisplayName(TextStyle, Locale)`.
func DayOfWeekDisplayName(dow int64, style, locale string) string {
	if dow < 1 || dow > 7 {
		dow = 1
	}
	st, _ := normalizeTextStyleRound62(style)
	lang := normalizeLocaleLangRound62(locale)
	isRoot := strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(locale), "Locale."), "ROOT")

	// Locale.ROOT in OpenJDK CLDR returns English standalone/format names for FULL/SHORT and numeric/letter narrow.
	if isRoot && (st == "NARROW" || st == "NARROW_STANDALONE") {
		rootNarrow := [8]string{"", "M", "T", "W", "T", "F", "S", "S"}
		return rootNarrow[dow]
	}

	switch lang {
	case "fr":
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [8]string{"", "lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."}
			return n[dow]
		case "NARROW", "NARROW_STANDALONE":
			n := [8]string{"", "L", "M", "M", "J", "V", "S", "D"}
			return n[dow]
		default:
			n := [8]string{"", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"}
			return n[dow]
		}
	case "de":
		switch st {
		case "SHORT":
			n := [8]string{"", "Mo.", "Di.", "Mi.", "Do.", "Fr.", "Sa.", "So."}
			return n[dow]
		case "SHORT_STANDALONE":
			n := [8]string{"", "Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"}
			return n[dow]
		case "NARROW", "NARROW_STANDALONE":
			n := [8]string{"", "M", "D", "M", "D", "F", "S", "S"}
			return n[dow]
		default:
			n := [8]string{"", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"}
			return n[dow]
		}
	case "it":
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [8]string{"", "lun", "mar", "mer", "gio", "ven", "sab", "dom"}
			return n[dow]
		case "NARROW", "NARROW_STANDALONE":
			n := [8]string{"", "L", "M", "M", "G", "V", "S", "D"}
			return n[dow]
		default:
			n := [8]string{"", "lunedì", "martedì", "mercoledì", "giovedì", "venerdì", "sabato", "domenica"}
			return n[dow]
		}
	case "ja":
		switch st {
		case "SHORT", "SHORT_STANDALONE", "NARROW", "NARROW_STANDALONE":
			n := [8]string{"", "月", "火", "水", "木", "金", "土", "日"}
			return n[dow]
		default:
			n := [8]string{"", "月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日", "日曜日"}
			return n[dow]
		}
	case "zh":
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [8]string{"", "周一", "周二", "周三", "周四", "周五", "周六", "周日"}
			return n[dow]
		case "NARROW", "NARROW_STANDALONE":
			n := [8]string{"", "一", "二", "三", "四", "五", "六", "日"}
			return n[dow]
		default:
			n := [8]string{"", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"}
			return n[dow]
		}
	default:
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [8]string{"", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
			return n[dow]
		case "NARROW", "NARROW_STANDALONE":
			n := [8]string{"", "M", "T", "W", "T", "F", "S", "S"}
			return n[dow]
		default:
			n := [8]string{"", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
			return n[dow]
		}
	}
}

// MonthDisplayName formats a month (1=January .. 12=December) matching
// `java.time.Month.getDisplayName(TextStyle, Locale)`.
func MonthDisplayName(month int64, style, locale string) string {
	if month < 1 || month > 12 {
		month = 1
	}
	st, _ := normalizeTextStyleRound62(style)
	lang := normalizeLocaleLangRound62(locale)

	switch lang {
	case "fr":
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [13]string{"", "janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."}
			return n[month]
		case "NARROW", "NARROW_STANDALONE":
			n := [13]string{"", "J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"}
			return n[month]
		default:
			n := [13]string{"", "janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"}
			return n[month]
		}
	case "de":
		switch st {
		case "SHORT":
			n := [13]string{"", "Jan.", "Feb.", "März", "Apr.", "Mai", "Juni", "Juli", "Aug.", "Sept.", "Okt.", "Nov.", "Dez."}
			return n[month]
		case "SHORT_STANDALONE":
			n := [13]string{"", "Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"}
			return n[month]
		case "NARROW", "NARROW_STANDALONE":
			n := [13]string{"", "J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"}
			return n[month]
		default:
			n := [13]string{"", "Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"}
			return n[month]
		}
	case "it":
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [13]string{"", "gen", "feb", "mar", "apr", "mag", "giu", "lug", "ago", "set", "ott", "nov", "dic"}
			return n[month]
		case "NARROW", "NARROW_STANDALONE":
			n := [13]string{"", "G", "F", "M", "A", "M", "G", "L", "A", "S", "O", "N", "D"}
			return n[month]
		default:
			n := [13]string{"", "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"}
			return n[month]
		}
	case "ja":
		switch st {
		case "NARROW", "NARROW_STANDALONE":
			return strconv.FormatInt(month, 10)
		default:
			return strconv.FormatInt(month, 10) + "月"
		}
	case "zh":
		switch st {
		case "NARROW", "NARROW_STANDALONE":
			return strconv.FormatInt(month, 10)
		case "SHORT", "SHORT_STANDALONE":
			return strconv.FormatInt(month, 10) + "月"
		default:
			n := [13]string{"", "一月", "二月", "三月", "四月", "五月", "六月", "七月", "八月", "九月", "十月", "十一月", "十二月"}
			return n[month]
		}
	default:
		switch st {
		case "SHORT", "SHORT_STANDALONE":
			n := [13]string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
			return n[month]
		case "NARROW", "NARROW_STANDALONE":
			n := [13]string{"", "J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"}
			return n[month]
		default:
			n := [13]string{"", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
			return n[month]
		}
	}
}

func evalEnumReceiverMethodRound62(recVal any, mBare string, evalCallArgs func() ([]any, error)) (any, bool, error) {
	if dow, isStr, ok := parseDayOfWeekEnumReceiverRound62(recVal); ok {
		// Only intercept raw strings if the method is an enum-specific method, so general String methods like `.substring()` still run on String!
		if isStr {
			switch mBare {
			case "getDisplayName", "getValue", "plus", "minus":
			default:
				return nil, false, nil
			}
		}
		switch mBare {
		case "getValue":
			return dow.Value, true, nil
		case "name", "toString":
			return dow.String(), true, nil
		case "getDisplayName":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) != 2 {
				return nil, true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Unable to find dynamic method [getDisplayName] with [%d] arguments for class [java.time.DayOfWeek].", len(args)),
				}
			}
			if args[0] == nil || args[1] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "style or locale is null"}
			}
			styleStr := fmt.Sprintf("%v", args[0])
			if _, valid := normalizeTextStyleRound62(styleStr); !valid {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Invalid TextStyle: " + styleStr}
			}
			return DayOfWeekDisplayName(dow.Value, styleStr, fmt.Sprintf("%v", args[1])), true, nil
		case "plus", "minus":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) != 1 {
				return nil, false, nil
			}
			n, okN := toInt64Painless(args[0])
			if !okN {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "DayOfWeek." + mBare + " requires long"}
			}
			if mBare == "minus" {
				return dow.Minus(n), true, nil
			}
			return dow.Plus(n), true, nil
		case "equals":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 1 {
				eq, _ := round60WrapperEquals(dow, args[0])
				return eq, true, nil
			}
		case "compareTo":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 1 {
				if args[0] == nil {
					return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "other"}
				}
				other, _, okO := parseDayOfWeekEnumReceiverRound62(args[0])
				if !okO {
					return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "Cannot compare DayOfWeek"}
				}
				return dow.Value - other.Value, true, nil
			}
		}
	}

	if mon, isStr, ok := parseMonthEnumReceiverRound62(recVal); ok {
		if isStr {
			switch mBare {
			case "getDisplayName", "getValue", "plus", "minus", "minLength", "maxLength", "firstMonthOfQuarter":
			default:
				return nil, false, nil
			}
		}
		switch mBare {
		case "getValue":
			return mon.Value, true, nil
		case "name", "toString":
			return mon.String(), true, nil
		case "minLength":
			return mon.MinLength(), true, nil
		case "maxLength":
			return mon.MaxLength(), true, nil
		case "firstMonthOfQuarter":
			return mon.FirstMonthOfQuarter(), true, nil
		case "length":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 1 {
				leap, _ := args[0].(bool)
				return mon.Length(leap), true, nil
			}
		case "getDisplayName":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) != 2 {
				return nil, true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Unable to find dynamic method [getDisplayName] with [%d] arguments for class [java.time.Month].", len(args)),
				}
			}
			if args[0] == nil || args[1] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "style or locale is null"}
			}
			styleStr := fmt.Sprintf("%v", args[0])
			if _, valid := normalizeTextStyleRound62(styleStr); !valid {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Invalid TextStyle: " + styleStr}
			}
			return MonthDisplayName(mon.Value, styleStr, fmt.Sprintf("%v", args[1])), true, nil
		case "plus", "minus":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) != 1 {
				return nil, false, nil
			}
			n, okN := toInt64Painless(args[0])
			if !okN {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "Month." + mBare + " requires long"}
			}
			if mBare == "minus" {
				return mon.Minus(n), true, nil
			}
			return mon.Plus(n), true, nil
		case "equals":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 1 {
				eq, _ := round60WrapperEquals(mon, args[0])
				return eq, true, nil
			}
		case "compareTo":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 1 {
				if args[0] == nil {
					return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "other"}
				}
				other, _, okO := parseMonthEnumReceiverRound62(args[0])
				if !okO {
					return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "Cannot compare Month"}
				}
				return mon.Value - other.Value, true, nil
			}
		}
	}

	return nil, false, nil
}

// ============================================================================
// Round 62 Deliverable 1: Complete `*ZonedDateTimeVal` `java.time` Dispatch
// ============================================================================

func newZonedDateTimeFromTimeRound62(tm time.Time, prev *ZonedDateTimeVal) *ZonedDateTimeVal {
	isNano := tm.Nanosecond()%1_000_000 != 0
	if prev != nil && prev.IsNano {
		isNano = true
	}
	return &ZonedDateTimeVal{
		Time:   tm,
		IsNano: isNano,
	}
}

func formatZonedDateTimeZoneIDRound62(tm time.Time) string {
	loc := tm.Location()
	if loc == nil || loc == time.UTC {
		return "Z"
	}
	name := loc.String()
	if name == "" || name == "UTC" {
		_, off := tm.Zone()
		if off == 0 {
			return "Z"
		}
		return tm.Format("-07:00")
	}
	return name
}

func formatZonedDateTimeOffsetRound62(tm time.Time) string {
	_, off := tm.Zone()
	if off == 0 {
		return "Z"
	}
	return tm.Format("-07:00")
}

func evalZonedDateTimeZeroArgRound62(tv *ZonedDateTimeVal, mSuffix string) (any, bool, error) {
	if tv == nil {
		return nil, false, nil
	}
	mBare := strings.TrimSuffix(strings.TrimPrefix(mSuffix, "."), "()")
	switch mSuffix {
	case ".getYear()":
		return tv.GetYear(), true, nil
	case ".getMonthValue()":
		return tv.GetMonthValue(), true, nil
	case ".getMonth()", ".getMonthEnum()":
		return newMonthEnumRound62(tv.Time.Month()), true, nil
	case ".getDayOfMonth()", ".getDate()":
		return tv.GetDayOfMonth(), true, nil
	case ".getDayOfYear()":
		return tv.GetDayOfYear(), true, nil
	case ".getDayOfWeek()":
		return tv.GetDayOfWeek(), true, nil
	case ".getDayOfWeekEnum()":
		return tv.GetDayOfWeekEnum(), true, nil
	case ".getHour()":
		return tv.GetHour(), true, nil
	case ".getMinute()":
		return tv.GetMinute(), true, nil
	case ".getSecond()":
		return tv.GetSecond(), true, nil
	case ".getNano()":
		return tv.GetNano(), true, nil
	case ".toInstant()":
		return tv.ToInstant(), true, nil
	case ".toEpochMilli()", ".getMillis()":
		return tv.ToEpochMilli(), true, nil
	case ".getEpochSecond()", ".toEpochSecond()":
		return tv.Time.Unix(), true, nil
	case ".toLocalDate()":
		return tv.Time.Format("2006-01-02"), true, nil
	case ".toLocalDateTime()":
		if tv.Time.Nanosecond() > 0 {
			return tv.Time.Format("2006-01-02T15:04:05.999999999"), true, nil
		}
		return tv.Time.Format("2006-01-02T15:04:05"), true, nil
	case ".toLocalTime()":
		return formatLocalTimePainless(tv.Time.Hour(), tv.Time.Minute(), tv.Time.Second(), tv.Time.Nanosecond()), true, nil
	case ".toOffsetDateTime()":
		return tv.Time.Format(time.RFC3339Nano), true, nil
	case ".getZone()":
		return formatZonedDateTimeZoneIDRound62(tv.Time), true, nil
	case ".getOffset()":
		return formatZonedDateTimeOffsetRound62(tv.Time), true, nil
	case ".getChronology()":
		return "ISO", true, nil
	case ".hashCode()":
		return computeJavaHashCodeScalarRound60(tv), true, nil
	case ".toString()":
		return tv.String(), true, nil
	default:
		if err := checkDeprecatedJodaMethodRound61(mBare); err != nil {
			return nil, true, err
		}
		return nil, true, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Unable to find dynamic method [%s] with [0] arguments for class [org.elasticsearch.script.JodaCompatibleZonedDateTime].", mBare),
		}
	}
}

func addChronoUnitToTimeRound62(tm time.Time, amount int64, unitRaw any) (time.Time, error) {
	if unitRaw == nil {
		return tm, &painlessExceptionError{exType: "NullPointerException", message: "unit"}
	}
	u := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", unitRaw)))
	u = strings.TrimPrefix(u, "JAVA.TIME.TEMPORAL.")
	u = strings.TrimPrefix(u, "CHRONOUNIT.")
	switch u {
	case "NANOS", "NANOSECONDS":
		return tm.Add(time.Duration(amount) * time.Nanosecond), nil
	case "MICROS", "MICROSECONDS":
		return tm.Add(time.Duration(amount) * time.Microsecond), nil
	case "MILLIS", "MILLISECONDS":
		return tm.Add(time.Duration(amount) * time.Millisecond), nil
	case "SECONDS", "SECOND":
		return tm.Add(time.Duration(amount) * time.Second), nil
	case "MINUTES", "MINUTE":
		return tm.Add(time.Duration(amount) * time.Minute), nil
	case "HOURS", "HOUR":
		return tm.Add(time.Duration(amount) * time.Hour), nil
	case "HALF_DAYS":
		return tm.Add(time.Duration(amount) * 12 * time.Hour), nil
	case "DAYS", "DAY":
		return tm.AddDate(0, 0, int(amount)), nil
	case "WEEKS", "WEEK":
		return tm.AddDate(0, 0, int(amount)*7), nil
	case "MONTHS", "MONTH":
		return addMonthsClampedPainless(tm, int(amount)), nil
	case "YEARS", "YEAR":
		return addMonthsClampedPainless(tm, int(amount)*12), nil
	case "DECADES":
		return addMonthsClampedPainless(tm, int(amount)*120), nil
	case "CENTURIES":
		return addMonthsClampedPainless(tm, int(amount)*1200), nil
	case "MILLENNIA":
		return addMonthsClampedPainless(tm, int(amount)*12000), nil
	default:
		return tm, &painlessExceptionError{
			exType:  "UnsupportedTemporalTypeException",
			message: "Unsupported unit: " + fmt.Sprintf("%v", unitRaw),
		}
	}
}

func evalZonedDateTimeMethodRound62(tv *ZonedDateTimeVal, mBare string, rawArgExprs []string, evalCallArgs func() ([]any, error), sourceMap, params map[string]any, depth int) (any, bool, error) {
	if tv == nil {
		return nil, false, nil
	}
	if len(rawArgExprs) == 0 {
		return evalZonedDateTimeZeroArgRound62(tv, "."+mBare+"()")
	}
	args, err := evalCallArgs()
	if err != nil {
		return nil, true, err
	}

	switch mBare {
	case "plus", "minus":
		sign := int64(1)
		if mBare == "minus" {
			sign = -1
		}
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "amountToAdd"}
			}
			if per, okP := parsePainlessPeriod(args[0]); okP {
				nt := addMonthsClampedPainless(tv.Time, int(sign)*(per.years*12+per.months))
				nt = nt.AddDate(0, 0, int(sign)*per.days)
				return newZonedDateTimeFromTimeRound62(nt, tv), true, nil
			}
			if dur, okD := parsePainlessDuration(args[0]); okD {
				nt := tv.Time.Add(time.Duration(sign) * dur)
				return newZonedDateTimeFromTimeRound62(nt, tv), true, nil
			}
			return nil, true, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to TemporalAmount", args[0])}
		}
		if len(args) == 2 {
			amt, okA := toInt64Painless(args[0])
			if !okA {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "Temporal amount must be numeric"}
			}
			nt, uErr := addChronoUnitToTimeRound62(tv.Time, sign*amt, args[1])
			if uErr != nil {
				return nil, true, uErr
			}
			return newZonedDateTimeFromTimeRound62(nt, tv), true, nil
		}

	case "plusYears", "minusYears", "plusMonths", "minusMonths", "plusWeeks", "minusWeeks",
		"plusDays", "minusDays", "plusHours", "minusHours", "plusMinutes", "minusMinutes",
		"plusSeconds", "minusSeconds", "plusMillis", "minusMillis", "plusNanos", "minusNanos":
		if len(args) == 1 {
			amt, okA := toInt64Painless(args[0])
			if !okA {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: mBare + " requires numeric argument"}
			}
			if strings.HasPrefix(mBare, "minus") {
				amt = -amt
			}
			unit := strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(mBare, "plus"), "minus"))
			nt, uErr := addChronoUnitToTimeRound62(tv.Time, amt, unit)
			if uErr != nil {
				return nil, true, uErr
			}
			return newZonedDateTimeFromTimeRound62(nt, tv), true, nil
		}

	case "withYear", "withMonth", "withDayOfMonth", "withDayOfYear", "withHour", "withMinute", "withSecond", "withNano":
		if len(args) == 1 {
			val, okV := toInt64Painless(args[0])
			if !okV {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: mBare + " requires integer argument"}
			}
			isLD, isYM := false, false
			nt, wErr := evalTemporalWithFieldRound58("."+mBare+"(", tv.Time, val, &isLD, &isYM)
			if wErr != nil {
				return nil, true, wErr
			}
			return newZonedDateTimeFromTimeRound62(nt, tv), true, nil
		}

	case "with":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "adjuster"}
			}
			adjArg := args[0]
			if d, okD := adjArg.(DayOfWeekEnum); okD {
				adjArg = d.String()
			} else if m, okM := adjArg.(MonthEnum); okM {
				adjArg = m.String()
			}
			res, wErr := evalWithTemporalAdjusterPainless(tv.Time, adjArg)
			if wErr != nil {
				return nil, true, wErr
			}
			if nt, okT := parsePainlessDateTime(res); okT {
				return newZonedDateTimeFromTimeRound62(nt.In(tv.Time.Location()), tv), true, nil
			}
			return tv, true, nil
		}
		if len(args) == 2 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "field"}
			}
			newVal, okV := toInt64Painless(args[1])
			if !okV {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: "with(TemporalField, long) requires numeric value"}
			}
			cf, okCF := parseChronoFieldArgPainless(args[0])
			if !okCF {
				return nil, true, &painlessExceptionError{
					exType:  "UnsupportedTemporalTypeException",
					message: fmt.Sprintf("Unsupported field: %v", args[0]),
				}
			}
			res, wErr := evalWithChronoFieldPainless(tv.Time.Format(time.RFC3339Nano), cf, newVal)
			if wErr != nil {
				return nil, true, wErr
			}
			if nt, okT := parsePainlessDateTime(res); okT {
				return newZonedDateTimeFromTimeRound62(nt.In(tv.Time.Location()), tv), true, nil
			}
			return tv, true, nil
		}

	case "withZoneSameInstant", "withZoneSameLocal":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "zone"}
			}
			loc := parseZoneLocationPainless(args[0])
			var nt time.Time
			if mBare == "withZoneSameInstant" {
				nt = tv.Time.In(loc)
			} else {
				nt = time.Date(tv.Time.Year(), tv.Time.Month(), tv.Time.Day(), tv.Time.Hour(), tv.Time.Minute(), tv.Time.Second(), tv.Time.Nanosecond(), loc)
			}
			return newZonedDateTimeFromTimeRound62(nt, tv), true, nil
		}

	case "truncatedTo":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "unit"}
			}
			u := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", args[0])))
			u = strings.TrimPrefix(u, "JAVA.TIME.TEMPORAL.")
			u = strings.TrimPrefix(u, "CHRONOUNIT.")
			tm := tv.Time
			switch u {
			case "DAYS", "DAY":
				tm = time.Date(tm.Year(), tm.Month(), tm.Day(), 0, 0, 0, 0, tm.Location())
			case "HALF_DAYS":
				hr := 0
				if tm.Hour() >= 12 {
					hr = 12
				}
				tm = time.Date(tm.Year(), tm.Month(), tm.Day(), hr, 0, 0, 0, tm.Location())
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
			case "NANOS", "NANOSECONDS":
				// no-op
			default:
				return nil, true, &painlessExceptionError{
					exType:  "UnsupportedTemporalTypeException",
					message: "Unit is too large to be used for truncation: " + fmt.Sprintf("%v", args[0]),
				}
			}
			return newZonedDateTimeFromTimeRound62(tm, tv), true, nil
		}

	case "get", "getLong":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "field"}
			}
			fExpr := fmt.Sprintf("%v", args[0])
			if mBare == "get" {
				upper := strings.ToUpper(fExpr)
				if strings.Contains(upper, "INSTANT_SECONDS") || strings.Contains(upper, "NANO_OF_DAY") || strings.Contains(upper, "MICRO_OF_DAY") || strings.Contains(upper, "EPOCH_DAY") || strings.Contains(upper, "PROLEPTIC_MONTH") {
					return nil, true, &painlessExceptionError{
						exType:  "UnsupportedTemporalTypeException",
						message: "Invalid field " + fExpr + " for get() method, use getLong() instead",
					}
				}
			}
			if val, ok := evalChronoOrIsoFieldOnTimeRound61(tv.Time, fExpr); ok {
				return val, true, nil
			}
			return nil, true, &painlessExceptionError{
				exType:  "UnsupportedTemporalTypeException",
				message: "Unsupported field: " + fExpr,
			}
		}

	case "isSupported":
		if len(args) == 1 {
			if args[0] == nil {
				return false, true, nil
			}
			fExpr := fmt.Sprintf("%v", args[0])
			if _, ok := evalChronoOrIsoFieldOnTimeRound61(tv.Time, fExpr); ok {
				return true, true, nil
			}
			u := strings.ToUpper(strings.TrimSpace(fExpr))
			u = strings.TrimPrefix(u, "JAVA.TIME.TEMPORAL.")
			u = strings.TrimPrefix(u, "CHRONOUNIT.")
			switch u {
			case "NANOS", "MICROS", "MILLIS", "SECONDS", "MINUTES", "HOURS", "HALF_DAYS",
				"DAYS", "WEEKS", "MONTHS", "YEARS", "DECADES", "CENTURIES", "MILLENNIA", "ERAS":
				return true, true, nil
			}
			return false, true, nil
		}

	case "isAfter", "isBefore", "isEqual":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "other"}
			}
			tm2, ok := parseFlexibleESDateTimeRound60(args[0])
			if !ok {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot compare ZonedDateTime with %T", args[0])}
			}
			switch mBare {
			case "isAfter":
				return tv.Time.After(tm2), true, nil
			case "isBefore":
				return tv.Time.Before(tm2), true, nil
			default:
				return tv.Time.Equal(tm2), true, nil
			}
		}

	case "equals":
		if len(args) == 1 {
			eq, _ := round60WrapperEquals(tv, args[0])
			return eq, true, nil
		}

	case "compareTo":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "other"}
			}
			tm2, ok := parseFlexibleESDateTimeRound60(args[0])
			if !ok {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot compare ZonedDateTime with %T", args[0])}
			}
			if tv.Time.Before(tm2) {
				return int64(-1), true, nil
			}
			if tv.Time.After(tm2) {
				return int64(1), true, nil
			}
			return int64(0), true, nil
		}

	case "until":
		if len(args) == 2 {
			if args[0] == nil || args[1] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "endExclusive or unit"}
			}
			u := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", args[1])))
			u = strings.TrimPrefix(u, "JAVA.TIME.TEMPORAL.")
			u = strings.TrimPrefix(u, "CHRONOUNIT.")
			res, uErr := evalTemporalBetweenUnitPainless(u, tv.Time, args[0])
			return res, true, uErr
		}

	case "format":
		if len(args) == 1 {
			if args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "formatter"}
			}
			layout, loc := splitFormatterAndZonePainless(args[0])
			tm := tv.Time
			if loc != nil {
				tm = tm.In(loc)
			}
			return tm.Format(layout), true, nil
		}
	}

	_ = sourceMap
	_ = params
	_ = depth

	if err := checkDeprecatedJodaMethodRound61(mBare); err != nil {
		return nil, true, err
	}
	return nil, true, &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("Unable to find dynamic method [%s] with [%d] arguments for class [org.elasticsearch.script.JodaCompatibleZonedDateTime].", mBare, len(args)),
	}
}

func evalBuiltinDateParseRound62(ev []any, sourceMap, params map[string]any) (any, error) {
	if len(ev) != 1 {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("parse() requires 1 argument, got %d", len(ev)),
		}
	}
	val := ev[0]
	if val == nil {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "Cannot parse null date value"}
	}
	if iv, ok := isIntegerValuePainless(val); ok {
		return iv, nil
	}
	switch tv := val.(type) {
	case float32:
		return int64(tv), nil
	case float64:
		return int64(tv), nil
	case *ZonedDateTimeVal:
		if tv != nil {
			return tv.ToEpochMilli(), nil
		}
	case *InstantVal:
		if tv != nil {
			return tv.ToEpochMilli(), nil
		}
	case string:
		dateFmt := ""
		for _, m := range []map[string]any{params, sourceMap} {
			if m != nil {
				if df, ok := m["__runtime_date_format"].(string); ok && df != "" {
					dateFmt = df
					break
				}
			}
		}
		if z, ok := parseDocDateWithMappingFormatRound61(tv, dateFmt, false); ok && z != nil {
			return z.ToEpochMilli(), nil
		}
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("failed to parse date field [%s]", tv),
		}
	}
	if z, ok := parseZonedDateTimeValRound60(val, false); ok && z != nil {
		return z.ToEpochMilli(), nil
	}
	return nil, &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("failed to parse date field [%v]", val),
	}
}

// ============================================================================
// Round 62 Deliverable 3: Built-In `grok(...)` & `dissect(...)` + Composite `emit(...)`
// ============================================================================

type grokCaptureSpec struct {
	groupName string
	fieldName string
	valueType string
}

// GrokExtractor is a compiled Elasticsearch-compatible Grok pattern extractor
// supporting `.extract(String)` in Painless runtime scripts (`250_grok.yml`, `110_composite.yml`).
type GrokExtractor struct {
	Pattern  string
	re       *regexp.Regexp
	captures []grokCaptureSpec
}

func (g *GrokExtractor) String() string {
	if g == nil {
		return "null"
	}
	return "Grok[" + g.Pattern + "]"
}

// DissectFieldKind classifies a `%{...}` token in a Dissect pattern.
type dissectFieldKind int

const (
	dissectFieldNormal dissectFieldKind = iota
	dissectFieldSkip
	dissectFieldAppend
	dissectFieldSaveKey
	dissectFieldUseKey
)

type dissectFieldSpec struct {
	kind       dissectFieldKind
	name       string
	order      int
	hasOrder   bool
	rightPad   bool
	joinSep    string
	delimAfter string
}

// DissectExtractor is a compiled Elasticsearch-compatible Dissect pattern extractor
// supporting `.extract(String)` in Painless runtime scripts (`260_dissect.yml`).
type DissectExtractor struct {
	Pattern     string
	prefixDelim string
	fields      []dissectFieldSpec
}

func (d *DissectExtractor) String() string {
	if d == nil {
		return "null"
	}
	return "Dissect[" + d.Pattern + "]"
}

type extractorLRUCache[T any] struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type extractorCacheItem[T any] struct {
	key string
	val T
}

func newExtractorLRUCache[T any](capacity int) *extractorLRUCache[T] {
	return &extractorLRUCache[T]{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[string]*list.Element, 64),
	}
}

func (c *extractorLRUCache[T]) get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*extractorCacheItem[T]).val, true
	}
	var zero T
	return zero, false
}

func (c *extractorLRUCache[T]) put(key string, val T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*extractorCacheItem[T]).val = val
		return
	}
	if c.ll.Len() >= c.cap {
		if back := c.ll.Back(); back != nil {
			c.ll.Remove(back)
			delete(c.items, back.Value.(*extractorCacheItem[T]).key)
		}
	}
	el := c.ll.PushFront(&extractorCacheItem[T]{key: key, val: val})
	c.items[key] = el
}

var (
	globalGrokCache    = newExtractorLRUCache[*GrokExtractor](MaxGrokDissectCacheCapacity)
	globalDissectCache = newExtractorLRUCache[*DissectExtractor](MaxGrokDissectCacheCapacity)
)

// builtinElasticGrokPatternsRound62 defines standard Elasticsearch Grok patterns
// using pure RE2-compatible syntax (no possessive quantifiers or atomic groups).
var builtinElasticGrokPatternsRound62 = map[string]string{
	"USERNAME":          `[a-zA-Z0-9._-]+`,
	"USER":              `%{USERNAME}`,
	"EMAILLOCALPART":    `[a-zA-Z][a-zA-Z0-9_.+-=:]+`,
	"EMAILADDRESS":      `%{EMAILLOCALPART}@%{HOSTNAME}`,
	"HTTPDUSER":         `%{EMAILADDRESS}|%{USER}`,
	"INT":               `(?:[+-]?(?:[0-9]+))`,
	"BASE10NUM":         `(?:[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))`,
	"NUMBER":            `(?:%{BASE10NUM})`,
	"BASE16NUM":         `(?:0[xX]?[0-9a-fA-F]+)`,
	"BASE16FLOAT":       `\b(?:0[xX]?[0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?(?:[pP][+-]?[0-9]+)?)\b`,
	"POSINT":            `\b(?:[1-9][0-9]*)\b`,
	"NONNEGINT":         `\b(?:[0-9]+)\b`,
	"WORD":              `\b\w+\b`,
	"NOTSPACE":          `\S+`,
	"SPACE":             `\s*`,
	"DATA":              `.*?`,
	"GREEDYDATA":        `.*`,
	"QUOTEDSTRING":      `"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`,
	"UUID":              `[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}`,
	"CISCOMAC":          `(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})`,
	"WINDOWSMAC":        `(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})`,
	"COMMONMAC":         `(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})`,
	"MAC":               `(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})`,
	"IPV4":              `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`,
	"IPV6":              `(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|%{IPV4}|:)|(?:[0-9A-Fa-f]{1,4}:){5}(?:(?::[0-9A-Fa-f]{1,4}){1,2}|:%{IPV4}|:)|(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){1,3}|(?::[0-9A-Fa-f]{1,4})?:%{IPV4}|:)|(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){1,4}|(?::[0-9A-Fa-f]{1,4}){0,2}:%{IPV4}|:)|(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){1,5}|(?::[0-9A-Fa-f]{1,4}){0,3}:%{IPV4}|:)|(?:[0-9A-Fa-f]{1,4}:){1}(?:(?::[0-9A-Fa-f]{1,4}){1,6}|(?::[0-9A-Fa-f]{1,4}){0,4}:%{IPV4}|:)|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|(?::[0-9A-Fa-f]{1,4}){0,5}:%{IPV4}|:))`,
	"IP":                `(?:%{IPV6}|%{IPV4})`,
	"HOSTNAME":          `\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(?:\.?|\b)`,
	"HOST":              `%{HOSTNAME}`,
	"IPORHOST":          `(?:%{IP}|%{HOSTNAME})`,
	"HOSTPORT":          `%{IPORHOST}:%{POSINT}`,
	"UNIXPATH":          `(?:/[\w_%!$@:.,+~-]+)+`,
	"TTY":               `(?:/dev/(?:pts|tty(?:[pq])?)(?:\w+)?/?(?:[0-9]+))`,
	"WINPATH":           `(?:[A-Za-z]+:|\\)(?:\\[^\\?*]*)+`,
	"PATH":              `(?:%{UNIXPATH}|%{WINPATH})`,
	"URIPROTO":          `[A-Za-z][A-Za-z0-9+\-.]+`,
	"URIHOST":           `%{IPORHOST}(?::%{POSINT:port})?`,
	"URIPATH":           `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+`,
	"URIPARAM":          `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*`,
	"URIPATHPARAM":      `%{URIPATH}(?:%{URIPARAM})?`,
	"URI":               `%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?`,
	"MONTH":             `\b(?:Jan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?)\b`,
	"MONTHNUM":          `(?:0?[1-9]|1[0-2])`,
	"MONTHNUM2":         `(?:0[1-9]|1[0-2])`,
	"MONTHDAY":          `(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])`,
	"DAY":               `(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)`,
	"YEAR":              `(?:[0-9][0-9]){1,2}`,
	"HOUR":              `(?:2[0123]|[01]?[0-9])`,
	"MINUTE":            `(?:[0-5][0-9])`,
	"SECOND":            `(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)`,
	"TIME":              `(?:%{HOUR}:%{MINUTE}(?::%{SECOND})?)`,
	"DATE_US":           `%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}`,
	"DATE_EU":           `%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}`,
	"ISO8601_TIMEZONE":  `(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))`,
	"ISO8601_SECOND":    `(?:%{SECOND}|60)`,
	"TIMESTAMP_ISO8601": `%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?`,
	"DATE":              `%{DATE_US}|%{DATE_EU}`,
	"DATESTAMP":         `%{DATE}[- ]%{TIME}`,
	"HTTPDATE":          `%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}`,
	"SYSLOGTIMESTAMP":   `%{MONTH} +%{MONTHDAY} %{TIME}`,
	"PROG":              `[\x21-\x5a\x5c\x5e-\x7e]+`,
	"SYSLOGPROG":        `%{PROG:program}(?:\[%{POSINT:pid}\])?`,
	"SYSLOGHOST":        `%{IPORHOST}`,
	"SYSLOGFACILITY":    `<%{NONNEGINT:facility}\.%{NONNEGINT:priority}>`,
	"SYSLOGBASE":        `%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:`,
	"LOGLEVEL":          `(?:[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo(?:rmation)?|INFO(?:RMATION)?|[Ww]arn(?:ing)?|WARN(?:ING)?|[Ee]rr(?:or)?|ERR(?:OR)?|[Cc]rit(?:ical)?|CRIT(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)`,
	"COMMONAPACHELOG":   `%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)`,
	"HTTPD_COMMONLOG":   `%{COMMONAPACHELOG}`,
	"COMBINEDAPACHELOG": `%{COMMONAPACHELOG} %{QUOTEDSTRING:referrer} %{QUOTEDSTRING:agent}`,
}

func isValidOnigmoRegexEscapeLetterRound62(b byte) bool {
	switch b {
	case 'a', 'A', 'b', 'B', 'c', 'd', 'D', 'e', 'E', 'f', 'G', 'h', 'H',
		'k', 'n', 'N', 'p', 'P', 'Q', 'r', 'R', 's', 'S', 't', 'u', 'v', 'V',
		'w', 'W', 'x', 'X', 'z', 'Z':
		return true
	default:
		return false
	}
}

func validateAndRewriteRawRegexSegmentRound62(rawPat, seg string, captures *[]grokCaptureSpec) (string, error) {
	var sb strings.Builder
	sb.Grow(len(seg) + 16)
	inClass := false
	inQuote := false
	for i := 0; i < len(seg); i++ {
		ch := seg[i]
		if inQuote {
			if ch == '\\' && i+1 < len(seg) && seg[i+1] == 'E' {
				sb.WriteString(`\E`)
				inQuote = false
				i++
				continue
			}
			sb.WriteByte(ch)
			continue
		}
		if ch == '\\' {
			if i+1 >= len(seg) {
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("error compiling grok pattern [%s]: premature end of escape sequence", rawPat),
				}
			}
			next := seg[i+1]
			if next == 'Q' {
				inQuote = true
				sb.WriteString(`\Q`)
				i++
				continue
			}
			if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') {
				if !isValidOnigmoRegexEscapeLetterRound62(next) {
					return "", &painlessExceptionError{
						exType:  "IllegalArgumentException",
						message: fmt.Sprintf("error compiling grok pattern [%s]: emitted warnings: [invalid escape sequence \\%c]", rawPat, next),
					}
				}
			}
			sb.WriteByte('\\')
			sb.WriteByte(next)
			i++
			continue
		}
		if ch == '[' && !inClass {
			inClass = true
			sb.WriteByte(ch)
			continue
		}
		if ch == ']' && inClass {
			inClass = false
			sb.WriteByte(ch)
			continue
		}
		if !inClass && i+2 < len(seg) && ch == '(' && seg[i+1] == '?' && seg[i+2] == '<' {
			// Distinguish lookbehind `(?<=` / `(?<!` from named group `(?<name>...`
			if i+3 < len(seg) && (seg[i+3] == '=' || seg[i+3] == '!') {
				sb.WriteString(seg[i : i+4])
				i += 3
				continue
			}
			endAngle := strings.IndexByte(seg[i+3:], '>')
			if endAngle < 0 {
				badName := seg[i+3:]
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("error compiling grok pattern [%s]: invalid group name <%s>", rawPat, badName),
				}
			}
			gName := seg[i+3 : i+3+endAngle]
			if !isValidGrokGroupNameRound62(gName) {
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("error compiling grok pattern [%s]: invalid group name <%s>", rawPat, gName),
				}
			}
			synGroup := fmt.Sprintf("__g%d", len(*captures))
			*captures = append(*captures, grokCaptureSpec{
				groupName: synGroup,
				fieldName: gName,
				valueType: "string",
			})
			sb.WriteString("(?P<")
			sb.WriteString(synGroup)
			sb.WriteByte('>')
			i += 3 + endAngle
			continue
		}
		sb.WriteByte(ch)
	}
	return sb.String(), nil
}

func isValidGrokGroupNameRound62(name string) bool {
	if name == "" {
		return false
	}
	c0 := name[0]
	if (c0 < 'a' || c0 > 'z') && (c0 < 'A' || c0 > 'Z') && c0 != '_' && c0 != '@' && c0 != '[' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '.' || c == '-' || c == '@' || c == '[' || c == ']' {
			continue
		}
		return false
	}
	return true
}

func expandGrokPatternRecursiveRound62(origPat, curPat string, captures *[]grokCaptureSpec, depth int) (string, error) {
	if depth > 32 {
		return "", &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("error compiling grok pattern [%s]: pattern recursion depth exceeded", origPat),
		}
	}
	var sb strings.Builder
	pos := 0
	for pos < len(curPat) {
		rel := strings.Index(curPat[pos:], "%{")
		if rel < 0 {
			tail, err := validateAndRewriteRawRegexSegmentRound62(origPat, curPat[pos:], captures)
			if err != nil {
				return "", err
			}
			sb.WriteString(tail)
			break
		}
		openIdx := pos + rel
		// Check if `%` was escaped `\%{`
		bsCount := 0
		for k := openIdx - 1; k >= pos && curPat[k] == '\\'; k-- {
			bsCount++
		}
		if bsCount%2 == 1 {
			seg, err := validateAndRewriteRawRegexSegmentRound62(origPat, curPat[pos:openIdx+2], captures)
			if err != nil {
				return "", err
			}
			sb.WriteString(seg)
			pos = openIdx + 2
			continue
		}
		if openIdx > pos {
			seg, err := validateAndRewriteRawRegexSegmentRound62(origPat, curPat[pos:openIdx], captures)
			if err != nil {
				return "", err
			}
			sb.WriteString(seg)
		}
		closeRel := strings.IndexByte(curPat[openIdx+2:], '}')
		if closeRel < 0 {
			return "", &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("error compiling grok pattern [%s]: unclosed grok macro", origPat),
			}
		}
		macroSpec := curPat[openIdx+2 : openIdx+2+closeRel]
		parts := strings.SplitN(macroSpec, ":", 3)
		syntaxName := strings.TrimSpace(parts[0])
		semanticName := ""
		valType := "string"
		if len(parts) >= 2 {
			semanticName = strings.TrimSpace(parts[1])
		}
		if len(parts) == 3 {
			valType = strings.ToLower(strings.TrimSpace(parts[2]))
			switch valType {
			case "", "string", "int", "integer", "long", "float", "double", "boolean":
				if valType == "" {
					valType = "string"
				}
			default:
				return "", &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("error compiling grok pattern [%s]: unsupported conversion type [%s]", origPat, valType),
				}
			}
		}
		body, exists := builtinElasticGrokPatternsRound62[syntaxName]
		if !exists {
			return "", &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("error compiling grok pattern [%s]: Grok pattern [%s] not defined", origPat, syntaxName),
			}
		}
		expanded, err := expandGrokPatternRecursiveRound62(origPat, body, captures, depth+1)
		if err != nil {
			return "", err
		}
		if semanticName != "" {
			synGroup := fmt.Sprintf("__g%d", len(*captures))
			*captures = append(*captures, grokCaptureSpec{
				groupName: synGroup,
				fieldName: semanticName,
				valueType: valType,
			})
			sb.WriteString("(?P<")
			sb.WriteString(synGroup)
			sb.WriteByte('>')
			sb.WriteString(expanded)
			sb.WriteByte(')')
		} else {
			sb.WriteString("(?:")
			sb.WriteString(expanded)
			sb.WriteByte(')')
		}
		pos = openIdx + 2 + closeRel + 1
	}
	return sb.String(), nil
}

// CompileGrokPattern compiles an Elasticsearch Grok pattern with bounded LRU caching.
func CompileGrokPattern(pattern string) (*GrokExtractor, error) {
	if len(pattern) > MaxRegexPatternLen {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("error compiling grok pattern [%s]: pattern exceeds maximum length (%d)", pattern, MaxRegexPatternLen),
		}
	}
	if cached, ok := globalGrokCache.get(pattern); ok {
		return cached, nil
	}
	var captures []grokCaptureSpec
	regexBody, err := expandGrokPatternRecursiveRound62(pattern, pattern, &captures, 0)
	if err != nil {
		return nil, err
	}
	re, rErr := regexp.Compile(regexBody)
	if rErr != nil {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("error compiling grok pattern [%s]: %v", pattern, rErr),
		}
	}
	ext := &GrokExtractor{
		Pattern:  pattern,
		re:       re,
		captures: captures,
	}
	globalGrokCache.put(pattern, ext)
	return ext, nil
}

func convertGrokTypedCaptureRound62(raw, valType string) (any, bool) {
	switch valType {
	case "int", "integer":
		iv, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
		if err != nil {
			return nil, false
		}
		return iv, true
	case "long":
		iv, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, false
		}
		return iv, true
	case "float":
		fv, err := strconv.ParseFloat(strings.TrimSpace(raw), 32)
		if err != nil {
			return nil, false
		}
		return float32(fv), true
	case "double":
		fv, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			return nil, false
		}
		return fv, true
	case "boolean":
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "true" {
			return true, true
		}
		if s == "false" {
			return false, true
		}
		return nil, false
	default:
		return raw, true
	}
}

func assignGrokFieldPathRound62(dst map[string]any, fieldName string, val any) {
	// Support ECS bracket notation `[host][ip]` -> nested map `{"host": {"ip": val}}` if used,
	// while keeping dotted names like `http.clientip` flat/nested per Grok convention.
	if strings.HasPrefix(fieldName, "[") && strings.HasSuffix(fieldName, "]") && strings.Contains(fieldName, "][") {
		trimmed := strings.TrimPrefix(strings.TrimSuffix(fieldName, "]"), "[")
		segs := strings.Split(trimmed, "][")
		cur := dst
		for i := 0; i < len(segs)-1; i++ {
			next, ok := cur[segs[i]].(map[string]any)
			if !ok {
				next = make(map[string]any)
				cur[segs[i]] = next
			}
			cur = next
		}
		cur[segs[len(segs)-1]] = val
		return
	}
	dst[fieldName] = val
}

// Extract matches `text` against the compiled Grok pattern and returns the extracted
// map of named captures, or `nil` when `text` does not match.
func (g *GrokExtractor) Extract(text string) map[string]any {
	if g == nil || g.re == nil {
		return nil
	}
	loc := g.re.FindStringSubmatchIndex(text)
	if loc == nil {
		return nil
	}
	out := make(map[string]any, len(g.captures))
	for _, capSpec := range g.captures {
		subIdx := g.re.SubexpIndex(capSpec.groupName)
		if subIdx <= 0 || 2*subIdx+1 >= len(loc) {
			continue
		}
		start, end := loc[2*subIdx], loc[2*subIdx+1]
		if start < 0 || end < 0 {
			continue
		}
		converted, ok := convertGrokTypedCaptureRound62(text[start:end], capSpec.valueType)
		if !ok {
			continue
		}
		assignGrokFieldPathRound62(out, capSpec.fieldName, converted)
	}
	return out
}

// CompileDissectPattern compiles an Elasticsearch Dissect pattern with bounded LRU caching.
func CompileDissectPattern(pattern string) (*DissectExtractor, error) {
	if len(pattern) > MaxRegexPatternLen {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("error compiling dissect pattern [%s]: pattern exceeds maximum length (%d)", pattern, MaxRegexPatternLen),
		}
	}
	if cached, ok := globalDissectCache.get(pattern); ok {
		return cached, nil
	}

	var prefixDelim string
	var fields []dissectFieldSpec
	pos := 0
	first := true
	prevDelim := ""

	for pos <= len(pattern) {
		rel := strings.Index(pattern[pos:], "%{")
		if rel < 0 {
			tail := pattern[pos:]
			if first {
				prefixDelim = tail
			} else if len(fields) > 0 {
				fields[len(fields)-1].delimAfter = tail
			}
			break
		}
		openIdx := pos + rel
		delim := pattern[pos:openIdx]
		if first {
			prefixDelim = delim
			first = false
		} else {
			if delim == "" {
				return nil, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("error compiling dissect pattern [%s]: impossible dissect pattern, two consecutive fields without delimiter", pattern),
				}
			}
			fields[len(fields)-1].delimAfter = delim
		}
		prevDelim = delim

		closeRel := strings.IndexByte(pattern[openIdx+2:], '}')
		if closeRel < 0 {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("error compiling dissect pattern [%s]: unclosed field token", pattern),
			}
		}
		token := pattern[openIdx+2 : openIdx+2+closeRel]
		rightPad := false
		if strings.HasSuffix(token, "->") {
			rightPad = true
			token = strings.TrimSuffix(token, "->")
		}
		spec := dissectFieldSpec{
			kind:     dissectFieldNormal,
			rightPad: rightPad,
			joinSep:  prevDelim,
		}
		switch {
		case token == "":
			spec.kind = dissectFieldSkip
		case strings.HasPrefix(token, "?"):
			spec.kind = dissectFieldSkip
			spec.name = token[1:]
		case strings.HasPrefix(token, "*"):
			spec.kind = dissectFieldSaveKey
			spec.name = token[1:]
		case strings.HasPrefix(token, "&"):
			spec.kind = dissectFieldUseKey
			spec.name = token[1:]
		case strings.HasPrefix(token, "+"):
			spec.kind = dissectFieldAppend
			rest := token[1:]
			if slashIdx := strings.LastIndexByte(rest, '/'); slashIdx > 0 {
				ord, err := strconv.Atoi(rest[slashIdx+1:])
				if err != nil {
					return nil, &painlessExceptionError{
						exType:  "IllegalArgumentException",
						message: fmt.Sprintf("error compiling dissect pattern [%s]: invalid append order in [%%%s]", pattern, token),
					}
				}
				spec.name = rest[:slashIdx]
				spec.order = ord
				spec.hasOrder = true
			} else {
				spec.name = rest
			}
		default:
			spec.kind = dissectFieldNormal
			spec.name = token
		}
		fields = append(fields, spec)
		pos = openIdx + 2 + closeRel + 1
	}

	ext := &DissectExtractor{
		Pattern:     pattern,
		prefixDelim: prefixDelim,
		fields:      fields,
	}
	globalDissectCache.put(pattern, ext)
	return ext, nil
}

// Extract matches `text` against the compiled Dissect pattern and returns the extracted
// map of keys, or `nil` when `text` does not match.
func (d *DissectExtractor) Extract(text string) map[string]any {
	if d == nil {
		return nil
	}
	if len(d.fields) == 0 {
		if text == d.prefixDelim {
			return map[string]any{}
		}
		return nil
	}
	if !strings.HasPrefix(text, d.prefixDelim) {
		return nil
	}
	rem := text[len(d.prefixDelim):]

	type appendPiece struct {
		order int
		seq   int
		val   string
		sep   string
	}
	out := make(map[string]any, len(d.fields))
	savedKeys := make(map[string]string)
	var orderedAppends map[string][]appendPiece

	for i, f := range d.fields {
		var captured string
		if f.delimAfter == "" {
			// Last field with empty trailing delimiter consumes remainder
			captured = rem
			rem = ""
		} else {
			idx := strings.Index(rem, f.delimAfter)
			if idx < 0 {
				return nil
			}
			// If this is the final field and has a trailing delimiter, match at the suffix if multiple occurrences exist
			if i == len(d.fields)-1 && !f.rightPad {
				if !strings.HasSuffix(rem, f.delimAfter) {
					return nil
				}
				idx = len(rem) - len(f.delimAfter)
			}
			captured = rem[:idx]
			rem = rem[idx+len(f.delimAfter):]
			if f.rightPad && len(f.delimAfter) > 0 {
				for strings.HasPrefix(rem, f.delimAfter) {
					rem = rem[len(f.delimAfter):]
				}
			}
		}

		switch f.kind {
		case dissectFieldSkip:
			// ignored
		case dissectFieldNormal:
			out[f.name] = captured
		case dissectFieldSaveKey:
			savedKeys[f.name] = captured
		case dissectFieldUseKey:
			if k, ok := savedKeys[f.name]; ok && k != "" {
				out[k] = captured
			}
		case dissectFieldAppend:
			if f.hasOrder {
				if orderedAppends == nil {
					orderedAppends = make(map[string][]appendPiece)
				}
				orderedAppends[f.name] = append(orderedAppends[f.name], appendPiece{
					order: f.order,
					seq:   i,
					val:   captured,
					sep:   f.joinSep,
				})
			} else {
				if prev, exists := out[f.name]; exists {
					out[f.name] = fmt.Sprintf("%v%s%s", prev, f.joinSep, captured)
				} else {
					out[f.name] = captured
				}
			}
		}
	}

	if rem != "" {
		return nil
	}

	for k, pieces := range orderedAppends {
		sort.SliceStable(pieces, func(i, j int) bool {
			if pieces[i].order != pieces[j].order {
				return pieces[i].order < pieces[j].order
			}
			return pieces[i].seq < pieces[j].seq
		})
		var sb strings.Builder
		if existing, hasEx := out[k]; hasEx {
			_, _ = fmt.Fprintf(&sb, "%v", existing)
		}
		for idx, p := range pieces {
			if idx > 0 || sb.Len() > 0 {
				sb.WriteString(p.sep)
			}
			sb.WriteString(p.val)
		}
		out[k] = sb.String()
	}

	return out
}

func evalGrokOrDissectMethodRound62(recVal any, mBare string, evalCallArgs func() ([]any, error)) (any, bool, error) {
	switch tv := recVal.(type) {
	case *GrokExtractor:
		if tv == nil {
			return nil, false, nil
		}
		switch mBare {
		case "extract":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) != 1 {
				return nil, true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Unable to find dynamic method [extract] with [%d] arguments for class [Grok].", len(args)),
				}
			}
			if args[0] == nil {
				return nil, true, nil
			}
			m := tv.Extract(fmt.Sprintf("%v", args[0]))
			if m == nil {
				return nil, true, nil
			}
			return m, true, nil
		case "toString":
			return tv.String(), true, nil
		}
	case *DissectExtractor:
		if tv == nil {
			return nil, false, nil
		}
		switch mBare {
		case "extract":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) != 1 {
				return nil, true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Unable to find dynamic method [extract] with [%d] arguments for class [Dissect].", len(args)),
				}
			}
			if args[0] == nil {
				return nil, true, nil
			}
			m := tv.Extract(fmt.Sprintf("%v", args[0]))
			if m == nil {
				return nil, true, nil
			}
			return m, true, nil
		case "toString":
			return tv.String(), true, nil
		}
	}
	return nil, false, nil
}

func unescapeCompileStringTokenRound62(lit string) (string, bool) {
	if strings.HasPrefix(lit, `"""`) && strings.HasSuffix(lit, `"""`) && len(lit) >= 6 {
		body := lit[3 : len(lit)-3]
		if len(body) > 0 && body[0] == '\r' {
			body = body[1:]
		}
		if len(body) > 0 && body[0] == '\n' {
			body = body[1:]
		}
		return unescapePainlessString(body), true
	}
	if len(lit) >= 2 && ((lit[0] == '\'' && lit[len(lit)-1] == '\'') || (lit[0] == '"' && lit[len(lit)-1] == '"')) {
		return unescapePainlessString(lit[1 : len(lit)-1]), true
	}
	return "", false
}

func evalCompileConstantStringTokensRound62(argToks []compileTokRound60) (string, bool) {
	if len(argToks) == 0 {
		return "", false
	}
	// Strip outer balanced parens
	for len(argToks) >= 2 && argToks[0].lit == "(" && argToks[len(argToks)-1].lit == ")" &&
		findMatchingTokenDelimRound60(argToks, 0, "(", ")") == len(argToks)-1 {
		argToks = argToks[1 : len(argToks)-1]
	}
	if len(argToks) == 0 {
		return "", false
	}
	var sb strings.Builder
	expectStr := true
	for _, tk := range argToks {
		if expectStr {
			if tk.kind != ctkStringRound60 {
				return "", false
			}
			val, ok := unescapeCompileStringTokenRound62(tk.lit)
			if !ok {
				return "", false
			}
			sb.WriteString(val)
			expectStr = false
		} else {
			if tk.kind != ctkOpRound60 || tk.lit != "+" {
				return "", false
			}
			expectStr = true
		}
	}
	if expectStr {
		return "", false
	}
	return sb.String(), true
}

func splitCompileArgSlicesRound62(toks []compileTokRound60) [][]compileTokRound60 {
	if len(toks) == 0 {
		return nil
	}
	var out [][]compileTokRound60
	depth := 0
	start := 0
	for i, tk := range toks {
		if tk.kind == ctkOpenDelimRound60 {
			depth++
			continue
		}
		if tk.kind == ctkCloseDelimRound60 {
			if depth > 0 {
				depth--
			}
			continue
		}
		if tk.kind == ctkCommaRound60 && depth == 0 {
			out = append(out, toks[start:i])
			start = i + 1
		}
	}
	out = append(out, toks[start:])
	return out
}

// validateGrokAndDissectCallsRound62 enforces Elasticsearch's compile-time checks
// on built-in `grok(pattern)` and `dissect(pattern)` calls:
//  1. Every argument must be a compile-time constant string literal (`all arguments to [grok] must be constant but the [1] argument isn't`).
//  2. The constant pattern must compile cleanly without invalid group names or Onigmo warnings.
func validateGrokAndDissectCallsRound62(src string, toks []compileTokRound60, userFuncs map[string]bool) error {
	for i := 0; i < len(toks); i++ {
		tk := toks[i]
		if tk.kind != ctkIdentRound60 || (tk.lit != "grok" && tk.lit != "dissect") {
			continue
		}
		if i > 0 && (toks[i-1].kind == ctkDotRound60 || toks[i-1].kind == ctkMethodRefRound60) {
			continue
		}
		if i+1 >= len(toks) || toks[i+1].lit != "(" {
			continue
		}
		// Skip top-level function declaration headers `def grok(String p) { ... }`
		closeP := findMatchingTokenDelimRound60(toks, i+1, "(", ")")
		if closeP < 0 {
			continue
		}
		if i > 0 && toks[i-1].kind == ctkIdentRound60 && closeP+1 < len(toks) && toks[closeP+1].lit == "{" {
			continue
		}
		argSlices := splitCompileArgSlicesRound62(toks[i+2 : closeP])
		arity := len(argSlices)
		if userFuncs[fmt.Sprintf("%s/%d", tk.lit, arity)] {
			continue
		}
		if arity != 1 {
			return newScriptCompileErrorAtRound60(src, tk.offset, fmt.Sprintf("illegal_argument_exception: Unable to find dynamic method [%s] with [%d] arguments", tk.lit, arity))
		}
		constPat, isConst := evalCompileConstantStringTokensRound62(argSlices[0])
		if !isConst {
			argOff := tk.offset
			if len(argSlices[0]) > 0 {
				argOff = argSlices[0][0].offset
			}
			return newScriptCompileErrorAtRound60(
				src,
				argOff,
				fmt.Sprintf("illegal_argument_exception: all arguments to [%s] must be constant but the [1] argument isn't", tk.lit),
			)
		}
		argOff := argSlices[0][0].offset
		if tk.lit == "grok" {
			if _, err := CompileGrokPattern(constPat); err != nil {
				msg := err.Error()
				if pe, ok := err.(*painlessExceptionError); ok {
					msg = "illegal_argument_exception: " + pe.message
				}
				return newScriptCompileErrorAtRound60(src, argOff, msg)
			}
		} else {
			if _, err := CompileDissectPattern(constPat); err != nil {
				msg := err.Error()
				if pe, ok := err.(*painlessExceptionError); ok {
					msg = "illegal_argument_exception: " + pe.message
				}
				return newScriptCompileErrorAtRound60(src, argOff, msg)
			}
		}
	}
	return nil
}

// MergeCompositeEmittedMaps merges all `map[string]any` entries emitted during a
// `composite` runtime-field execution into a single flat/nested subfield map.
func MergeCompositeEmittedMaps(emitted []any) map[string]any {
	if len(emitted) == 0 {
		return nil
	}
	merged := make(map[string]any)
	for _, item := range emitted {
		m, ok := item.(map[string]any)
		if !ok || m == nil {
			continue
		}
		for k, v := range m {
			if isInternalPainlessMapKey(m, k) || v == nil {
				continue
			}
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func handleCompositeEmitRound62(budget *evalBudget, rawArgs []any) (any, error) {
	if len(rawArgs) == 1 {
		if isEmptyOptionalOrNilPainless(rawArgs[0]) {
			// In Elasticsearch CompositeFieldScript.emit(Map), emitting null (e.g. when grok/dissect
			// returns null on a non-matching message in 110_composite.yml) is a clean no-op!
			return nil, nil
		}
		m, ok := rawArgs[0].(map[string]any)
		if !ok {
			return nil, &painlessExceptionError{
				exType:  "ClassCastException",
				message: fmt.Sprintf("Cannot emit %T in composite_field context; expected Map", rawArgs[0]),
			}
		}
		cleaned := make(map[string]any, len(m))
		for k, v := range m {
			if isInternalPainlessMapKey(m, k) || isEmptyOptionalOrNilPainless(v) {
				continue
			}
			cleaned[k] = v
		}
		if len(cleaned) > 0 && budget != nil {
			budget.emittedVals = append(budget.emittedVals, cleaned)
		}
		return cleaned, nil
	}
	if len(rawArgs) == 2 {
		if isEmptyOptionalOrNilPainless(rawArgs[0]) {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "Cannot emit null field name",
			}
		}
		if isEmptyOptionalOrNilPainless(rawArgs[1]) {
			return nil, nil
		}
		subField := fmt.Sprintf("%v", rawArgs[0])
		entry := map[string]any{subField: rawArgs[1]}
		if budget != nil {
			budget.emittedVals = append(budget.emittedVals, entry)
		}
		return entry, nil
	}
	return nil, &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("composite emit() takes 1 or 2 arguments, got %d", len(rawArgs)),
	}
}

// ============================================================================
// Round 62 Deliverable 4: Lazy `DenseVectorDocValue` & `FieldVal` Coercions
// ============================================================================

func (v *DenseVectorVal) isMissingVectorRound62() bool {
	if v == nil {
		return true
	}
	if v.IsDocValue && !v.Present {
		return true
	}
	return len(v.Floats) == 0
}

func newMissingDenseVectorDocValueErrorRound62() error {
	return &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: DenseVectorMissingMessage,
	}
}

func (v *DenseVectorVal) vectorElementsSliceRound62(budget *evalBudget) []any {
	if v == nil || len(v.Floats) == 0 {
		return []any{}
	}
	if (v.ElemType == "byte" || v.ElemType == "bit") && len(v.Bytes) == len(v.Floats) {
		out := make([]any, len(v.Bytes))
		for i, b := range v.Bytes {
			out[i] = int64(b)
		}
		return markTypedArraySliceRound59(budget, out, "byte[]")
	}
	out := make([]any, len(v.Floats))
	for i, f := range v.Floats {
		out[i] = f
	}
	return markTypedArraySliceRound59(budget, out, "float[]")
}

func javaQueryVectorClassNameRound62(val any) string {
	if val == nil {
		return "null"
	}
	cls := painlessClassForValuePainless(val)
	if cls.fullName != "" {
		return cls.fullName
	}
	return fmt.Sprintf("%T", val)
}

func parseDenseVectorQueryArgRound62(qVal any, elemType string, allowHex bool) ([]float32, []int8, error) {
	if qVal == nil {
		return nil, nil, &painlessExceptionError{
			exType:  "NullPointerException",
			message: "query vector must not be null",
		}
	}
	if s, isStr := qVal.(string); isStr {
		if allowHex {
			if i8, f32, err := DecodeHexSignedByteVector(s); err == nil {
				return f32, i8, nil
			}
		}
		return nil, nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Cannot use vector [%s] with class [java.lang.String] as query vector", s),
		}
	}
	switch qVal.(type) {
	case []any, []float32, []float64, []int8, []int, []int64, *DenseVectorVal:
		return parseVectorValueRound61(qVal, elemType)
	default:
		return nil, nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Cannot use vector [%s] with class [%s] as query vector", FormatValueSafe(qVal), javaQueryVectorClassNameRound62(qVal)),
		}
	}
}

func coerceFieldValDefaultRound62(fv *FieldVal, defaultVal any) any {
	if defaultVal == nil || fv == nil {
		return defaultVal
	}
	switch fv.FieldType {
	case "float", "half_float":
		if f32, ok := defaultVal.(float32); ok {
			return f32
		}
		if f64, ok := toFloat64WithRawPainless(defaultVal); ok {
			if fv.FieldType == "half_float" {
				return QuantizeHalfFloat(f64)
			}
			return float32(f64)
		}
	case "double", "scaled_float":
		if f64, ok := defaultVal.(float64); ok {
			return f64
		}
		if f64, ok := toFloat64WithRawPainless(defaultVal); ok {
			return f64
		}
	case "date", "date_nanos":
		if z, ok := defaultVal.(*ZonedDateTimeVal); ok {
			return z
		}
		if z, ok := parseZonedDateTimeValRound60(defaultVal, fv.FieldType == "date_nanos"); ok {
			return z
		}
	}
	return defaultVal
}

func resolveTemporalStringPropertyRound62(strVal, seg string) (any, bool) {
	switch seg {
	case "year", "monthValue", "monthOfYear", "month", "monthEnum", "dayOfMonth", "dayOfYear", "date",
		"hour", "hourOfDay", "minute", "minuteOfHour", "second", "secondOfMinute", "nano",
		"dayOfWeek", "dayOfWeekEnum", "millis":
	default:
		return nil, false
	}
	tm, ok := parsePainlessDateTime(strVal)
	if !ok {
		return nil, false
	}
	switch seg {
	case "year":
		return int64(tm.Year()), true
	case "monthValue", "monthOfYear":
		return int64(tm.Month()), true
	case "month", "monthEnum":
		return newMonthEnumRound62(tm.Month()), true
	case "dayOfMonth", "date":
		return int64(tm.Day()), true
	case "dayOfYear":
		return int64(tm.YearDay()), true
	case "hour", "hourOfDay":
		return int64(tm.Hour()), true
	case "minute", "minuteOfHour":
		return int64(tm.Minute()), true
	case "second", "secondOfMinute":
		return int64(tm.Second()), true
	case "nano":
		return int64(tm.Nanosecond()), true
	case "dayOfWeek", "dayOfWeekEnum":
		return newDayOfWeekEnumFromWeekdayRound60(tm.Weekday()), true
	case "millis":
		return tm.UnixMilli(), true
	}
	return nil, false
}

func isFieldMappedInContextRound62(sourceMap, params map[string]any, fieldPath string) bool {
	clean := strings.ReplaceAll(fieldPath, "\x00", ".")
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		if strictSet, ok := m["__strict_doc_fields"].(map[string]bool); ok && strictSet != nil && strictSet[clean] {
			return true
		}
		if ftMap, ok := m["__field_types"].(map[string]string); ok && ftMap != nil && ftMap[clean] != "" {
			return true
		}
	}
	return false
}
