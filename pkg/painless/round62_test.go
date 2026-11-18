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
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRound62_Deliverable1_ZonedDateTimeValCompleteDispatchAndDateParse(t *testing.T) {
	t.Run("40_date_yml_DocIterationAndSourceParse", func(t *testing.T) {
		fieldTypes := map[string]string{"timestamp": "date"}

		// 1. Iterating doc['timestamp'] and calling dt.plus(1, ChronoUnit.DAYS).toEpochMilli()
		doc := map[string]any{"timestamp": "2018-01-16T17:41:34.000Z"}
		emitted, err := EvalEmitContext(
			"for (def dt : doc['timestamp']) { emit(dt.plus(1, ChronoUnit.DAYS).toEpochMilli()); }",
			"date_field",
			doc,
			doc,
			nil,
			fieldTypes,
		)
		if err != nil {
			t.Fatalf("40_date doc['timestamp'] plus failed: %v", err)
		}
		if len(emitted) != 1 || emitted[0] != "2018-01-17T17:41:34.000Z" {
			t.Fatalf("unexpected emitted date: %#v", emitted)
		}

		// 2. tomorrow_from_source with BOTH numeric epoch millis and ISO string via parse(...)
		srcScript := `
			ZonedDateTime dt = ZonedDateTime.ofInstant(Instant.ofEpochMilli(parse(params._source.timestamp)), ZoneId.of('Z'));
			emit(dt.plus(1, ChronoUnit.DAYS).toEpochMilli());
		`
		emittedNum, err := EvalEmitContext(
			srcScript,
			"date_field",
			map[string]any{"timestamp": int64(1516124494000)},
			map[string]any{"timestamp": int64(1516124494000)},
			nil,
			fieldTypes,
		)
		if err != nil || len(emittedNum) != 1 || emittedNum[0] != "2018-01-17T17:41:34.000Z" {
			t.Fatalf("tomorrow_from_source numeric failed: emitted=%#v err=%v", emittedNum, err)
		}

		emittedISO, err := EvalEmitContext(
			srcScript,
			"date_field",
			map[string]any{"timestamp": "2018-01-18T17:41:34.000Z"},
			map[string]any{"timestamp": "2018-01-18T17:41:34.000Z"},
			nil,
			fieldTypes,
		)
		if err != nil || len(emittedISO) != 1 || emittedISO[0] != "2018-01-19T17:41:34.000Z" {
			t.Fatalf("tomorrow_from_source ISO string failed: emitted=%#v err=%v", emittedISO, err)
		}

		// Custom __runtime_date_format + float/ZonedDateTime/Instant/error branches of parse(...)
		emittedCustomFmt, err := EvalEmitContext(
			srcScript,
			"date_field",
			map[string]any{"timestamp": "2018-01-18 17:41:34"},
			map[string]any{"timestamp": "2018-01-18 17:41:34"},
			map[string]any{"__runtime_date_format": "yyyy-MM-dd HH:mm:ss"},
			fieldTypes,
		)
		if err != nil || len(emittedCustomFmt) != 1 || emittedCustomFmt[0] != "2018-01-19T17:41:34.000Z" {
			t.Fatalf("custom __runtime_date_format parse failed: emitted=%#v err=%v", emittedCustomFmt, err)
		}

		// 65_runtime_doc_values.yml: date.plusDays(1).millis
		emittedPlusDayMillis, err := EvalEmitContext(
			"for (def date : doc['timestamp']) { emit(date.plusDays(1).millis); }",
			"long_field",
			doc,
			doc,
			nil,
			fieldTypes,
		)
		if err != nil || len(emittedPlusDayMillis) != 1 || emittedPlusDayMillis[0] != int64(1516210894000) {
			t.Fatalf("65_runtime_doc_values date.plusDays(1).millis failed: %#v, err=%v", emittedPlusDayMillis, err)
		}
	})

	t.Run("ZonedDateTimeValFullMethodParityAndExceptions", func(t *testing.T) {
		doc := NormalizeDocValuesForScript(
			map[string]any{
				"ts":      "2024-02-29T14:35:45.123Z",
				"ts_nano": "2024-02-29T14:35:45.123456789Z",
			},
			map[string]string{
				"ts":      "date",
				"ts_nano": "date_nanos",
			},
		)
		params := map[string]any{
			"__field_types": map[string]string{
				"ts":      "date",
				"ts_nano": "date_nanos",
			},
		}
		script := `
			def dt = doc['ts'].value;
			def dtNano = doc['ts_nano'].value;
			def plusPeriod = dt.plus(Period.of(1, 1, 2));
			def minusDur = dt.minus(Duration.ofHours(2));
			def u1 = dt.plus(2, ChronoUnit.DAYS).minus(3, ChronoUnit.HOURS).plus(15, ChronoUnit.MINUTES).minus(10, ChronoUnit.SECONDS);
			def u2 = dt.plus(500, ChronoUnit.MILLIS).plus(200, ChronoUnit.MICROS).plus(50, ChronoUnit.NANOS).plus(1, ChronoUnit.HALF_DAYS);
			def u3 = dt.plus(1, ChronoUnit.WEEKS).plus(1, ChronoUnit.MONTHS).plus(1, ChronoUnit.YEARS).plus(1, ChronoUnit.DECADES).plus(1, ChronoUnit.CENTURIES).plus(1, ChronoUnit.MILLENNIA);
			def chainBase = dt.withMonth(3).withDayOfMonth(15);
			def chain = chainBase.plusYears(1).minusYears(1).plusMonths(2).minusMonths(2).plusWeeks(1).minusWeeks(1)
				.plusDays(3).minusDays(3).plusHours(4).minusHours(4).plusMinutes(5).minusMinutes(5)
				.plusSeconds(6).minusSeconds(6).plusMillis(7).minusMillis(7).plusNanos(8).minusNanos(8);
			def leapClamp = dt.plusYears(1);
			def withChain = dt.withYear(2023).withMonth(4).withDayOfMonth(15).withHour(8).withMinute(20).withSecond(30).withNano(0);
			def withDoy = dt.withDayOfYear(60);
			def withAdj1 = dt.with(TemporalAdjusters.firstDayOfMonth());
			def withAdj2 = dt.with(DayOfWeek.MONDAY);
			def withAdj3 = dt.with(dt.month);
			def withField = dt.with(ChronoField.YEAR, 2025);
			def zonedNY = dt.withZoneSameInstant(ZoneId.of('America/New_York'));
			def zonedLocal = dt.withZoneSameLocal(ZoneOffset.ofHours(2));
			def truncDay = dtNano.truncatedTo(ChronoUnit.DAYS);
			def truncHalf = dtNano.truncatedTo(ChronoUnit.HALF_DAYS);
			def truncHr = dtNano.truncatedTo(ChronoUnit.HOURS);
			def truncMin = dtNano.truncatedTo(ChronoUnit.MINUTES);
			def truncSec = dtNano.truncatedTo(ChronoUnit.SECONDS);
			def truncMs = dtNano.truncatedTo(ChronoUnit.MILLIS);
			def truncUs = dtNano.truncatedTo(ChronoUnit.MICROS);
			def truncNs = dtNano.truncatedTo(ChronoUnit.NANOS);
			int yoe = dt.get(ChronoField.YEAR_OF_ERA);
			int qoy = dt.get(IsoFields.QUARTER_OF_YEAR);
			long instSec = dt.getLong(ChronoField.INSTANT_SECONDS);
			boolean sup1 = dt.isSupported(ChronoField.YEAR) && dt.isSupported(ChronoUnit.DAYS) && !dt.isSupported(null);
			boolean cmpOk = chainBase.plusDays(1).isAfter(chainBase) && chainBase.isBefore(chainBase.plusDays(1)) && chainBase.isEqual(chain) &&
				chainBase.equals(chain) && chainBase.compareTo(chainBase.plusDays(1)) < 0 && chainBase.plusDays(1).compareTo(chainBase) > 0 && chainBase.compareTo(chain) == 0 && leapClamp.getDayOfMonth() == 28;
			long untilDays = dt.until(dt.plusDays(5), ChronoUnit.DAYS);
			String fmtOut = dt.format(DateTimeFormatter.ofPattern('yyyy/MM/dd HH:mm'));

			int errs = 0;
			try { dt.get(ChronoField.INSTANT_SECONDS); } catch (Exception e) { errs++; }
			try { dt.truncatedTo(ChronoUnit.MONTHS); } catch (Exception e) { errs++; }
			try { dt.plus(1, 'BAD_UNIT'); } catch (Exception e) { errs++; }
			try { dt.getCenturyOfEra(); } catch (Exception e) { errs++; }
			try { dt.nonExistentZeroArg(); } catch (IllegalArgumentException e) { errs++; }
			try { dt.nonExistentWithArg(1); } catch (IllegalArgumentException e) { errs++; }
			try { parse(null); } catch (NullPointerException e) { errs++; }
			try { parse('not-a-date'); } catch (IllegalArgumentException e) { errs++; }

			return [
				'plusPeriod': plusPeriod.toString(),
				'minusDurHour': minusDur.getHour(),
				'u1Hour': u1.getHour(),
				'u2Day': u2.getDayOfMonth(),
				'u3Year': u3.getYear(),
				'chainEq': chain.toEpochMilli() == chainBase.toEpochMilli(),
				'withChain': withChain.toString(),
				'withDoyMonth': withDoy.getMonthValue(),
				'withAdj1Dom': withAdj1.getDayOfMonth(),
				'withAdj2Dow': withAdj2.getDayOfWeek(),
				'withAdj3Mon': withAdj3.getMonthValue(),
				'withFieldYear': withField.getYear(),
				'zonedNYZone': zonedNY.getZone(),
				'zonedNYStr': zonedNY.toString().endsWith('[America/New_York]'),
				'zonedLocalOff': zonedLocal.getOffset(),
				'truncDay': truncDay.toString(),
				'truncHalfHr': truncHalf.getHour(),
				'truncHrMin': truncHr.getMinute(),
				'truncMinSec': truncMin.getSecond(),
				'truncSecNano': truncSec.getNano(),
				'truncMsNano': truncMs.getNano(),
				'truncUsNano': truncUs.getNano(),
				'truncNsNano': truncNs.getNano(),
				'yoe': yoe,
				'qoy': qoy,
				'instSec': instSec == dt.toEpochSecond() && instSec == dt.getEpochSecond(),
				'sup1': sup1,
				'cmpOk': cmpOk,
				'untilDays': untilDays,
				'fmtOut': fmtOut,
				'localDate': dt.toLocalDate(),
				'localDateTime': dt.toLocalDateTime(),
				'localTime': dt.toLocalTime(),
				'offsetDT': dt.toOffsetDateTime() != null,
				'instantMs': dt.toInstant().toEpochMilli() == dt.toEpochMilli(),
				'chronology': dt.getChronology(),
				'zoneProp': dt.zone == 'Z' && dt.offset == 'Z',
				'hc': dt.hashCode() != 0,
				'parseFloat': parse(1516124494000.0) == 1516124494000L,
				'parseZdt': parse(dt) == dt.toEpochMilli(),
				'parseInst': parse(dt.toInstant()) == dt.toEpochMilli(),
				'errs': errs
			];
		`
		res, err := Eval(doc, script, params)
		if err != nil {
			t.Fatalf("ZonedDateTimeVal full parity script failed: %v", err)
		}
		got := res.(map[string]any)
		checks := map[string]any{
			"plusPeriod":    "2025-03-31T14:35:45.123Z",
			"minusDurHour":  int64(12),
			"u1Hour":        int64(11),
			"u2Day":         int64(1),
			"u3Year":        int64(3135),
			"chainEq":       true,
			"withChain":     "2023-04-15T08:20:30.000Z",
			"withDoyMonth":  int64(2),
			"withAdj1Dom":   int64(1),
			"withAdj2Dow":   int64(1),
			"withAdj3Mon":   int64(2),
			"withFieldYear": int64(2025),
			"zonedNYZone":   "America/New_York",
			"zonedNYStr":    true,
			"zonedLocalOff": "+02:00",
			"truncDay":      "2024-02-29T00:00:00.000Z",
			"truncHalfHr":   int64(12),
			"truncHrMin":    int64(0),
			"truncMinSec":   int64(0),
			"truncSecNano":  int64(0),
			"truncMsNano":   int64(123000000),
			"truncUsNano":   int64(123456000),
			"truncNsNano":   int64(123456789),
			"yoe":           int64(2024),
			"qoy":           int64(1),
			"instSec":       true,
			"sup1":          true,
			"cmpOk":         true,
			"untilDays":     int64(5),
			"fmtOut":        "2024/02/29 14:35",
			"localDate":     "2024-02-29",
			"localDateTime": "2024-02-29T14:35:45.123",
			"localTime":     "14:35:45.123",
			"offsetDT":      true,
			"instantMs":     true,
			"chronology":    "ISO",
			"zoneProp":      true,
			"hc":            true,
			"parseFloat":    true,
			"parseZdt":      true,
			"parseInst":     true,
			"errs":          int64(8),
		}
		for k, w := range checks {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, got[k], w)
			}
		}
	})
}

func TestRound62_Deliverable2_DayOfWeekAndMonthDisplayNameAndLocales(t *testing.T) {
	t.Run("10_keyword_yml_BothDocValueAndFromSource", func(t *testing.T) {
		fieldTypes := map[string]string{"timestamp": "date"}
		// 1516124494000 == Tuesday 2018-01-16T17:41:34.000Z
		doc := map[string]any{"timestamp": int64(1516124494000)}

		// 1. doc['timestamp'].value.dayOfWeekEnum.getDisplayName(TextStyle.FULL, Locale.ENGLISH)
		e1, err := EvalEmitContext(
			"emit(doc['timestamp'].value.dayOfWeekEnum.getDisplayName(TextStyle.FULL, Locale.ENGLISH))",
			"keyword_field",
			doc,
			doc,
			nil,
			fieldTypes,
		)
		if err != nil || len(e1) != 1 || e1[0] != "Tuesday" {
			t.Fatalf("day_of_week doc value failed: %#v, err=%v", e1, err)
		}

		// 2. ZonedDateTime.ofInstant(...).dayOfWeek.getDisplayName(TextStyle.FULL, Locale.ENGLISH)
		e2, err := EvalEmitContext(
			"ZonedDateTime dt = ZonedDateTime.ofInstant(Instant.ofEpochMilli(params._source.timestamp), ZoneId.of('Z')); emit(dt.dayOfWeek.getDisplayName(TextStyle.FULL, Locale.ENGLISH));",
			"keyword_field",
			doc,
			doc,
			nil,
			fieldTypes,
		)
		if err != nil || len(e2) != 1 || e2[0] != "Tuesday" {
			t.Fatalf("day_of_week_from_source failed: %#v, err=%v", e2, err)
		}
	})

	t.Run("AllTextStylesLocalesAndEnumMethods", func(t *testing.T) {
		doc := NormalizeDocValuesForScript(
			map[string]any{"ts": "2024-02-29T12:00:00.000Z"}, // Thursday, February
			map[string]string{"ts": "date"},
		)
		script := `
			def zdt = doc['ts'].value;
			DayOfWeekEnum dow = zdt.dayOfWeekEnum;
			MonthEnum mon = zdt.getMonth();
			ZonedDateTime strDt = ZonedDateTime.parse('2024-02-29T12:00:00Z');

			int errs = 0;
			try { dow.getDisplayName(TextStyle.FULL); } catch (IllegalArgumentException e) { errs++; }
			try { dow.getDisplayName(null, Locale.ENGLISH); } catch (NullPointerException e) { errs++; }
			try { dow.getDisplayName('NOT_A_STYLE', Locale.ENGLISH); } catch (IllegalArgumentException e) { errs++; }
			try { mon.getDisplayName(TextStyle.FULL); } catch (IllegalArgumentException e) { errs++; }
			try { mon.getDisplayName('NOT_A_STYLE', Locale.ENGLISH); } catch (IllegalArgumentException e) { errs++; }

			return [
				'enFull': dow.getDisplayName(TextStyle.FULL, Locale.ENGLISH),
				'enShort': dow.getDisplayName(TextStyle.SHORT, Locale.US),
				'enNarrow': dow.getDisplayName(TextStyle.NARROW, Locale.UK),
				'rootNarrow': dow.getDisplayName(TextStyle.NARROW_STANDALONE, Locale.ROOT),
				'frFull': dow.getDisplayName(TextStyle.FULL_STANDALONE, Locale.FRENCH),
				'frShort': dow.getDisplayName(TextStyle.SHORT, Locale.forLanguageTag('fr-FR')),
				'deFull': dow.getDisplayName(TextStyle.FULL, Locale.GERMAN),
				'deShort': dow.getDisplayName(TextStyle.SHORT, new Locale('de', 'DE')),
				'deShortSA': dow.getDisplayName(TextStyle.SHORT_STANDALONE, Locale.GERMAN),
				'itFull': dow.getDisplayName(TextStyle.FULL, Locale.ITALIAN),
				'itShort': dow.getDisplayName(TextStyle.SHORT, Locale.ITALIAN),
				'jaFull': dow.getDisplayName(TextStyle.FULL, Locale.JAPANESE),
				'jaShort': dow.getDisplayName(TextStyle.SHORT, Locale.JAPANESE),
				'zhFull': dow.getDisplayName(TextStyle.FULL, Locale.CHINESE),
				'zhShort': dow.getDisplayName(TextStyle.SHORT, Locale.CHINESE),
				'zhNarrow': dow.getDisplayName(TextStyle.NARROW, Locale.CHINESE),
				'dowVal': dow.getValue() == 4 && dow.value == 4 && dow.name() == 'THURSDAY' && dow.toString() == 'THURSDAY',
				'dowPlusMinus': dow.plus(4).name() == 'MONDAY' && dow.minus(5).name() == 'SATURDAY',
				'dowCmp': dow.compareTo(DayOfWeek.MONDAY) == 3 && dow.equals('THURSDAY'),
				'monEnFull': mon.getDisplayName(TextStyle.FULL, Locale.ENGLISH),
				'monEnShort': mon.getDisplayName(TextStyle.SHORT, Locale.ENGLISH),
				'monEnNarrow': mon.getDisplayName(TextStyle.NARROW, Locale.ENGLISH),
				'monFrFull': mon.getDisplayName(TextStyle.FULL, Locale.FRENCH),
				'monFrShort': mon.getDisplayName(TextStyle.SHORT, Locale.FRENCH),
				'monDeShort': mon.getDisplayName(TextStyle.SHORT, Locale.GERMAN),
				'monDeShortSA': mon.getDisplayName(TextStyle.SHORT_STANDALONE, Locale.GERMAN),
				'monItFull': mon.getDisplayName(TextStyle.FULL, Locale.ITALIAN),
				'monJaFull': mon.getDisplayName(TextStyle.FULL, Locale.JAPANESE),
				'monJaNarrow': mon.getDisplayName(TextStyle.NARROW, Locale.JAPANESE),
				'monZhFull': mon.getDisplayName(TextStyle.FULL, Locale.CHINESE),
				'monZhShort': mon.getDisplayName(TextStyle.SHORT, Locale.CHINESE),
				'monMeta': mon.getValue() == 2 && mon.value == 2 && mon.minLength() == 28 && mon.maxLength() == 29 &&
					mon.length(true) == 29 && mon.length(false) == 28 && mon.firstMonthOfQuarter().name() == 'JANUARY' &&
					mon.plus(11).name() == 'JANUARY' && mon.minus(3).name() == 'NOVEMBER' && mon == 'FEBRUARY',
				'strDtParity': strDt.getDayOfWeekEnum().getDisplayName(TextStyle.FULL, Locale.ENGLISH) == 'Thursday' &&
					strDt.getMonthEnum().getDisplayName(TextStyle.FULL, Locale.ENGLISH) == 'February' &&
					strDt.monthEnum.getDisplayName(TextStyle.SHORT, Locale.ENGLISH) == 'Feb' &&
					DayOfWeek.FRIDAY.getDisplayName(TextStyle.SHORT, Locale.ENGLISH) == 'Fri' &&
					Month.AUGUST.getDisplayName(TextStyle.SHORT, Locale.ENGLISH) == 'Aug',
				'errs': errs
			];
		`
		res, err := Eval(doc, script, nil)
		if err != nil {
			t.Fatalf("AllTextStylesLocalesAndEnumMethods failed: %v", err)
		}
		got := res.(map[string]any)
		want := map[string]any{
			"enFull":       "Thursday",
			"enShort":      "Thu",
			"enNarrow":     "T",
			"rootNarrow":   "T",
			"frFull":       "jeudi",
			"frShort":      "jeu.",
			"deFull":       "Donnerstag",
			"deShort":      "Do.",
			"deShortSA":    "Do",
			"itFull":       "giovedì",
			"itShort":      "gio",
			"jaFull":       "木曜日",
			"jaShort":      "木",
			"zhFull":       "星期四",
			"zhShort":      "周四",
			"zhNarrow":     "四",
			"dowVal":       true,
			"dowPlusMinus": true,
			"dowCmp":       true,
			"monEnFull":    "February",
			"monEnShort":   "Feb",
			"monEnNarrow":  "F",
			"monFrFull":    "février",
			"monFrShort":   "févr.",
			"monDeShort":   "Feb.",
			"monDeShortSA": "Feb",
			"monItFull":    "febbraio",
			"monJaFull":    "2月",
			"monJaNarrow":  "2",
			"monZhFull":    "二月",
			"monZhShort":   "2月",
			"monMeta":      true,
			"strDtParity":  true,
			"errs":         int64(5),
		}
		for k, w := range want {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, got[k], w)
			}
		}

		// Verify MonthEnum JSON marshaling & FormatValueSafe
		me := newMonthEnumRound62(time.April)
		jb, err := json.Marshal(me)
		if err != nil || string(jb) != `"APRIL"` || FormatValueSafe(me) != "APRIL" {
			t.Fatalf("unexpected MonthEnum marshal/format: %s, %v", string(jb), err)
		}
	})
}

func TestRound62_Deliverable3_GrokDissectCompileValidationAndCompositeEmit(t *testing.T) {
	t.Run("250_grok_yml_And_110_composite_yml", func(t *testing.T) {
		fieldTypes := map[string]string{"message": "keyword"}

		// Matching Apache log with numeric bytes
		docMatch := map[string]any{
			"message": `40.135.0.0 - - [30/Apr/1998:14:30:17 -0500] "GET /images/hm_bg.jpg HTTP/1.0" 200 24736`,
		}
		emitted1, err := EvalEmitContext(
			`emit(grok('%{COMMONAPACHELOG}').extract(doc["message"].value))`,
			"composite_field",
			docMatch,
			docMatch,
			nil,
			fieldTypes,
		)
		if err != nil {
			t.Fatalf("grok COMMONAPACHELOG composite emit failed: %v", err)
		}
		merged1 := MergeCompositeEmittedMaps(emitted1)
		if merged1["clientip"] != "40.135.0.0" || merged1["verb"] != "GET" ||
			merged1["request"] != "/images/hm_bg.jpg" || merged1["response"] != "200" || merged1["bytes"] != "24736" {
			t.Fatalf("unexpected grok extracted map: %#v", merged1)
		}

		// Apache 304 log with `-` for bytes -> `bytes` capture does NOT participate and is omitted
		doc304 := map[string]any{
			"message": `232.0.0.0 - - [30/Apr/1998:14:30:25 -0500] "GET /images/hm_bg.jpg HTTP/1.0" 304 -`,
		}
		emitted304, err := EvalEmitContext(
			`emit(grok('%{COMMONAPACHELOG}').extract(doc["message"].value))`,
			"composite_field",
			doc304,
			doc304,
			nil,
			fieldTypes,
		)
		if err != nil {
			t.Fatalf("grok 304 log failed: %v", err)
		}
		merged304 := MergeCompositeEmittedMaps(emitted304)
		if _, hasBytes := merged304["bytes"]; hasBytes || merged304["response"] != "304" {
			t.Fatalf("expected omitted bytes on 304 '-', got %#v", merged304)
		}

		// Non-matching message -> grok().extract(...) returns null -> emit(null) in composite context is a clean no-op!
		docNonMatch := map[string]any{"message": "completely unrelated line"}
		emittedNonMatch, err := EvalEmitContext(
			`emit(grok('%{COMMONAPACHELOG}').extract(doc["message"].value))`,
			"composite_field",
			docNonMatch,
			docNonMatch,
			nil,
			fieldTypes,
		)
		if err != nil || len(emittedNonMatch) != 0 || MergeCompositeEmittedMaps(emittedNonMatch) != nil {
			t.Fatalf("expected empty emitted slice on non-matching grok in composite context, got %#v, err=%v", emittedNonMatch, err)
		}

		// 111_search_time_composite.yml: 2-arg emit(String subField, Object value)
		emitted2Arg, err := EvalEmitContext(
			`emit('shouldReturn', true); emit('count', 42); emit('ignoredNull', null);`,
			"composite",
			docMatch,
			docMatch,
			nil,
			fieldTypes,
		)
		if err != nil {
			t.Fatalf("2-arg composite emit failed: %v", err)
		}
		merged2Arg := MergeCompositeEmittedMaps(emitted2Arg)
		if merged2Arg["shouldReturn"] != true || merged2Arg["count"] != int64(42) || len(merged2Arg) != 2 {
			t.Fatalf("unexpected 2-arg composite merged map: %#v", merged2Arg)
		}

		// Typed Grok conversions (:int, :long, :float, :double, :boolean), ECS bracket paths, and Onigmo (?<name>...) groups
		typedRes, err := Eval(
			map[string]any{"line": "10.0.0.1 512 9999999999 1.5 2.25 true custom_val"},
			`
				Grok g = grok('%{IPV4:[host][ip]} %{NUMBER:status:int} %{NUMBER:big:long} %{NUMBER:lat:float} %{NUMBER:dbl:double} %{WORD:ok:boolean} (?<tag>[a-z_]+)');
				Map m = g.extract(ctx._source.line);
				return [
					'ip': m.host.ip,
					'status': m.status,
					'big': m.big,
					'lat': m.lat,
					'dbl': m.dbl,
					'ok': m.ok,
					'tag': m.tag,
					'nullIn': g.extract(null) == null,
					'str': g.toString().startsWith('Grok[')
				];
			`,
			nil,
		)
		if err != nil {
			t.Fatalf("typed grok script failed: %v", err)
		}
		tm := typedRes.(map[string]any)
		if tm["ip"] != "10.0.0.1" || tm["status"] != int64(512) || tm["big"] != int64(9999999999) ||
			tm["lat"] != float32(1.5) || tm["dbl"] != 2.25 || tm["ok"] != true || tm["tag"] != "custom_val" ||
			tm["nullIn"] != true || tm["str"] != true {
			t.Fatalf("unexpected typed grok result: %#v", tm)
		}
	})

	t.Run("260_dissect_yml_ModifiersAndExtraction", func(t *testing.T) {
		res, err := Eval(
			map[string]any{
				"apache": `247.37.0.0 - - [30/Apr/1998:14:30:59 -0500] "GET /english/venues/cities/images/montpellier/18.gif HTTP/1.0" 200 3171`,
				"order":  "Dec 16 2024 host1",
				"kv":     "cpu=87 mem=42",
				"padded": "alpha     beta   gamma",
			},
			`
				Dissect d1 = dissect('%{clientip} %{ident} %{auth} [%{@timestamp}] "%{verb} %{request} HTTP/%{httpversion}" %{status} %{size}');
				Map m1 = d1.extract(ctx._source.apache);
				Map mOrd = dissect('%{+dt/2} %{+dt/3} %{+dt/1} %{?ignored}').extract(ctx._source.order);
				Map mApp = dissect('%{+joined} %{+joined} %{} %{host}').extract(ctx._source.order);
				Map mKV = dissect('%{*k1}=%{&k1} %{*k2}=%{&k2}').extract(ctx._source.kv);
				Map mPad = dissect('%{a->} %{b->} %{c}').extract(ctx._source.padded);
				return [
					'ip': m1.clientip,
					'ts': m1['@timestamp'],
					'status': m1.status,
					'size': m1.size,
					'ordDt': mOrd.dt,
					'hasIgnored': mOrd.containsKey('ignored'),
					'appJoined': mApp.joined,
					'appHost': mApp.host,
					'kvCpu': mKV.cpu,
					'kvMem': mKV.mem,
					'padA': mPad.a,
					'padB': mPad.b,
					'padC': mPad.c,
					'noMatch': d1.extract('nope') == null,
					'nullIn': d1.extract(null) == null,
					'str': d1.toString().startsWith('Dissect[')
				];
			`,
			nil,
		)
		if err != nil {
			t.Fatalf("dissect script failed: %v", err)
		}
		got := res.(map[string]any)
		want := map[string]any{
			"ip":         "247.37.0.0",
			"ts":         "30/Apr/1998:14:30:59 -0500",
			"status":     "200",
			"size":       "3171",
			"ordDt":      "2024Dec 16",
			"hasIgnored": false,
			"appJoined":  "Dec 16",
			"appHost":    "host1",
			"kvCpu":      "87",
			"kvMem":      "42",
			"padA":       "alpha",
			"padB":       "beta",
			"padC":       "gamma",
			"noMatch":    true,
			"nullIn":     true,
			"str":        true,
		}
		for k, w := range want {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, got[k], w)
			}
		}
	})

	t.Run("CompileTimeValidationErrors_250_grok_And_260_dissect", func(t *testing.T) {
		cases := []struct {
			name    string
			src     string
			wantSub string
		}{
			{
				name:    "NonConstantGrokVar",
				src:     `String p = '%{COMMONAPACHELOG}'; emit(grok(p).extract('x'));`,
				wantSub: "all arguments to [grok] must be constant but the [1] argument isn't",
			},
			{
				name:    "NonConstantDissectVar",
				src:     `String p = '%{a} %{b}'; emit(dissect(p).extract('x y'));`,
				wantSub: "all arguments to [dissect] must be constant but the [1] argument isn't",
			},
			{
				name:    "InvalidGrokNumericGroupName",
				src:     `emit(grok('(?<2134>abc)').extract('abc'));`,
				wantSub: "error compiling grok pattern [(?<2134>abc)]: invalid group name <2134>",
			},
			{
				name:    "InvalidGrokOnigmoEscapeWarning",
				src:     `emit(grok('\\o').extract('o'));`,
				wantSub: `error compiling grok pattern [\o]: emitted warnings`,
			},
			{
				name:    "UnknownGrokMacro",
				src:     `emit(grok('%{DOES_NOT_EXIST:x}').extract('abc'));`,
				wantSub: "Grok pattern [DOES_NOT_EXIST] not defined",
			},
			{
				name:    "ImpossibleDissectAdjacentTokens",
				src:     `emit(dissect('%{a}%{b}').extract('ab'));`,
				wantSub: "impossible dissect pattern",
			},
			{
				name:    "WrongArityGrok",
				src:     `emit(grok('%{INT:a}', 'extra').extract('1'));`,
				wantSub: "Unable to find dynamic method [grok] with [2] arguments",
			},
		}
		for _, tc := range cases {
			err := CompileValidate(tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("%s: expected compile error containing %q, got %v", tc.name, tc.wantSub, err)
			}
		}

		// Constant concatenation and user-defined shadow function MUST pass CompileValidate
		if err := CompileValidate(`emit(grok('%{IPV4:' + 'ip}').extract('1.2.3.4'));`); err != nil {
			t.Fatalf("constant string concatenation in grok() should compile, got: %v", err)
		}
		if err := CompileValidate(`String grok(String s) { return s; } String x = 'dyn'; return grok(x);`); err != nil {
			t.Fatalf("user-defined grok(String) shadow function should compile, got: %v", err)
		}
	})
}

func TestRound62_Deliverable4_FieldValFormattingAndDenseVectorDocValue(t *testing.T) {
	t.Run("50_script_doc_values_yml_KeywordFloatDateTokenCount", func(t *testing.T) {
		fieldTypes := map[string]string{
			"keyword":     "keyword",
			"missing_kw":  "keyword",
			"float":       "float",
			"missing_flt": "float",
			"half_flt":    "half_float",
			"date":        "date",
			"missing_dt":  "date",
		}
		rawDoc := map[string]any{
			"keyword": []any{"foo", "bar"},
			"float":   []any{float64(1.5)},
			"date":    "2020-05-10T08:30:00.000Z",
		}
		normDoc := NormalizeDocValuesForScript(rawDoc, fieldTypes)
		normDoc["__raw_source"] = rawDoc
		params := map[string]any{
			"__field_types":       fieldTypes,
			"__strict_doc_fields": map[string]bool{"keyword": true, "missing_kw": true, "float": true, "missing_flt": true, "half_flt": true, "date": true, "missing_dt": true},
		}

		script := `
			return [
				'joinPresent': String.join(', ', field('keyword')),
				'joinMissing': String.join(', ', field('missing_kw')),
				'kwDefault': field('missing_kw').get('fallback'),
				'kwEmpty': field('missing_kw').isEmpty() && field('missing_kw').size() == 0 && doc['missing_kw'].empty && doc['missing_kw'].size() == 0,
				'containsMappedMissing': doc.containsKey('missing_kw') && !doc.containsKey('unmapped_field'),
				'fltMissingDefStr': field('missing_flt').get(-1).toString(),
				'fltIdxDefStr': field('float').get(1, 9.2f).toString(),
				'halfFltDef': field('half_flt').get(1.5).toString(),
				'dtDefault': field('missing_dt').get(ZonedDateTime.parse('2018-01-01T12:11:12.000Z')).toString(),
				'dtPresentYoe': $('date', null).get(ChronoField.YEAR_OF_ERA)
			];
		`
		res, err := Eval(normDoc, script, params)
		if err != nil {
			t.Fatalf("50_script_doc_values script failed: %v", err)
		}
		got := res.(map[string]any)
		want := map[string]any{
			"joinPresent":           "bar, foo",
			"joinMissing":           "",
			"kwDefault":             "fallback",
			"kwEmpty":               true,
			"containsMappedMissing": true,
			"fltMissingDefStr":      "-1.0",
			"fltIdxDefStr":          "9.2",
			"halfFltDef":            "1.5",
			"dtDefault":             "2018-01-01T12:11:12.000Z",
			"dtPresentYoe":          int64(2020),
		}
		for k, w := range want {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, got[k], w)
			}
		}

		// Token count numeric string regression check ("123" -> 1 token, int64(5) -> pre-counted 5)
		if c, ok := CountStandardAnalyzerTokens("123"); !ok || c != 1 {
			t.Fatalf("expected CountStandardAnalyzerTokens(\"123\") == 1, got %d (%v)", c, ok)
		}
		if c, ok := CountStandardAnalyzerTokens(int64(5)); !ok || c != 5 {
			t.Fatalf("expected CountStandardAnalyzerTokens(int64(5)) == 5, got %d (%v)", c, ok)
		}
	})

	t.Run("180_And_185_LazyDenseVectorDocValue_FloatByteAndBit", func(t *testing.T) {
		fieldTypes := map[string]string{
			"fvec":         "dense_vector",
			"missing_fvec": "dense_vector",
			"bvec":         "dense_vector",
			"missing_bvec": "dense_vector",
			"bitvec":       "dense_vector",
		}
		elemTypes := map[string]string{
			"fvec":         "float",
			"missing_fvec": "float",
			"bvec":         "byte",
			"missing_bvec": "byte",
			"bitvec":       "bit",
		}
		doc := map[string]any{
			"fvec":   []any{1.0, 1.0, 3.0},
			"bvec":   []any{1, -2, 3},
			"bitvec": []any{int8(0x0f), int8(-128)},
		}
		params := map[string]any{
			"__field_types":          fieldTypes,
			"__vector_element_types": elemTypes,
		}

		// 1. Present & Missing Lazy DenseVectorDocValue checks (`180` & `185`)
		script := `
			DenseVectorDocValue dv = field('fvec').get();
			DenseVectorDocValue mdv = field('missing_fvec').get();
			DenseVectorDocValue bdv = field('bvec').get();
			DenseVectorDocValue mbdv = field('missing_bvec').get();
			DenseVectorDocValue bitdv = field('bitvec').get();

			int missingThrows = 0;
			List missingMsgs = new ArrayList();
			try { def x = mdv.vector; } catch (IllegalArgumentException e) { missingThrows++; missingMsgs.add(e.getMessage()); }
			try { def x = mdv.getVector(); } catch (IllegalArgumentException e) { missingThrows++; }
			try { def x = mdv.dims; } catch (IllegalArgumentException e) { missingThrows++; }
			try { def x = mdv.getDims(); } catch (IllegalArgumentException e) { missingThrows++; }
			try { def x = mdv.magnitude; } catch (IllegalArgumentException e) { missingThrows++; }
			try { mdv.dotProduct([1.0, 2.0, 3.0]); } catch (IllegalArgumentException e) { missingThrows++; }
			try { mdv.cosineSimilarity([1.0, 2.0, 3.0]); } catch (IllegalArgumentException e) { missingThrows++; }
			try { mdv.l1Norm([1.0, 2.0, 3.0]); } catch (IllegalArgumentException e) { missingThrows++; }
			try { mdv.l2Norm([1.0, 2.0, 3.0]); } catch (IllegalArgumentException e) { missingThrows++; }
			try { mbdv.hamming([1, 2, 3]); } catch (IllegalArgumentException e) { missingThrows++; }

			String iterErr1 = '';
			String iterErr2 = '';
			try { for (def v : field('fvec')) { } } catch (UnsupportedOperationException e) { iterErr1 = e.getMessage(); }
			try { field('bvec').iterator(); } catch (UnsupportedOperationException e) { iterErr2 = e.getMessage(); }

			String badQueryErr1 = '';
			String badQueryErr2 = '';
			try { dv.dotProduct('one, two, three'); } catch (IllegalArgumentException e) { badQueryErr1 = e.getMessage(); }
			try { bdv.cosineSimilarity(42); } catch (IllegalArgumentException e) { badQueryErr2 = e.getMessage(); }

			return [
				'presentNotEmpty': !dv.isEmpty() && !dv.empty,
				'presentSizeOne': dv.size() == 1,
				'presentDimsThree': dv.dims == 3 && dv.getDims() == 3,
				'vecMulSize': dv.vector[2] * dv.size(),
				'dotProd': dv.dotProduct([2.0, 3.0, 4.0]),
				'l1Dist': dv.l1Norm([1.0, 2.0, 1.0]),
				'l2Dist': dv.l2Norm([1.0, 1.0, 3.0]),
				'cosSim': dv.cosineSimilarity([1.0, 1.0, 3.0]),
				'byteVecElem': bdv.vector[1],
				'byteHamming': bdv.hamming([1, -2, 2]),
				'bitL1Self': bitdv.l1Norm(),
				'bitHamming': bitdv.hamming([15, -128]),
				'missingEmpty': mdv.isEmpty() && mdv.empty && mdv.size() == 0,
				'getDefaultNull': field('missing_fvec').get(null) == null,
				'missingThrows': missingThrows,
				'missingMsgExact': missingMsgs[0],
				'iterErr1': iterErr1,
				'iterErr2': iterErr2,
				'badQueryErr1': badQueryErr1,
				'badQueryErr2': badQueryErr2
			];
		`
		res, err := Eval(doc, script, params)
		if err != nil {
			t.Fatalf("180/185 DenseVectorDocValue script failed: %v", err)
		}
		got := res.(map[string]any)
		if got["presentNotEmpty"] != true || got["presentSizeOne"] != true || got["presentDimsThree"] != true {
			t.Fatalf("present DenseVectorDocValue metadata mismatch: %#v", got)
		}
		if f, _ := toFloat64(got["vecMulSize"]); f != 3.0 {
			t.Fatalf("expected dv.vector[2] * dv.size() == 3.0, got %#v", got["vecMulSize"])
		}
		if f, _ := toFloat64(got["dotProd"]); f != 17.0 {
			t.Fatalf("expected dotProd == 17.0, got %#v", got["dotProd"])
		}
		if f, _ := toFloat64(got["l1Dist"]); f != 3.0 {
			t.Fatalf("expected l1Dist == 3.0, got %#v", got["l1Dist"])
		}
		if f, _ := toFloat64(got["l2Dist"]); f != 0.0 {
			t.Fatalf("expected l2Dist == 0.0, got %#v", got["l2Dist"])
		}
		if f, _ := toFloat64(got["cosSim"]); math.Abs(f-1.0) > 1e-5 {
			t.Fatalf("expected cosSim ~= 1.0, got %#v", got["cosSim"])
		}
		if got["byteVecElem"] != int64(-2) || got["byteHamming"] != float64(1) ||
			got["bitL1Self"] != float64(5) || got["bitHamming"] != float64(0) {
			t.Fatalf("unexpected byte/bit vector results: %#v", got)
		}
		if got["missingEmpty"] != true || got["getDefaultNull"] != true || got["missingThrows"] != int64(10) {
			t.Fatalf("missing DenseVectorDocValue checks failed: %#v", got)
		}
		if got["missingMsgExact"] != DenseVectorMissingMessage {
			t.Fatalf("unexpected missing vector message: got %q, want %q", got["missingMsgExact"], DenseVectorMissingMessage)
		}
		if got["iterErr1"] != DenseVectorIterateErrorMessage || got["iterErr2"] != DenseVectorIterateErrorMessage {
			t.Fatalf("unexpected iterate error message: %q / %q", got["iterErr1"], got["iterErr2"])
		}
		if got["badQueryErr1"] != "Cannot use vector [one, two, three] with class [java.lang.String] as query vector" {
			t.Fatalf("unexpected badQueryErr1: %q", got["badQueryErr1"])
		}
		if !strings.Contains(fmt.Sprintf("%v", got["badQueryErr2"]), "Cannot use vector [42]") {
			t.Fatalf("unexpected badQueryErr2: %q", got["badQueryErr2"])
		}
	})
}

func TestRound62_LRUCacheEvictionAndConcurrentSafety(t *testing.T) {
	// Exercise small bounded LRU cache eviction & move-to-front deterministically
	small := newExtractorLRUCache[int](3)
	small.put("a", 1)
	small.put("b", 2)
	small.put("c", 3)
	if v, ok := small.get("a"); !ok || v != 1 {
		t.Fatalf("expected hit for 'a', got %v, %v", v, ok)
	}
	small.put("a", 10) // update existing
	small.put("d", 4)  // evicts 'b'
	if _, ok := small.get("b"); ok {
		t.Fatalf("expected 'b' to be evicted")
	}
	if v, ok := small.get("a"); !ok || v != 10 {
		t.Fatalf("expected updated 'a'=10, got %v, %v", v, ok)
	}

	// Concurrent Grok + Dissect compilation & extraction under -race
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				gx, err := CompileGrokPattern(fmt.Sprintf("%%{IPV4:ip_%d} %%{INT:num:int}", i%5))
				if err != nil {
					t.Errorf("concurrent CompileGrokPattern failed: %v", err)
					return
				}
				m := gx.Extract(fmt.Sprintf("192.168.1.%d %d", id, i))
				if m["num"] != int64(i) {
					t.Errorf("unexpected concurrent grok extract: %#v", m)
					return
				}
				dx, err := CompileDissectPattern(fmt.Sprintf("%%{k_%d}:%%{val}", i%5))
				if err != nil {
					t.Errorf("concurrent CompileDissectPattern failed: %v", err)
					return
				}
				dm := dx.Extract("hello:world")
				if dm["val"] != "world" {
					t.Errorf("unexpected concurrent dissect extract: %#v", dm)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestRound62_ComprehensiveEdgeAndErrorBranches(t *testing.T) {
	// 1. Direct Go helper & enum method coverage (30/31-day months, locales, pointer receivers)
	mJan := newMonthEnumRound62(time.January)
	mApr := newMonthEnumRound62(time.April)
	mOOB := newMonthEnumRound62(0)
	if mJan.GetValue() != 1 || mJan.Name() != "JANUARY" || mJan.MinLength() != 31 || mJan.MaxLength() != 31 || mJan.Length(false) != 31 {
		t.Fatalf("unexpected January MonthEnum metadata: %+v", mJan)
	}
	if mApr.MinLength() != 30 || mApr.MaxLength() != 30 || mApr.GetDisplayName("SHORT", "ITALIAN") != "apr" || mOOB.Name() != "JANUARY" {
		t.Fatalf("unexpected April/OOB MonthEnum metadata")
	}
	if (MonthEnum{Value: 5}).String() != "MAY" || (MonthEnum{Value: 99}).String() != "JANUARY" {
		t.Fatalf("unexpected raw MonthEnum.String() fallback")
	}
	for _, st := range []string{"FULL", "SHORT", "SHORT_STANDALONE", "NARROW"} {
		for _, loc := range []string{"FRENCH", "GERMAN", "ITALIAN", "JAPANESE", "CHINESE", "SPANISH", "KOREAN", "UNKNOWN_LOC"} {
			if DayOfWeekDisplayName(1, st, loc) == "" || MonthDisplayName(1, st, loc) == "" {
				t.Fatalf("empty display name for style=%s loc=%s", st, loc)
			}
		}
	}
	if DayOfWeekDisplayName(0, "FULL", "ENGLISH") != "Monday" || MonthDisplayName(0, "FULL", "ENGLISH") != "January" {
		t.Fatalf("expected OOB dow/month display fallback")
	}
	dowPtr := &DayOfWeekEnum{Value: 2, NameStr: "TUESDAY"}
	monPtr := &MonthEnum{Value: 4, NameStr: "APRIL"}
	if FormatValueSafe(dowPtr) != "TUESDAY" || FormatValueSafe(monPtr) != "APRIL" {
		t.Fatalf("unexpected pointer enum FormatValueSafe")
	}
	var nilGrok *GrokExtractor
	var nilDissect *DissectExtractor
	if nilGrok.String() != "null" || nilGrok.Extract("x") != nil || nilDissect.String() != "null" || nilDissect.Extract("x") != nil {
		t.Fatalf("unexpected nil Grok/Dissect behavior")
	}

	// 2. ZonedDateTimeVal & Enum exception branches + post-call string temporal properties
	doc := NormalizeDocValuesForScript(
		map[string]any{"ts": "2024-04-15T09:10:11.000Z", "dbl": []any{float64(2.5)}},
		map[string]string{"ts": "date", "dbl": "double", "missing_dbl": "double"},
	)
	params := map[string]any{
		"__field_types": map[string]string{"ts": "date", "dbl": "double", "missing_dbl": "double"},
		"monPtr":        monPtr,
		"dowPtr":        dowPtr,
	}
	script := `
		def dt = doc['ts'].value;
		def mon = dt.getMonth();
		def dow = dt.dayOfWeekEnum;
		int errs = 0;

		try { dt.plus(null); } catch (NullPointerException e) { errs++; }
		try { dt.plus('bad'); } catch (ClassCastException e) { errs++; }
		try { dt.plus('bad', ChronoUnit.DAYS); } catch (ClassCastException e) { errs++; }
		try { dt.plus(1, null); } catch (NullPointerException e) { errs++; }
		try { dt.plusDays('bad'); } catch (ClassCastException e) { errs++; }
		try { dt.withYear('bad'); } catch (ClassCastException e) { errs++; }
		try { dt.with(null); } catch (NullPointerException e) { errs++; }
		try { dt.with(null, 1); } catch (NullPointerException e) { errs++; }
		try { dt.with(ChronoField.YEAR, 'bad'); } catch (ClassCastException e) { errs++; }
		try { dt.with('BAD_FIELD', 1); } catch (Exception e) { errs++; }
		try { dt.withZoneSameInstant(null); } catch (NullPointerException e) { errs++; }
		try { dt.truncatedTo(null); } catch (NullPointerException e) { errs++; }
		try { dt.get(null); } catch (NullPointerException e) { errs++; }
		try { dt.get('BAD_FIELD'); } catch (Exception e) { errs++; }
		try { dt.isAfter(null); } catch (NullPointerException e) { errs++; }
		try { dt.isAfter('not-a-date'); } catch (ClassCastException e) { errs++; }
		try { dt.compareTo(null); } catch (NullPointerException e) { errs++; }
		try { dt.compareTo('not-a-date'); } catch (ClassCastException e) { errs++; }
		try { dt.until(null, ChronoUnit.DAYS); } catch (NullPointerException e) { errs++; }
		try { dt.format(null); } catch (NullPointerException e) { errs++; }
		try { parse(1, 2); } catch (IllegalArgumentException e) { errs++; }

		try { dow.plus('bad'); } catch (ClassCastException e) { errs++; }
		try { dow.compareTo(null); } catch (NullPointerException e) { errs++; }
		try { dow.compareTo(123); } catch (ClassCastException e) { errs++; }
		try { mon.plus('bad'); } catch (ClassCastException e) { errs++; }
		try { mon.compareTo(null); } catch (NullPointerException e) { errs++; }
		try { mon.compareTo(123); } catch (ClassCastException e) { errs++; }
		try { mon.getDisplayName(null, Locale.ENGLISH); } catch (NullPointerException e) { errs++; }

		boolean strChainOk =
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).year == 2024 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).monthValue == 4 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).month.getValue() == 4 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).dayOfMonth == 16 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).dayOfYear == 107 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).hour == 9 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).minute == 10 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).second == 11 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).nano == 0 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).dayOfWeek.getValue() == 2 &&
			ZonedDateTime.parse('2024-04-15T09:10:11Z').plusDays(1).millis > 0;

		boolean ptrAndDblOk =
			params.monPtr.equals('APRIL') && params.monPtr.compareTo('MARCH') == 1 &&
			params.dowPtr.getValue() == 2 &&
			dt.toLocalDateTime() == '2024-04-15T09:10:11' &&
			field('missing_dbl').get(3) == 3.0;

		return ['errs': errs, 'strChainOk': strChainOk, 'ptrAndDblOk': ptrAndDblOk];
	`
	res, err := Eval(doc, script, params)
	if err != nil {
		t.Fatalf("comprehensive ZDT/Enum edge script failed: %v", err)
	}
	got := res.(map[string]any)
	if got["errs"] != int64(28) || got["strChainOk"] != true || got["ptrAndDblOk"] != true {
		t.Fatalf("unexpected ZDT/Enum edge results: %#v", got)
	}

	// 3. Grok & Dissect regex escapes, triple-quoted literals, trailing delimiters, and composite emit errors
	gxEsc, err := CompileGrokPattern(`\Q[literal]\E \%{notmacro} %{WORD:flag:boolean}`)
	if err != nil {
		t.Fatalf("CompileGrokPattern with \\Q..\\E and escaped macro failed: %v", err)
	}
	if m := gxEsc.Extract(`[literal] %{notmacro} false`); m["flag"] != false {
		t.Fatalf("unexpected escaped grok extract: %#v", m)
	}
	for _, badGrok := range []string{`abc\`, `(?<unclosed`, `%{INT:unclosed`, `%{INT:x:badconv}`, strings.Repeat("a", MaxRegexPatternLen+5)} {
		if _, gErr := CompileGrokPattern(badGrok); gErr == nil {
			t.Errorf("expected CompileGrokPattern(%q) to fail", badGrok)
		}
	}
	for _, badDissect := range []string{`%{unclosed`, `%{+ord/notint}`, strings.Repeat("a", MaxRegexPatternLen+5)} {
		if _, dErr := CompileDissectPattern(badDissect); dErr == nil {
			t.Errorf("expected CompileDissectPattern(%q) to fail", badDissect)
		}
	}
	dLit, err := CompileDissectPattern("exact-only")
	if err != nil || dLit.Extract("exact-only") == nil || dLit.Extract("other") != nil {
		t.Fatalf("unexpected literal-only dissect behavior: %v", err)
	}
	dSuffix, err := CompileDissectPattern("%{msg}!")
	if err != nil || dSuffix.Extract("hello!")["msg"] != "hello" || dSuffix.Extract("hello") != nil {
		t.Fatalf("unexpected trailing-delimiter dissect behavior: %v", err)
	}

	// Triple-quoted & parenthesized constant pattern in CompileValidate + composite emit error cases
	emittedTriple, err := EvalEmitContext(
		"Grok g = grok((\"\"\"\n%{IPV4:ip}\"\"\")); emit(g.extract('1.2.3.4'));",
		"composite",
		map[string]any{},
		map[string]any{},
		nil,
		nil,
	)
	if err != nil || MergeCompositeEmittedMaps(emittedTriple)["ip"] != "1.2.3.4" {
		t.Fatalf("triple-quoted constant grok failed: %#v, err=%v", emittedTriple, err)
	}
	if _, cErr := EvalEmitContext("emit('not-a-map')", "composite", nil, nil, nil, nil); cErr == nil {
		t.Fatalf("expected ClassCastException when emitting String in 1-arg composite context")
	}
	if _, cErr := EvalEmitContext("emit(null, 'v')", "composite", nil, nil, nil, nil); cErr == nil {
		t.Fatalf("expected error when emitting null subfield name in 2-arg composite context")
	}
	if _, cErr := EvalEmitContext("emit('a', 'b', 'c')", "composite", nil, nil, nil, nil); cErr == nil {
		t.Fatalf("expected error when calling 3-arg emit in composite context")
	}
}
