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

package analysis

import (
	"fmt"
	"strings"
)

func buildStemmerFunc(lang string) (func(string) string, error) {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "", "english", "porter2", "lovins":
		return stemEnglishPorter, nil
	case "porter":
		return stemEnglishPorter, nil
	case "possessive_english":
		return stemPossessiveEnglish, nil
	case "light_english":
		return stemLightEnglish, nil
	case "minimal_english":
		return stemMinimalEnglish, nil
	case "kstem":
		return stemKStem, nil
	case "arabic":
		return stemArabic, nil
	case "armenian":
		return stemArmenian, nil
	case "basque":
		return stemBasque, nil
	case "bengali":
		return stemBengali, nil
	case "brazilian":
		return stemBrazilian, nil
	case "bulgarian":
		return stemBulgarian, nil
	case "catalan":
		return stemCatalan, nil
	case "czech":
		return stemCzech, nil
	case "danish":
		return stemDanish, nil
	case "dutch", "kp":
		return stemDutch, nil
	case "estonian":
		return stemEstonian, nil
	case "finnish", "light_finnish":
		return stemFinnish, nil
	case "french":
		return stemFrench, nil
	case "light_french", "minimal_french":
		return stemLightFrench, nil
	case "galician", "minimal_galician":
		return stemGalician, nil
	case "german", "german2":
		return stemGerman, nil
	case "light_german", "minimal_german":
		return stemLightGerman, nil
	case "greek":
		return stemGreek, nil
	case "hindi":
		return stemHindi, nil
	case "hungarian", "light_hungarian":
		return stemHungarian, nil
	case "indonesian":
		return stemIndonesian, nil
	case "irish":
		return stemIrish, nil
	case "italian", "light_italian":
		return stemItalian, nil
	case "latvian":
		return stemLatvian, nil
	case "lithuanian":
		return stemLithuanian, nil
	case "norwegian", "light_norwegian", "minimal_norwegian", "nynorsk", "light_nynorsk", "minimal_nynorsk":
		return stemNorwegian, nil
	case "portuguese", "light_portuguese", "minimal_portuguese", "portuguese_rslp":
		return stemPortuguese, nil
	case "romanian":
		return stemRomanian, nil
	case "russian", "light_russian":
		return stemRussian, nil
	case "serbian":
		return stemSerbian, nil
	case "sorani":
		return stemSorani, nil
	case "spanish", "light_spanish":
		return stemSpanish, nil
	case "swedish", "light_swedish":
		return stemSwedish, nil
	case "turkish":
		return stemTurkish, nil
	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown stemmer language [%s]", lang))
	}
}

// ============================================================================
// English Stemmers: Porter (1980), Possessive, Light, Minimal, KStem
// ============================================================================

func stemPossessiveEnglish(s string) string {
	rs := []rune(s)
	if len(rs) >= 2 && (rs[len(rs)-1] == 's' || rs[len(rs)-1] == 'S') {
		ap := rs[len(rs)-2]
		if ap == '\'' || ap == '\u2019' || ap == '\uFF07' {
			return string(rs[:len(rs)-2])
		}
	}
	return s
}

func stemMinimalEnglish(s string) string {
	n := len(s)
	if n <= 3 || s[n-1] != 's' {
		return s
	}
	if strings.HasSuffix(s, "ies") && n > 4 && !strings.HasSuffix(s, "eies") && !strings.HasSuffix(s, "aies") {
		return s[:n-3] + "y"
	}
	if strings.HasSuffix(s, "es") && (strings.HasSuffix(s, "sses") || strings.HasSuffix(s, "xes") || strings.HasSuffix(s, "ches") || strings.HasSuffix(s, "shes")) {
		return s[:n-2]
	}
	if strings.HasSuffix(s, "us") || strings.HasSuffix(s, "ss") {
		return s
	}
	return s[:n-1]
}

func stemLightEnglish(s string) string {
	w := stemMinimalEnglish(s)
	for _, suf := range []string{"ing", "ed", "ly"} {
		if len(w) > len(suf)+2 && strings.HasSuffix(w, suf) {
			w = w[:len(w)-len(suf)]
			break
		}
	}
	return w
}

var kstemIrregulars = map[string]string{
	"mice": "mouse", "children": "child", "feet": "foot", "teeth": "tooth",
	"geese": "goose", "men": "man", "women": "woman", "oxen": "ox",
	"matrices": "matrix", "vertices": "vertex", "indices": "index",
	"analyses": "analysis", "crises": "crisis", "theses": "thesis",
	"phenomena": "phenomenon", "criteria": "criterion", "ran": "run",
	"wrote": "write", "written": "write", "went": "go", "gone": "go",
}

func stemKStem(s string) string {
	if len(s) <= 3 {
		return s
	}
	if irr, ok := kstemIrregulars[s]; ok {
		return irr
	}
	w := s
	if strings.HasSuffix(w, "ies") && len(w) > 4 {
		return w[:len(w)-3] + "y"
	}
	if (strings.HasSuffix(w, "ches") || strings.HasSuffix(w, "shes") || strings.HasSuffix(w, "xes") || strings.HasSuffix(w, "zes") || strings.HasSuffix(w, "sses")) && len(w) > 4 {
		return w[:len(w)-2]
	}
	if strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") && !strings.HasSuffix(w, "us") && !strings.HasSuffix(w, "is") {
		w = w[:len(w)-1]
	}
	if strings.HasSuffix(w, "ing") && len(w) > 5 {
		base := w[:len(w)-3]
		if len(base) >= 2 && base[len(base)-1] == base[len(base)-2] && base[len(base)-1] != 'l' && base[len(base)-1] != 's' && base[len(base)-1] != 'z' {
			return base[:len(base)-1]
		}
		return base
	}
	if strings.HasSuffix(w, "ed") && len(w) > 4 && !strings.HasSuffix(w, "eed") {
		base := w[:len(w)-2]
		if len(base) >= 2 && base[len(base)-1] == base[len(base)-2] && base[len(base)-1] != 'l' && base[len(base)-1] != 's' && base[len(base)-1] != 'z' {
			return base[:len(base)-1]
		}
		return base
	}
	return w
}

// stemEnglishPorter implements Martin Porter's 1980 English stemming algorithm.
func stemEnglishPorter(word string) string {
	if len(word) <= 2 {
		return word
	}
	for i := 0; i < len(word); i++ {
		if word[i] < 'a' || word[i] > 'z' {
			return word
		}
	}
	b := []byte(word)

	// Step 1a
	if porterEnds(b, "sses") {
		b = b[:len(b)-2]
	} else if porterEnds(b, "ies") {
		b = b[:len(b)-2]
	} else if !porterEnds(b, "ss") && porterEnds(b, "s") {
		b = b[:len(b)-1]
	}

	// Step 1b
	step1bExtra := false
	if porterEnds(b, "eed") {
		stem := b[:len(b)-3]
		if porterMeasure(stem) > 0 {
			b = b[:len(b)-1]
		}
	} else if porterEnds(b, "ed") {
		stem := b[:len(b)-2]
		if porterHasVowel(stem) {
			b = stem
			step1bExtra = true
		}
	} else if porterEnds(b, "ing") {
		stem := b[:len(b)-3]
		if porterHasVowel(stem) {
			b = stem
			step1bExtra = true
		}
	}
	if step1bExtra {
		if porterEnds(b, "at") || porterEnds(b, "bl") || porterEnds(b, "iz") {
			b = append(b, 'e')
		} else if porterDoubleConsonant(b) {
			last := b[len(b)-1]
			if last != 'l' && last != 's' && last != 'z' {
				b = b[:len(b)-1]
			}
		} else if porterMeasure(b) == 1 && porterCVC(b) {
			b = append(b, 'e')
		}
	}

	// Step 1c
	if porterEnds(b, "y") && porterHasVowel(b[:len(b)-1]) {
		b[len(b)-1] = 'i'
	}

	// Step 2
	b = porterStep2(b)
	// Step 3
	b = porterStep3(b)
	// Step 4
	b = porterStep4(b)

	// Step 5a
	if porterEnds(b, "e") {
		stem := b[:len(b)-1]
		m := porterMeasure(stem)
		if m > 1 || (m == 1 && !porterCVC(stem)) {
			b = stem
		}
	}
	// Step 5b
	if porterMeasure(b) > 1 && porterDoubleConsonant(b) && b[len(b)-1] == 'l' {
		b = b[:len(b)-1]
	}
	return string(b)
}

func porterIsConsonant(b []byte, i int) bool {
	switch b[i] {
	case 'a', 'e', 'i', 'o', 'u':
		return false
	case 'y':
		if i == 0 {
			return true
		}
		return !porterIsConsonant(b, i-1)
	default:
		return true
	}
}

func porterMeasure(b []byte) int {
	n := 0
	i := 0
	l := len(b)
	for i < l && porterIsConsonant(b, i) {
		i++
	}
	for i < l {
		for i < l && !porterIsConsonant(b, i) {
			i++
		}
		if i >= l {
			break
		}
		n++
		for i < l && porterIsConsonant(b, i) {
			i++
		}
	}
	return n
}

func porterHasVowel(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if !porterIsConsonant(b, i) {
			return true
		}
	}
	return false
}

func porterDoubleConsonant(b []byte) bool {
	l := len(b)
	if l < 2 || b[l-1] != b[l-2] {
		return false
	}
	return porterIsConsonant(b, l-1)
}

func porterCVC(b []byte) bool {
	l := len(b)
	if l < 3 {
		return false
	}
	if !porterIsConsonant(b, l-1) || porterIsConsonant(b, l-2) || !porterIsConsonant(b, l-3) {
		return false
	}
	ch := b[l-1]
	return ch != 'w' && ch != 'x' && ch != 'y'
}

func porterEnds(b []byte, suf string) bool {
	if len(b) < len(suf) {
		return false
	}
	return string(b[len(b)-len(suf):]) == suf
}

func porterReplaceIfM0(b []byte, suf, repl string) ([]byte, bool) {
	if !porterEnds(b, suf) {
		return b, false
	}
	stem := b[:len(b)-len(suf)]
	if porterMeasure(stem) > 0 {
		out := make([]byte, len(stem)+len(repl))
		copy(out, stem)
		copy(out[len(stem):], repl)
		return out, true
	}
	return b, true
}

var porterStep2Rules = [][2]string{
	{"ational", "ate"}, {"tional", "tion"}, {"enci", "ence"}, {"anci", "ance"},
	{"izer", "ize"}, {"bli", "ble"}, {"alli", "al"}, {"entli", "ent"},
	{"eli", "e"}, {"ousli", "ous"}, {"ization", "ize"}, {"ation", "ate"},
	{"ator", "ate"}, {"alism", "al"}, {"iveness", "ive"}, {"fulness", "ful"},
	{"ousness", "ous"}, {"aliti", "al"}, {"iviti", "ive"}, {"biliti", "ble"},
	{"logi", "log"},
}

func porterStep2(b []byte) []byte {
	for _, r := range porterStep2Rules {
		if nb, matched := porterReplaceIfM0(b, r[0], r[1]); matched {
			return nb
		}
	}
	return b
}

var porterStep3Rules = [][2]string{
	{"icate", "ic"}, {"ative", ""}, {"alize", "al"}, {"iciti", "ic"},
	{"ical", "ic"}, {"ful", ""}, {"ness", ""},
}

func porterStep3(b []byte) []byte {
	for _, r := range porterStep3Rules {
		if nb, matched := porterReplaceIfM0(b, r[0], r[1]); matched {
			return nb
		}
	}
	return b
}

var porterStep4Suffixes = []string{
	"al", "ance", "ence", "er", "ic", "able", "ible", "ant",
	"ement", "ment", "ent", "ion", "ou", "ism", "ate", "iti",
	"ous", "ive", "ize",
}

func porterStep4(b []byte) []byte {
	for _, suf := range porterStep4Suffixes {
		if porterEnds(b, suf) {
			stem := b[:len(b)-len(suf)]
			if suf == "ion" {
				if len(stem) > 0 && (stem[len(stem)-1] == 's' || stem[len(stem)-1] == 't') && porterMeasure(stem) > 1 {
					return stem
				}
				return b
			}
			if porterMeasure(stem) > 1 {
				return stem
			}
			return b
		}
	}
	return b
}

// ============================================================================
// Multilingual Stemmers (Lucene Light & Snowball Stemmers)
// ============================================================================

func findR1(runes []rune, isVowel func(rune) bool) int {
	n := len(runes)
	i := 0
	for i < n && !isVowel(runes[i]) {
		i++
	}
	for i < n && isVowel(runes[i]) {
		i++
	}
	if i < n {
		return i + 1
	}
	return n
}

func stripLongestSuffixInRegion(runes []rune, minRoot int, suffixes []string) ([]rune, bool) {
	for _, suf := range suffixes {
		sr := []rune(suf)
		if len(runes)-len(sr) >= minRoot && runesEqual(runes[len(runes)-len(sr):], sr) {
			return runes[:len(runes)-len(sr)], true
		}
	}
	return runes, false
}

func isLatinVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u', 'y', 'á', 'à', 'â', 'ä', 'ã', 'å', 'æ',
		'é', 'è', 'ê', 'ë', 'í', 'ì', 'î', 'ï', 'ó', 'ò', 'ô', 'ö', 'õ', 'ø',
		'ú', 'ù', 'û', 'ü', 'ý', 'ÿ', 'ą', 'ę', 'į', 'ų', 'ū', 'ī', 'ē', 'ā':
		return true
	default:
		return false
	}
}

func foldRomanceAccents(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 'à', 'á', 'â', 'ã', 'ä':
			b.WriteByte('a')
		case 'è', 'é', 'ê', 'ë':
			b.WriteByte('e')
		case 'ì', 'í', 'î', 'ï':
			b.WriteByte('i')
		case 'ò', 'ó', 'ô', 'õ', 'ö':
			b.WriteByte('o')
		case 'ù', 'ú', 'û', 'ü':
			b.WriteByte('u')
		case 'ç':
			b.WriteByte('c')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Arabic Stemmer (Lucene ArabicStemmer)
var arabicPrefixes = []string{"وال", "بال", "كال", "فال", "لل", "ال"}
var arabicSuffixes = []string{"ها", "ان", "ات", "ون", "ين", "يه", "ية", "ه", "ة", "ي"}

func stemArabic(s string) string {
	norm := normalizeArabic(s)
	rs := []rune(norm)
	for _, p := range arabicPrefixes {
		pr := []rune(p)
		if len(rs)-len(pr) >= 2 && runesEqual(rs[:len(pr)], pr) {
			rs = rs[len(pr):]
			break
		}
	}
	rs, _ = stripLongestSuffixInRegion(rs, 2, arabicSuffixes)
	return string(rs)
}

// Armenian Snowball Stemmer
var armenianSuffixes = []string{
	"ներից", "ներին", "ներով", "ները", "ների", "ներն", "ներ",
	"ից", "ին", "ով", "ում", "իվ", "ու", "ան", "են", "ը", "ն",
}

func stemArmenian(s string) string {
	rs := []rune(s)
	isV := func(r rune) bool {
		switch r {
		case 'ա', 'ե', 'է', 'ը', 'ի', 'ո', 'օ':
			return true
		}
		return false
	}
	r1 := findR1(rs, isV)
	if r1 < 2 {
		r1 = 2
	}
	rs, _ = stripLongestSuffixInRegion(rs, r1, armenianSuffixes)
	return string(rs)
}

// Basque Snowball Stemmer
var basqueSuffixes = []string{
	"tarik", "etako", "etara", "etatik", "aren", "ekin", "etan", "etik",
	"ak", "ek", "ko", "ra", "ta", "en", "ik",
}

func stemBasque(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, basqueSuffixes)
	return string(rs)
}

// Bengali Stemmer (Lucene BengaliStemmer)
var bengaliSuffixes = []string{
	"য়েদেরকে", "য়েদের", "দেরকে", "েছিলাম", "েছিলেন", "েছিলে", "েছিল",
	"য়েছে", "েছেন", "েছে", "গুলো", "গুলি", "দের", "টার", "টির", "টা", "টি",
	"ের", "তে", "কে", "রা", "য়", "ি", "ী", "ে", "ো",
}

func stemBengali(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 2, bengaliSuffixes)
	return string(rs)
}

// Brazilian Stemmer (Lucene BrazilianStemmer)
var brazilianSuffixes = []string{
	"amentos", "imentos", "amento", "imento", "adoras", "adores", "aço~es",
	"logias", "encias", "amente", "idades", "ismos", "istas", "adora", "aça~o",
	"logia", "encia", "idade", "aria", "arias", "ismo", "ista", "osos", "osas",
	"icos", "icas", "ivos", "ivas", "oso", "osa", "ico", "ica", "ivo", "iva",
	"ias", "ia", "es", "as", "os", "a", "e", "o",
}

func stemBrazilian(s string) string {
	w := foldRomanceAccents(strings.ToLower(s))
	rs := []rune(w)
	rs, _ = stripLongestSuffixInRegion(rs, 3, brazilianSuffixes)
	return string(rs)
}

// Bulgarian Stemmer (Lucene BulgarianStemmer)
var bulgarianArticles = []string{"ият", "ят", "то", "те", "та", "ът"}
var bulgarianPlurals = []string{"ове", "еве", "ища", "та", "ци", "зи", "си", "и", "а", "о", "е", "я"}

func stemBulgarian(s string) string {
	rs := []rune(s)
	if len(rs) <= 3 {
		return s
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, bulgarianArticles)
	rs, _ = stripLongestSuffixInRegion(rs, 3, bulgarianPlurals)
	return string(rs)
}

// Catalan Stemmer
var catalanSuffixes = []string{
	"aments", "iments", "ament", "iment", "acions", "adors", "adores",
	"itats", "istes", "ismes", "ació", "ador", "adora", "itat", "ista", "isme",
	"es", "os", "as", "is", "s", "a", "e", "o",
}

func stemCatalan(s string) string {
	w := foldRomanceAccents(s)
	rs := []rune(w)
	rs, _ = stripLongestSuffixInRegion(rs, 3, catalanSuffixes)
	return string(rs)
}

// Czech Stemmer (Lucene CzechStemmer)
var czechCaseSuffixes = []string{
	"atech", "ětem", "atům", "ech", "ích", "ové", "ými", "emi", "ami",
	"ete", "eti", "iho", "ího", "ími", "imu",
	"em", "es", "ém", "ím", "ům", "at", "ám", "os", "us", "ým", "mi", "ou",
	"a", "e", "i", "o", "u", "y", "á", "é", "í", "ý", "ě",
}

func stemCzech(s string) string {
	rs := []rune(s)
	if len(rs) <= 3 {
		return s
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, czechCaseSuffixes)
	rs = czechPalatalise(rs)
	return string(rs)
}

func czechPalatalise(rs []rune) []rune {
	n := len(rs)
	if n >= 2 {
		last2 := string(rs[n-2:])
		switch last2 {
		case "či", "če":
			return append(rs[:n-2], 'k')
		case "ži", "že":
			return append(rs[:n-2], 'h')
		case "čt":
			return append(rs[:n-2], 'c', 'k')
		case "št":
			return append(rs[:n-2], 's', 'k')
		}
	}
	if n >= 3 {
		last3 := string(rs[n-3:])
		switch last3 {
		case "čtě", "čti", "čtí":
			return append(rs[:n-3], 'c', 'k')
		case "ště", "šti", "ští":
			return append(rs[:n-3], 's', 'k')
		}
	}
	return rs
}

// Danish Snowball Stemmer
var danishSuffixes = []string{
	"erendes", "erende", "hedens", "elser", "endes", "ernes", "heden", "heder",
	"erer", "ered", "ende", "enes", "erne", "else", "heds", "ene", "ere", "ens",
	"ers", "ets", "hed", "en", "er", "es", "et", "e", "s",
}

func stemDanish(s string) string {
	rs := []rune(s)
	r1 := findR1(rs, isLatinVowel)
	if r1 < 3 {
		r1 = 3
	}
	rs, _ = stripLongestSuffixInRegion(rs, r1, danishSuffixes)
	if len(rs) >= 2 && rs[len(rs)-1] == rs[len(rs)-2] && !isLatinVowel(rs[len(rs)-1]) {
		rs = rs[:len(rs)-1]
	}
	return string(rs)
}

// Dutch Snowball Stemmer
func stemDutch(s string) string {
	rs := []rune(foldRomanceAccents(s))
	r1 := findR1(rs, isLatinVowel)
	if r1 < 3 {
		r1 = 3
	}
	// Step 1: heden -> heid, en/ene, s/se
	if len(rs)-5 >= r1 && string(rs[len(rs)-5:]) == "heden" {
		rs = append(rs[:len(rs)-5], []rune("heid")...)
	} else if len(rs)-3 >= r1 && string(rs[len(rs)-3:]) == "ene" && !isLatinVowel(rs[len(rs)-4]) && !strings.HasSuffix(string(rs[:len(rs)-3]), "gem") {
		rs = dutchUndouble(rs[:len(rs)-3])
	} else if len(rs)-2 >= r1 && string(rs[len(rs)-2:]) == "en" && !isLatinVowel(rs[len(rs)-3]) && !strings.HasSuffix(string(rs[:len(rs)-2]), "gem") {
		rs = dutchUndouble(rs[:len(rs)-2])
	} else if len(rs)-2 >= r1 && string(rs[len(rs)-2:]) == "se" && !isLatinVowel(rs[len(rs)-3]) && rs[len(rs)-3] != 'j' {
		rs = rs[:len(rs)-2]
	} else if len(rs)-1 >= r1 && rs[len(rs)-1] == 's' && !isLatinVowel(rs[len(rs)-2]) && rs[len(rs)-2] != 'j' {
		rs = rs[:len(rs)-1]
	}

	// Step 2: delete suffix 'e' if in R1 and preceded by non-vowel, then undouble.
	if len(rs)-1 >= r1 && rs[len(rs)-1] == 'e' && !isLatinVowel(rs[len(rs)-2]) {
		rs = dutchUndouble(rs[:len(rs)-1])
	}
	return string(rs)
}

func dutchUndouble(rs []rune) []rune {
	n := len(rs)
	if n >= 2 {
		c := rs[n-1]
		if c == rs[n-2] && (c == 'k' || c == 'd' || c == 't') {
			return rs[:n-1]
		}
	}
	return rs
}

// Estonian Snowball Stemmer
var estonianSuffixes = []string{
	"تاسse", "valt", "tele", "teni", "test", "tega", "teta", "sse", "st", "le", "lt", "ga", "ta", "ni", "na", "te", "de",
}

func stemEstonian(s string) string {
	rs := []rune(s)
	r1 := findR1(rs, isLatinVowel)
	if r1 < 3 {
		r1 = 3
	}
	rs, _ = stripLongestSuffixInRegion(rs, r1, estonianSuffixes)
	return string(rs)
}

// Finnish Light Stemmer
var finnishPossessives = []string{"nsä", "nsa", "mme", "nne", "ni", "si", "an", "än", "en"}
var finnishCases = []string{"iinsä", "iinsa", "ssa", "ssä", "sta", "stä", "lla", "llä", "lta", "ltä", "lle", "na", "nä", "ksi", "tta", "ttä", "iin", "in", "n", "a", "ä", "i"}

func stemFinnish(s string) string {
	rs := []rune(s)
	if len(rs) <= 4 {
		return s
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, finnishPossessives)
	for pass := 0; pass < 2; pass++ {
		var changed bool
		rs, changed = stripLongestSuffixInRegion(rs, 3, finnishCases)
		if !changed {
			break
		}
	}
	return string(rs)
}

// French Snowball / FrenchStemmer (french_stem) & French Light Stemmer (french analyzer)
func stemFrench(s string) string {
	rs := []rune(s)
	if len(rs) >= 4 && string(rs[len(rs)-4:]) == "eaux" {
		return string(rs[:len(rs)-1])
	}
	if len(rs) >= 4 && string(rs[len(rs)-3:]) == "aux" {
		return string(rs[:len(rs)-3]) + "al"
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, []string{
		"issements", "issement", "atrices", "ateurs", "ations", "atrice", "ateur", "ation",
		"ements", "ement", "ités", "ité", "ives", "ifs", "ive", "if", "es", "s", "e",
	})
	return string(rs)
}

func stemLightFrench(s string) string {
	rs := []rune(s)
	if len(rs) > 4 && rs[len(rs)-1] == 's' {
		rs = rs[:len(rs)-1]
	}
	if len(rs) >= 4 && string(rs[len(rs)-3:]) == "aux" {
		rs = append(rs[:len(rs)-3], 'a', 'l')
	}
	w := foldRomanceAccents(string(rs))
	rs = []rune(w)
	if len(rs) > 4 && rs[len(rs)-1] == 'e' {
		rs = rs[:len(rs)-1]
	}
	if len(rs) > 4 && rs[len(rs)-1] == rs[len(rs)-2] && !isLatinVowel(rs[len(rs)-1]) {
		rs = rs[:len(rs)-1]
	}
	return string(rs)
}

// Galician Stemmer
var galicianSuffixes = []string{
	"amentos", "imentos", "amento", "imento", "acións", "adores", "adoras",
	"erán", "irán", "arán", "erá", "irá", "ará", "ando", "endo", "indo",
	"ados", "idos", "adas", "idas", "ado", "ido", "ada", "ida", "es", "os", "as", "s", "a", "o", "e",
}

func stemGalician(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, galicianSuffixes)
	return foldRomanceAccents(string(rs))
}

// German Stemmer (german_stem) & Light German Stemmer (german analyzer)
func stemGerman(s string) string {
	w := strings.ReplaceAll(s, "ß", "ss")
	w = strings.NewReplacer("ä", "a", "ö", "o", "ü", "u", "Ä", "a", "Ö", "o", "Ü", "u").Replace(w)
	rs := []rune(w)
	rs, _ = stripLongestSuffixInRegion(rs, 3, []string{"ern", "em", "er", "en", "es", "e", "s"})
	return string(rs)
}

func stemLightGerman(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, []string{"ern", "em", "er", "en", "es", "st", "e", "s"})
	return string(rs)
}

// Greek Stemmer
var greekSuffixes = []string{
	"ουσα", "αμε", "ατε", "ανε", "ουν", "ετε", "ωσ", "ων", "ου", "οσ", "εσ", "ασ", "ισ", "ησ",
}

func stemGreek(s string) string {
	rs := []rune(lowercaseWithLang(s, "greek"))
	if len(rs) <= 4 {
		return string(rs)
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, greekSuffixes)
	return string(rs)
}

// Hindi Stemmer (Lucene HindiStemmer)
var hindiSuffixes = []string{
	"ाएंगी", "ाएंगे", "ाऊंगी", "ाऊंगा", "ाइयाँ", "ाइयों", "ाइयां",
	"ाएगी", "ाएगा", "ाओगी", "ाओगे", "एंगी", "एंगे", "ूंगी", "ूंगा", "ियों", "ियां",
	"ाती", "ाते", "ाता", "तीं", "ाओं", "ाएं", "ुओं", "ुएं", "ुआं",
	"ाकर", "ाइए", "ाईं", "ाया", "ेगी", "ेगा", "ोगी", "ोगे", "ाने", "ाना", "ानी",
	"ते", "ती", "ता", "ना", "नी", "ने", "कर", "ाओ", "िए", "ाई", "ाए", "ें", "ों", "ां",
	"ा", "ि", "ी", "ु", "ू", "े", "ै", "ो", "ौ",
}

func stemHindi(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 2, hindiSuffixes)
	return string(rs)
}

// Hungarian Light Stemmer
var hungarianSuffixes = []string{
	"képpen", "onként", "enként", "anként", "eként", "oként",
	"nak", "nek", "ban", "ben", "ból", "ből", "ról", "ről", "tól", "től",
	"hoz", "hez", "höz", "nál", "nél", "ig", "ért", "kor", "ként",
	"ok", "ek", "ök", "ak", "ik", "at", "et", "ot", "öt", "i", "a", "e",
}

func stemHungarian(s string) string {
	rs := []rune(s)
	if len(rs) <= 4 {
		return s
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, hungarianSuffixes)
	return string(rs)
}

// Indonesian Stemmer (Lucene IndonesianStemmer: particles, possessives, prefixes & suffixes)
func stemIndonesian(s string) string {
	rs := []rune(s)
	if countIndonesianVowels(rs) <= 2 {
		return s
	}
	// Strip particles (-lah, -kah, -pun)
	rs, _ = stripLongestSuffixInRegion(rs, 3, []string{"lah", "kah", "pun"})
	if countIndonesianVowels(rs) <= 2 {
		return string(rs)
	}
	// Strip possessives (-ku, -mu, -nya)
	rs, _ = stripLongestSuffixInRegion(rs, 3, []string{"nya", "ku", "mu"})
	if countIndonesianVowels(rs) <= 2 {
		return string(rs)
	}
	// Strip derivational prefix (pe-, peng-, pem-, pen-, peny-, per-, ber-, ter-, me-, meng-, mem-, men-, meny-, di-, ke-, se-)
	removedPeOrKe := false
	for _, pref := range []string{"meng", "meny", "peng", "peny", "mem", "men", "pem", "pen", "ber", "ter", "per", "pe", "me", "di", "ke", "se"} {
		pr := []rune(pref)
		if len(rs)-len(pr) >= 3 && runesEqual(rs[:len(pr)], pr) {
			rs = rs[len(pr):]
			if strings.HasPrefix(pref, "pe") || pref == "ke" {
				removedPeOrKe = true
			}
			break
		}
	}
	// Strip derivational suffix (-kan is disallowed after pe-/peng-/per-/ke- circumfixes in Lucene IndonesianStemmer!)
	if countIndonesianVowels(rs) >= 2 {
		if removedPeOrKe {
			rs, _ = stripLongestSuffixInRegion(rs, 3, []string{"an", "i"})
		} else {
			rs, _ = stripLongestSuffixInRegion(rs, 3, []string{"kan", "an", "i"})
		}
	}
	return string(rs)
}

func countIndonesianVowels(rs []rune) int {
	c := 0
	for _, r := range rs {
		if r == 'a' || r == 'e' || r == 'i' || r == 'o' || r == 'u' {
			c++
		}
	}
	return c
}

// Irish Snowball Stemmer
var irishSuffixes = []string{
	"eachtaí", "eachta", "achtaí", "achta", "eacht", "acht",
	"aigh", "igh", "adh", "eadh", "úil", "amhail", "acha", "anna",
}

func stemIrish(s string) string {
	rs := []rune(s)
	for _, pref := range []string{"d'", "m'", "b'", "n-", "t-", "h-"} {
		pr := []rune(pref)
		if len(rs) > len(pr)+2 && runesEqual(rs[:len(pr)], pr) {
			rs = rs[len(pr):]
			break
		}
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, irishSuffixes)
	return string(rs)
}

// Italian Light Stemmer
var italianSuffixes = []string{
	"amenti", "imenti", "amento", "imento", "azioni", "atori", "atrici",
	"azione", "atore", "atrice", "mente", "ità", "ist", "izz",
	"ای", "iche", "ichi", "che", "chi", "ia", "ie", "io", "a", "e", "i", "o",
}

func stemItalian(s string) string {
	rs := []rune(foldRomanceAccents(s))
	if len(rs) <= 4 {
		return string(rs)
	}
	rs, _ = stripLongestSuffixInRegion(rs, 3, italianSuffixes)
	return string(rs)
}

// Latvian Stemmer (Lucene LatvianStemmer)
var latvianSuffixes = []string{
	"ajiem", "ajām", "ajam", "ajai", "ajos", "ajās",
	"iem", "ām", "am", "ai", "im", "um", "us", "as", "is", "es", "os", "ās",
	"a", "e", "i", "s", "u", "ā", "ē", "ī", "ū",
}

func stemLatvian(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, latvianSuffixes)
	return string(rs)
}

// Lithuanian Snowball Stemmer
var lithuanianSuffixes = []string{
	"iuose", "iuosi", "iomis", "iems", "iams", "uose", "omis", "ėmis", "asis",
	"iais", "ių", "ų", "ai", "am", "as", "ei", "es", "ės", "is", "į", "iu", "us", "a", "e", "ė", "i", "o", "u", "y",
}

func stemLithuanian(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, lithuanianSuffixes)
	return string(rs)
}

// Norwegian Light Stemmer
var norwegianSuffixes = []string{
	"hetene", "heten", "heter", "elser", "elsen", "else", "ende", "ane", "ene", "ere", "ens", "ers", "ets", "en", "er", "et", "ar", "as", "es", "e", "a", "s",
}

func stemNorwegian(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, norwegianSuffixes)
	return string(rs)
}

// Portuguese Light Stemmer
var portugueseSuffixes = []string{
	"amentos", "imentos", "amento", "imento", "ações", "adores", "adoras",
	"ação", "ador", "adora", "mente", "idades", "idade", "ismos", "ismo",
	"istas", "ista", "osas", "osos", "osa", "oso", "es", "as", "os", "s", "a", "e", "o",
}

func stemPortuguese(s string) string {
	w := foldRomanceAccents(s)
	rs := []rune(w)
	rs, _ = stripLongestSuffixInRegion(rs, 3, portugueseSuffixes)
	return string(rs)
}

// Romanian Snowball Stemmer
var romanianSuffixes = []string{
	"abilităţi", "abilitati", "ivităţi", "ivitati", "ătoare", "ători", "ătate", "ăţi",
	"iilor", "ilor", "elor", "ul", "ului", "aua", "ea", "ele", "elor", "iile", "iei",
	"ii", "i", "a", "ă", "e",
}

func stemRomanian(s string) string {
	rs := []rune(s)
	r1 := findR1(rs, func(r rune) bool {
		return isLatinVowel(r) || r == 'ă' || r == 'â' || r == 'î'
	})
	if r1 < 3 {
		r1 = 3
	}
	rs, _ = stripLongestSuffixInRegion(rs, r1, romanianSuffixes)
	return string(rs)
}

// Russian Snowball / Light Stemmer
var russianSuffixes = []string{
	"иями", "ями", "ами", "ией", "иям", "ием", "иях", "ев", "ов", "ие", "ье", "еи",
	"ии", "ей", "ой", "ий", "ям", "ем", "ам", "ом", "ах", "ях", "ию", "ью", "ия", "ья",
	"ешь", "ете", "ите", "ют", "уют", "ят", "ат", "ал", "ала", "ало", "али", "ил", "ила", "ило", "или",
	"а", "е", "и", "й", "о", "у", "ы", "ь", "ю", "я",
}

func stemRussian(s string) string {
	w := strings.ReplaceAll(s, "ё", "е")
	rs := []rune(w)
	isRusV := func(r rune) bool {
		switch r {
		case 'а', 'е', 'и', 'о', 'у', 'ы', 'э', 'ю', 'я':
			return true
		}
		return false
	}
	// RV is region after first vowel
	rv := len(rs)
	for i, r := range rs {
		if isRusV(r) {
			rv = i + 1
			break
		}
	}
	if rv < len(rs) {
		rs, _ = stripLongestSuffixInRegion(rs, rv, russianSuffixes)
	}
	return string(rs)
}

// Serbian Stemmer
var serbianSuffixes = []string{
	"ovima", "evima", "ama", "ima", "om", "em", "og", "eg", "oj", "im", "ih",
	"e", "i", "a", "o", "u",
}

func stemSerbian(s string) string {
	rs := []rune(normalizeSerbian(s, "bald"))
	rs, _ = stripLongestSuffixInRegion(rs, 3, serbianSuffixes)
	return string(rs)
}

// Sorani Stemmer (Lucene SoraniStemmer)
var soraniSuffixes = []string{
	"مان", "تان", "یان", "ەکان", "انە", "ەوە", "دا", "را", "ان", "ێک", "ە", "ی",
}

func stemSorani(s string) string {
	rs := []rune(normalizeSorani(s))
	rs, _ = stripLongestSuffixInRegion(rs, 2, soraniSuffixes)
	return string(rs)
}

// Spanish Light Stemmer
var spanishSuffixes = []string{
	"amientos", "imientos", "amiento", "imiento", "aciones", "adores", "adoras",
	"ación", "ador", "adora", "mente", "idades", "idad", "ismos", "ismo", "istas", "ista",
	"es", "os", "as", "s", "a", "e", "o",
}

func stemSpanish(s string) string {
	w := foldRomanceAccents(s)
	rs := []rune(w)
	rs, _ = stripLongestSuffixInRegion(rs, 3, spanishSuffixes)
	return string(rs)
}

// Swedish Light Stemmer
var swedishSuffixes = []string{
	"elser", "elsen", "else", "arne", "arna", "erna", "ornas", "arnas", "ernas",
	"ande", "ades", "nden", "ens", "aren", "ern", "het", "ast", "or", "ar", "er", "en", "at", "ad", "as", "es", "et", "a", "e", "s",
}

func stemSwedish(s string) string {
	rs := []rune(s)
	rs, _ = stripLongestSuffixInRegion(rs, 3, swedishSuffixes)
	return string(rs)
}

// Turkish Snowball Stemmer (with consonant harmony devoicing: b->p, c->ç, d->t, ğ->k)
var turkishSuffixes = []string{
	"larımız", "lerimiz", "larınız", "leriniz", "lardan", "lerden", "ların", "lerin",
	"lara", "lere", "ları", "leri", "ımız", "imiz", "umuz", "ümüz", "ınız", "iniz", "unuz", "ünüz",
	"ndan", "nden", "dan", "den", "tan", "ten", "lar", "ler", "nin", "nın", "nun", "nün",
	"in", "ın", "un", "ün", "na", "ne", "da", "de", "ta", "te", "yi", "yı", "yu", "yü",
	"i", "ı", "u", "ü", "a", "e",
}

func stemTurkish(s string) string {
	rs := []rune(s)
	if len(rs) <= 2 {
		return s
	}
	var stripped bool
	rs, stripped = stripLongestSuffixInRegion(rs, 2, turkishSuffixes)
	if stripped && len(rs) >= 2 {
		switch rs[len(rs)-1] {
		case 'c':
			rs[len(rs)-1] = 'ç'
		case 'b':
			rs[len(rs)-1] = 'p'
		case 'd':
			rs[len(rs)-1] = 't'
		case 'ğ':
			// Only devoice ğ -> k if not preceded by a back vowel where root ğ is lexical (like ağaç -> ağacı vs dağ -> dağı)
			// Note: ağacı -> stripped ı -> ağac -> c -> ç -> ağaç!
		}
	}
	return string(rs)
}
