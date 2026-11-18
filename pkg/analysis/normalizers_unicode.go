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
	"strings"
	"unicode"
)

// foldASCII implements Lucene's ASCIIFoldingFilter mapping non-ASCII Latin/typographic
// characters to their ASCII equivalents. Returns (folded, changed).
func foldASCII(s string) (string, bool) {
	changed := false
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		if unicode.Is(unicode.Mn, r) {
			// Combining diacritical marks stripped when folding to ASCII.
			changed = true
			continue
		}
		if rep, ok := asciiFoldMap[r]; ok {
			b.WriteString(rep)
			changed = true
		} else {
			b.WriteRune(r)
		}
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

var asciiFoldMap = map[rune]string{
	// Uppercase A
	'À': "A", 'Á': "A", 'Â': "A", 'Ã': "A", 'Ä': "A", 'Å': "A", 'Ā': "A", 'Ă': "A", 'Ą': "A",
	'Ǎ': "A", 'Ǻ': "A", 'Ạ': "A", 'Ả': "A", 'Ấ': "A", 'Ầ': "A", 'Ẩ': "A", 'Ẫ': "A", 'Ậ': "A",
	'Ắ': "A", 'Ằ': "A", 'Ẳ': "A", 'Ẵ': "A", 'Ặ': "A",
	// Lowercase a
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'ǎ': "a", 'ǻ': "a", 'ạ': "a", 'ả': "a", 'ấ': "a", 'ầ': "a", 'ẩ': "a", 'ẫ': "a", 'ậ': "a",
	'ắ': "a", 'ằ': "a", 'ẳ': "a", 'ẵ': "a", 'ặ': "a",
	// AE / OE / IJ / Dz / Lj / Nj
	'Æ': "AE", 'Ǽ': "AE", 'æ': "ae", 'ǽ': "ae",
	'Œ': "OE", 'œ': "oe",
	'Ĳ': "IJ", 'ĳ': "ij",
	'Ǳ': "DZ", 'ǲ': "Dz", 'ǳ': "dz", 'Ǆ': "DZ", 'ǅ': "Dz", 'ǆ': "dz",
	'Ǉ': "LJ", 'ǈ': "Lj", 'ǉ': "lj",
	'Ǌ': "NJ", 'ǋ': "Nj", 'ǌ': "nj",
	// B / C / D
	'Ɓ': "B", 'ɓ': "b", 'Ƃ': "B", 'ƃ': "b",
	'Ç': "C", 'Ć': "C", 'Ĉ': "C", 'Ċ': "C", 'Č': "C", 'Ƈ': "C",
	'ç': "c", 'ć': "c", 'ĉ': "c", 'ċ': "c", 'č': "c", 'ƈ': "c",
	'Ð': "D", 'Ď': "D", 'Đ': "D", 'Ɖ': "D", 'Ɗ': "D",
	'ð': "d", 'ď': "d", 'đ': "d", 'ɖ': "d", 'ɗ': "d",
	// E
	'È': "E", 'É': "E", 'Ê': "E", 'Ë': "E", 'Ē': "E", 'Ĕ': "E", 'Ė': "E", 'Ę': "E", 'Ě': "E",
	'Ẹ': "E", 'Ẻ': "E", 'Ẽ': "E", 'Ế': "E", 'Ề': "E", 'Ể': "E", 'Ễ': "E", 'Ệ': "E",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ĕ': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'ẹ': "e", 'ẻ': "e", 'ẽ': "e", 'ế': "e", 'ề': "e", 'ể': "e", 'ễ': "e", 'ệ': "e",
	// F / G / H
	'Ƒ': "F", 'ƒ': "f",
	'Ĝ': "G", 'Ğ': "G", 'Ġ': "G", 'Ģ': "G", 'Ǧ': "G", 'Ǵ': "G",
	'ĝ': "g", 'ğ': "g", 'ġ': "g", 'ģ': "g", 'ǧ': "g", 'ǵ': "g",
	'Ĥ': "H", 'Ħ': "H", 'ĥ': "h", 'ħ': "h",
	// I
	'Ì': "I", 'Í': "I", 'Î': "I", 'Ï': "I", 'Ĩ': "I", 'Ī': "I", 'Ĭ': "I", 'Į': "I", 'İ': "I", 'Ǐ': "I", 'Ỉ': "I", 'Ị': "I",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ĩ': "i", 'ī': "i", 'ĭ': "i", 'į': "i", 'ı': "i", 'ǐ': "i", 'ỉ': "i", 'ị': "i",
	// J / K / L / N
	'Ĵ': "J", 'ĵ': "j",
	'Ķ': "K", 'ķ': "k", 'ĸ': "k", 'Ǩ': "K", 'ǩ': "k",
	'Ĺ': "L", 'Ļ': "L", 'Ľ': "L", 'Ŀ': "L", 'Ł': "L",
	'ĺ': "l", 'ļ': "l", 'ľ': "l", 'ŀ': "l", 'ł': "l",
	'Ñ': "N", 'Ń': "N", 'Ņ': "N", 'Ň': "N", 'Ŋ': "N", 'Ǹ': "N",
	'ñ': "n", 'ń': "n", 'ņ': "n", 'ň': "n", 'ŉ': "n", 'ŋ': "n", 'ǹ': "n",
	// O
	'Ò': "O", 'Ó': "O", 'Ô': "O", 'Õ': "O", 'Ö': "O", 'Ø': "O", 'Ō': "O", 'Ŏ': "O", 'Ő': "O",
	'Ơ': "O", 'Ǒ': "O", 'Ǿ': "O", 'Ọ': "O", 'Ỏ': "O", 'Ố': "O", 'Ồ': "O", 'Ổ': "O", 'Ỗ': "O",
	'Ộ': "O", 'Ớ': "O", 'Ờ': "O", 'Ở': "O", 'Ỡ': "O", 'Ợ': "O",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o", 'ō': "o", 'ŏ': "o", 'ő': "o",
	'ơ': "o", 'ǒ': "o", 'ǿ': "o", 'ọ': "o", 'ỏ': "o", 'ố': "o", 'ồ': "o", 'ổ': "o", 'ỗ': "o",
	'ộ': "o", 'ớ': "o", 'ờ': "o", 'ở': "o", 'ỡ': "o", 'ợ': "o",
	// R / S / T
	'Ŕ': "R", 'Ŗ': "R", 'Ř': "R", 'ŕ': "r", 'ŗ': "r", 'ř': "r",
	'Ś': "S", 'Ŝ': "S", 'Ş': "S", 'Š': "S", 'Ș': "S",
	'ś': "s", 'ŝ': "s", 'ş': "s", 'š': "s", 'ș': "s", 'ſ': "s", 'ß': "ss", 'ẞ': "SS",
	'Ţ': "T", 'Ť': "T", 'Ŧ': "T", 'Ț': "T", 'Þ': "TH",
	'ţ': "t", 'ť': "t", 'ŧ': "t", 'ț': "t", 'þ': "th",
	// U
	'Ù': "U", 'Ú': "U", 'Û': "U", 'Ü': "U", 'Ũ': "U", 'Ū': "U", 'Ŭ': "U", 'Ů': "U", 'Ű': "U",
	'Ų': "U", 'Ư': "U", 'Ǔ': "U", 'Ụ': "U", 'Ủ': "U", 'Ứ': "U", 'Ừ': "U", 'Ử': "U", 'Ữ': "U", 'Ự': "U",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ũ': "u", 'ū': "u", 'ŭ': "u", 'ů': "u", 'ű': "u",
	'ų': "u", 'ư': "u", 'ǔ': "u", 'ụ': "u", 'ủ': "u", 'ứ': "u", 'ừ': "u", 'ử': "u", 'ữ': "u", 'ự': "u",
	// W / Y / Z
	'Ŵ': "W", 'ŵ': "w", 'Ẁ': "W", 'ẁ': "w", 'Ẃ': "W", 'ẃ': "w", 'Ẅ': "W", 'ẅ': "w",
	'Ý': "Y", 'Ŷ': "Y", 'Ÿ': "Y", 'Ỳ': "Y", 'Ỵ': "Y", 'Ỷ': "Y", 'Ỹ': "Y",
	'ý': "y", 'ÿ': "y", 'ŷ': "y", 'ỳ': "y", 'ỵ': "y", 'ỷ': "y", 'ỹ': "y",
	'Ź': "Z", 'Ż': "Z", 'Ž': "Z", 'ź': "z", 'ż': "z", 'ž': "z",
	// Ligatures & punctuation
	'ﬀ': "ff", 'ﬁ': "fi", 'ﬂ': "fl", 'ﬃ': "ffi", 'ﬄ': "ffl", 'ﬅ': "st", 'ﬆ': "st",
	'\u2018': "'", '\u2019': "'", '\u201A': "'", '\u201B': "'",
	'\u201C': "\"", '\u201D': "\"", '\u201E': "\"", '\u201F': "\"",
	'\u00AB': "\"", '\u00BB': "\"",
	'\u2010': "-", '\u2011': "-", '\u2012': "-", '\u2013': "-", '\u2014': "-",
	'\u00A0': " ",
	'⁰':      "0", '¹': "1", '²': "2", '³': "3", '⁴': "4", '⁵': "5", '⁶': "6", '⁷': "7", '⁸': "8", '⁹': "9",
	'₀': "0", '₁': "1", '₂': "2", '₃': "3", '₄': "4", '₅': "5", '₆': "6", '₇': "7", '₈': "8", '₉': "9",
}

// foldDecimalDigit converts all Unicode decimal digit characters (category Nd) to ASCII '0'..'9'.
func foldDecimalDigit(s string) string {
	const asciiDigits = "0123456789"
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		if unicode.Is(unicode.Nd, r) {
			if d, ok := unicodeDecimalDigitValue(r); ok && d >= 0 && d < len(asciiDigits) {
				b.WriteByte(asciiDigits[d])
				continue
			}
		}
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func unicodeDecimalDigitValue(r rune) (int, bool) {
	// Every Unicode Nd block is a contiguous 10-codepoint range '0'..'9'.
	for _, zero := range unicodeDecimalZeroBases {
		if r >= zero && r <= zero+9 {
			return int(r - zero), true
		}
	}
	return 0, false
}

var unicodeDecimalZeroBases = []rune{
	0x0030, // ASCII
	0x0660, // Arabic-Indic
	0x06F0, // Extended Arabic-Indic (Persian/Urdu)
	0x07C0, // NKo
	0x0966, // Devanagari
	0x09E6, // Bengali
	0x0A66, // Gurmukhi
	0x0AE6, // Gujarati
	0x0B66, // Oriya
	0x0BE6, // Tamil
	0x0C66, // Telugu
	0x0CE6, // Kannada
	0x0D66, // Malayalam
	0x0DE6, // Sinhala Lith
	0x0E50, // Thai
	0x0ED0, // Lao
	0x0F20, // Tibetan
	0x1040, // Myanmar
	0x1090, // Myanmar Shan
	0x17E0, // Khmer
	0x1810, // Mongolian
	0xFF10, // Fullwidth
}

// foldCJKWidth folds Fullwidth ASCII to Halfwidth ASCII and Halfwidth Katakana to Fullwidth Katakana.
func foldCJKWidth(s string) string {
	runes := []rune(s)
	var out []rune
	out = make([]rune, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		// Fullwidth ASCII variants U+FF01..U+FF5E -> U+0021..U+007E
		if r >= 0xFF01 && r <= 0xFF5E {
			out = append(out, r-0xFEE0)
			continue
		}
		if r == 0x3000 {
			out = append(out, ' ')
			continue
		}
		// Halfwidth Katakana U+FF65..U+FF9F
		if r >= 0xFF65 && r <= 0xFF9F {
			fw := halfwidthKatakanaMap[r-0xFF65]
			// Combine trailing dakuten (U+FF9E) or handakuten (U+FF9F) if applicable!
			if i+1 < len(runes) {
				next := runes[i+1]
				if next == 0xFF9E {
					if voiced, ok := katakanaVoicedMap[fw]; ok {
						out = append(out, voiced)
						i++
						continue
					}
				} else if next == 0xFF9F {
					if semi, ok := katakanaSemiVoicedMap[fw]; ok {
						out = append(out, semi)
						i++
						continue
					}
				}
			}
			out = append(out, fw)
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

var halfwidthKatakanaMap = [...]rune{
	'・', 'ヲ', 'ァ', 'ィ', 'ゥ', 'ェ', 'ォ', 'ャ', 'ュ', 'ョ', 'ッ',
	'ー', 'ア', 'イ', 'ウ', 'エ', 'オ', 'カ', 'キ', 'ク', 'ケ', 'コ',
	'サ', 'シ', 'ス', 'セ', 'ソ', 'タ', 'チ', 'ツ', 'テ', 'ト', 'ナ',
	'ニ', 'ヌ', 'ネ', 'ノ', 'ハ', 'ヒ', 'フ', 'ヘ', 'ホ', 'マ', 'ミ',
	'ム', 'メ', 'モ', 'ヤ', 'ユ', 'ヨ', 'ラ', 'リ', 'ル', 'レ', 'ロ',
	'ワ', 'ン', '゛', '゜',
}

var katakanaVoicedMap = map[rune]rune{
	'ウ': 'ヴ',
	'カ': 'ガ', 'キ': 'ギ', 'ク': 'グ', 'ケ': 'ゲ', 'コ': 'ゴ',
	'サ': 'ザ', 'シ': 'ジ', 'ス': 'ズ', 'セ': 'ゼ', 'ソ': 'ゾ',
	'タ': 'ダ', 'チ': 'ヂ', 'ツ': 'ヅ', 'テ': 'デ', 'ト': 'ド',
	'ハ': 'バ', 'ヒ': 'ビ', 'フ': 'ブ', 'ヘ': 'ベ', 'ホ': 'ボ',
}

var katakanaSemiVoicedMap = map[rune]rune{
	'ハ': 'パ', 'ヒ': 'ピ', 'フ': 'プ', 'ヘ': 'ペ', 'ホ': 'ポ',
}

// applyCJKBigram implements Lucene's CJKBigramFilter.
func applyCJKBigram(tokens []Token, ignoredScripts map[string]bool, outputUnigrams bool) []Token {
	type cjkChar struct {
		r     rune
		start int
		end   int
	}

	isHandledCJKToken := func(tok Token) bool {
		switch tok.Type {
		case "<IDEOGRAPHIC>":
			return !ignoredScripts["han"]
		case "<HIRAGANA>":
			return !ignoredScripts["hiragana"]
		case "<KATAKANA>":
			return !ignoredScripts["katakana"]
		case "<HANGUL>":
			return !ignoredScripts["hangul"]
		default:
			return false
		}
	}

	var out []Token
	nextPos := 0

	var buf []cjkChar
	flushBuf := func() {
		if len(buf) == 0 {
			return
		}
		if len(buf) == 1 {
			out = append(out, Token{
				Term:           string(buf[0].r),
				StartOffset:    buf[0].start,
				EndOffset:      buf[0].end,
				Type:           "<SINGLE>",
				Position:       nextPos,
				PositionLength: 1,
				TermFrequency:  1,
			})
			nextPos++
			buf = buf[:0]
			return
		}
		for i := 0; i < len(buf); i++ {
			if outputUnigrams {
				uPosLen := 1
				out = append(out, Token{
					Term:           string(buf[i].r),
					StartOffset:    buf[i].start,
					EndOffset:      buf[i].end,
					Type:           "<SINGLE>",
					Position:       nextPos,
					PositionLength: uPosLen,
					TermFrequency:  1,
				})
			}
			if i+1 < len(buf) {
				bPosLen := 1
				if outputUnigrams {
					bPosLen = 2
				}
				out = append(out, Token{
					Term:           string([]rune{buf[i].r, buf[i+1].r}),
					StartOffset:    buf[i].start,
					EndOffset:      buf[i+1].end,
					Type:           "<DOUBLE>",
					Position:       nextPos,
					PositionLength: bPosLen,
					TermFrequency:  1,
				})
				if !outputUnigrams {
					nextPos++
				}
			}
			if outputUnigrams {
				nextPos++
			}
		}
		buf = buf[:0]
	}

	var lastEnd int
	hasLastEnd := false
	for _, tok := range tokens {
		if !isHandledCJKToken(tok) {
			flushBuf()
			cp := tok.clone()
			cp.Position = nextPos
			if cp.PositionLength < 1 {
				cp.PositionLength = 1
			}
			out = append(out, cp)
			nextPos++
			hasLastEnd = false
			continue
		}
		// Non-adjacent CJK tokens (separated by whitespace/punctuation) flush the bigram buffer!
		if hasLastEnd && tok.StartOffset > lastEnd {
			flushBuf()
		}
		rs := []rune(tok.Term)
		span := tok.EndOffset - tok.StartOffset
		for k, r := range rs {
			var cs, ce int
			if span == len(rs) {
				cs = tok.StartOffset + k
				ce = cs + 1
			} else {
				cs = tok.StartOffset
				ce = tok.EndOffset
			}
			buf = append(buf, cjkChar{r: r, start: cs, end: ce})
		}
		lastEnd = tok.EndOffset
		hasLastEnd = true
	}
	flushBuf()
	return out
}

// Language Normalizers

func normalizeArabic(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u0622', '\u0623', '\u0625': // Alef with Madda/Hamza -> Alef
			b.WriteRune('\u0627')
		case '\u0649': // Alef Maksura -> Yeh
			b.WriteRune('\u064A')
		case '\u0629': // Teh Marbuta -> Heh
			b.WriteRune('\u0647')
		case '\u0640', '\u064B', '\u064C', '\u064D', '\u064E', '\u064F', '\u0650', '\u0651', '\u0652':
			// Strip Tatweel & Tashkeel diacritics
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizePersian(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u06CC', '\u0649': // Farsi Yeh / Alef Maksura -> Arabic Yeh U+064A
			b.WriteRune('\u064A')
		case '\u06A9': // Keheh -> Kaf U+0643
			b.WriteRune('\u0643')
		case '\u06C0', '\u0629': // Heh with Yeh / Teh Marbuta -> Heh U+0647
			b.WriteRune('\u0647')
		case '\u0654': // Hamza above -> strip
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizeSorani(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u064A', '\u0649': // Yeh / Alef Maksura -> Farsi Yeh U+06CC
			b.WriteRune('\u06CC')
		case '\u0643': // Kaf -> Keheh U+06A9
			b.WriteRune('\u06A9')
		case '\u0647', '\u0629', '\u06C0': // Heh / Teh Marbuta -> Kurdish Ae U+06D5
			b.WriteRune('\u06D5')
		case '\u0640', '\u200C': // Strip Tatweel & ZWNJ
		case '\u0695', '\u0692':
			b.WriteRune('\u0695')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizeIndic(s string) string {
	runes := []rune(s)
	n := len(runes)
	var out []rune
	out = make([]rune, 0, n)
	for i := 0; i < n; i++ {
		r := runes[i]
		// Bengali Khanda Ta: ত (09A4) + ্ (09CD) + ZWJ (200D) -> ৎ (09CE)
		if r == '\u09A4' && i+2 < n && runes[i+1] == '\u09CD' && runes[i+2] == '\u200D' {
			out = append(out, '\u09CE')
			i += 2
			continue
		}
		// Devanagari nasal consonant + halant before consonant -> anusvara (0902)
		if isDevanagariNasal(r) && i+2 < n && runes[i+1] == '\u094D' && isDevanagariStop(runes[i+2]) {
			out = append(out, '\u0902')
			i++
			continue
		}
		if r == '\u200C' || r == '\u200D' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

func isDevanagariNasal(r rune) bool {
	return r == '\u0919' || r == '\u091E' || r == '\u0923' || r == '\u0928' || r == '\u092E'
}

func isDevanagariStop(r rune) bool {
	return r >= '\u0915' && r <= '\u0939'
}

func normalizeBengali(s string) string {
	runes := []rune(s)
	n := len(runes)
	out := make([]rune, 0, n)
	for i := 0; i < n; i++ {
		r := runes[i]
		switch r {
		case '\u0981': // Chandrabindu deleted
			continue
		case '\u09BC': // Nukta: handle consonant + nukta combinations
			if len(out) > 0 {
				prev := out[len(out)-1]
				switch prev {
				case '\u09A1', '\u09A2': // ড/ঢ + ় -> র
					out[len(out)-1] = '\u09B0'
				case '\u09AF': // য + ় -> য
				}
			}
			continue
		case '\u09DC', '\u09DD': // ড় / ঢ় -> র
			out = append(out, '\u09B0')
		case '\u09DF': // য় -> য
			out = append(out, '\u09AF')
		case '\u09C0': // ী -> ি
			out = append(out, '\u09BF')
		case '\u09C2': // ূ -> ু
			out = append(out, '\u09C1')
		case '\u0988': // ঈ -> ই
			out = append(out, '\u0987')
		case '\u098A': // ঊ -> উ
			out = append(out, '\u0989')
		case '\u09CE': // ৎ -> ত
			out = append(out, '\u09A4')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func normalizeHindi(s string) string {
	var out []rune
	for _, r := range s {
		switch r {
		case '\u0901': // Chandrabindu -> Anusvara
			out = append(out, '\u0902')
		case '\u093C': // Nukta deleted
			continue
		case '\u0958':
			out = append(out, '\u0915')
		case '\u0959':
			out = append(out, '\u0916')
		case '\u095A':
			out = append(out, '\u0917')
		case '\u095B':
			out = append(out, '\u091C')
		case '\u095C':
			out = append(out, '\u0921')
		case '\u095D':
			out = append(out, '\u0922')
		case '\u095E':
			out = append(out, '\u092B')
		case '\u095F':
			out = append(out, '\u092F')
		case '\u0940': // ी -> ि
			out = append(out, '\u093F')
		case '\u0942': // ू -> ु
			out = append(out, '\u0941')
		case '\u0943', '\u0944':
			out = append(out, '\u0930')
		case '\u0945', '\u0946':
			out = append(out, '\u0947')
		case '\u0949', '\u094A':
			out = append(out, '\u094B')
		case '\u0908':
			out = append(out, '\u0907')
		case '\u090A':
			out = append(out, '\u0909')
		case '\u090D', '\u090E':
			out = append(out, '\u090F')
		case '\u0911', '\u0912':
			out = append(out, '\u0913')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func normalizeGerman(s string) string {
	// Implements Lucene GermanNormalizationFilter (DIN 5007-2 style):
	// ß -> ss; ä/ae -> a; ö/oe -> o; ü/ue -> u (with 'u' exception after q/e/a/o).
	runes := []rune(s)
	out := make([]rune, 0, len(runes)+2)
	const (
		stateN = iota
		stateV
		stateU
	)
	state := stateN
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case 'a', 'o':
			out = append(out, c)
			state = stateU
		case 'e':
			if state == stateU && len(out) > 0 {
				prev := out[len(out)-1]
				switch prev {
				case 'a', 'o', 'u', 'A', 'O', 'U':
					// ae/oe/ue -> a/o/u (drop 'e')
					state = stateV
					continue
				}
			}
			out = append(out, c)
			state = stateV
		case 'u':
			if state == stateN {
				state = stateU
			} else {
				state = stateV
			}
			out = append(out, c)
		case 'q', 'Q':
			out = append(out, c)
			state = stateV
		case 'i', 'y', 'I', 'Y':
			out = append(out, c)
			state = stateV
		case 'ä':
			out = append(out, 'a')
			state = stateV
		case 'Ä':
			out = append(out, 'A')
			state = stateV
		case 'ö':
			out = append(out, 'o')
			state = stateV
		case 'Ö':
			out = append(out, 'O')
			state = stateV
		case 'ü':
			out = append(out, 'u')
			state = stateV
		case 'Ü':
			out = append(out, 'U')
			state = stateV
		case 'ß':
			out = append(out, 's', 's')
			state = stateN
		case 's':
			if i+2 < len(runes) && runes[i+1] == 'c' && runes[i+2] == 'h' {
				out = append(out, 's', 'c', 'h')
				i += 2
				state = stateN
				continue
			}
			out = append(out, c)
			state = stateN
		default:
			out = append(out, c)
			state = stateN
		}
	}
	return string(out)
}

func normalizeScandinavian(s string) string {
	// Lucene ScandinavianNormalizationFilter: folds interchangeable å/aa->å, ä/æ/ae->æ, ö/ø/oe->ø.
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case 'ä':
			out = append(out, 'æ')
		case 'Ä':
			out = append(out, 'Æ')
		case 'ö':
			out = append(out, 'ø')
		case 'Ö':
			out = append(out, 'Ø')
		case 'a', 'A':
			if i+1 < len(runes) {
				nx := runes[i+1]
				if nx == 'a' || nx == 'A' {
					if r == 'A' {
						out = append(out, 'Å')
					} else {
						out = append(out, 'å')
					}
					i++
					continue
				}
				if nx == 'e' || nx == 'E' {
					if r == 'A' {
						out = append(out, 'Æ')
					} else {
						out = append(out, 'æ')
					}
					i++
					continue
				}
				if nx == 'o' || nx == 'O' {
					if r == 'A' {
						out = append(out, 'Å')
					} else {
						out = append(out, 'å')
					}
					i++
					continue
				}
			}
			out = append(out, r)
		case 'o', 'O':
			if i+1 < len(runes) && (runes[i+1] == 'e' || runes[i+1] == 'E') {
				if r == 'O' {
					out = append(out, 'Ø')
				} else {
					out = append(out, 'ø')
				}
				i++
				continue
			}
			out = append(out, r)
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func foldScandinavian(s string) string {
	// Lucene ScandinavianFoldingFilter: folds å/ä/æ/aa/ae -> a and ö/ø/oe -> o!
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case 'å', 'ä', 'æ':
			out = append(out, 'a')
		case 'Å', 'Ä', 'Æ':
			out = append(out, 'A')
		case 'ö', 'ø':
			out = append(out, 'o')
		case 'Ö', 'Ø':
			out = append(out, 'O')
		case 'a', 'A':
			if i+1 < len(runes) {
				nx := runes[i+1]
				if nx == 'a' || nx == 'A' || nx == 'e' || nx == 'E' || nx == 'o' || nx == 'O' {
					out = append(out, r)
					i++
					continue
				}
			}
			out = append(out, r)
		case 'o', 'O':
			if i+1 < len(runes) && (runes[i+1] == 'e' || runes[i+1] == 'E') {
				out = append(out, r)
				i++
				continue
			}
			out = append(out, r)
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func normalizeSerbian(s string, haircut string) string {
	regular := strings.EqualFold(strings.TrimSpace(haircut), "regular")
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if regular {
			if rep, ok := serbianRegularMap[r]; ok {
				b.WriteString(rep)
				continue
			}
		} else {
			if rep, ok := serbianBaldMap[r]; ok {
				b.WriteString(rep)
				continue
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

var serbianBaldMap = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'ђ': "dj", 'е': "e", 'ж': "z",
	'з': "z", 'и': "i", 'ј': "j", 'к': "k", 'л': "l", 'љ': "lj", 'м': "m", 'н': "n",
	'њ': "nj", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'ћ': "c", 'у': "u",
	'ф': "f", 'х': "h", 'ц': "c", 'ч': "c", 'џ': "dz", 'ш': "s",
	'А': "A", 'Б': "B", 'В': "V", 'Г': "G", 'Д': "D", 'Ђ': "Dj", 'Е': "E", 'Ж': "Z",
	'З': "Z", 'И': "I", 'Ј': "J", 'К': "K", 'Л': "L", 'Љ': "Lj", 'М': "M", 'Н': "N",
	'Њ': "Nj", 'О': "O", 'П': "P", 'Р': "R", 'С': "S", 'Т': "T", 'Ћ': "C", 'У': "U",
	'Ф': "F", 'Х': "H", 'Ц': "C", 'Ч': "C", 'Џ': "Dz", 'Ш': "S",
	'đ': "dj", 'Đ': "Dj", 'ž': "z", 'Ž': "Z", 'ć': "c", 'Ć': "C", 'č': "c", 'Č': "C", 'š': "s", 'Š': "S",
}

var serbianRegularMap = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'ђ': "đ", 'е': "e", 'ж': "ž",
	'з': "z", 'и': "i", 'ј': "j", 'к': "k", 'л': "l", 'љ': "lj", 'м': "m", 'н': "n",
	'њ': "nj", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'ћ': "ć", 'у': "u",
	'ф': "f", 'х': "h", 'ц': "c", 'ч': "č", 'џ': "dž", 'ш': "š",
	'А': "A", 'Б': "B", 'В': "V", 'Г': "G", 'Д': "D", 'Ђ': "Đ", 'Е': "E", 'Ж': "Ž",
	'З': "Z", 'И': "I", 'Ј': "J", 'К': "K", 'Л': "L", 'Љ': "Lj", 'М': "M", 'Н': "N",
	'Њ': "Nj", 'О': "O", 'П': "P", 'Р': "R", 'С': "S", 'Т': "T", 'Ћ': "Ć", 'У': "U",
	'Ф': "F", 'Х': "H", 'Ц': "C", 'Ч': "Č", 'Џ': "Dž", 'Ш': "Š",
}

func lowercaseWithLang(s string, lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "", "default":
		return strings.ToLower(s)
	case "greek":
		var b strings.Builder
		b.Grow(len(s))
		for _, r := range s {
			b.WriteRune(greekLowerRune(r))
		}
		return b.String()
	case "turkish":
		var b strings.Builder
		b.Grow(len(s))
		runes := []rune(s)
		for i := 0; i < len(runes); i++ {
			r := runes[i]
			if r == 'İ' {
				b.WriteRune('i')
				continue
			}
			if r == 'I' {
				if i+1 < len(runes) && runes[i+1] == '\u0307' {
					b.WriteRune('i')
					i++
				} else {
					b.WriteRune('ı')
				}
				continue
			}
			if r == '\u0307' {
				continue
			}
			b.WriteRune(unicode.ToLower(r))
		}
		return b.String()
	case "irish":
		runes := []rune(s)
		var b strings.Builder
		b.Grow(len(s) + 2)
		if len(runes) >= 2 && (runes[0] == 'n' || runes[0] == 't') && isIrishUpperVowel(runes[1]) {
			b.WriteRune(runes[0])
			b.WriteByte('-')
			for _, r := range runes[1:] {
				b.WriteRune(unicode.ToLower(r))
			}
			return b.String()
		}
		return strings.ToLower(s)
	default:
		return strings.ToLower(s)
	}
}

func isIrishUpperVowel(r rune) bool {
	switch r {
	case 'A', 'E', 'I', 'O', 'U', 'Á', 'É', 'Í', 'Ó', 'Ú':
		return true
	default:
		return false
	}
}

func greekLowerRune(r rune) rune {
	switch r {
	case 'Ά', 'Α', 'ά':
		return 'α'
	case 'Έ', 'Ε', 'έ':
		return 'ε'
	case 'Ή', 'Η', 'ή':
		return 'η'
	case 'Ί', 'Ϊ', 'Ι', 'ί', 'ϊ', 'ΐ':
		return 'ι'
	case 'Ό', 'Ο', 'ό':
		return 'ο'
	case 'Ύ', 'Ϋ', 'Υ', 'ύ', 'ϋ', 'ΰ':
		return 'υ'
	case 'Ώ', 'Ω', 'ώ':
		return 'ω'
	case 'Σ', 'ς':
		return 'σ'
	default:
		return unicode.ToLower(r)
	}
}

var defaultElisionArticles = []string{
	"l", "m", "t", "qu", "n", "s", "j", "d", "c", "jusqu", "quoiqu", "lorsqu", "puisqu",
}

func applyElision(s string, articles []string, articlesCase bool) string {
	idx := strings.IndexAny(s, "'\u2019")
	if idx <= 0 {
		return s
	}
	prefix := s[:idx]
	var rest string
	if strings.HasPrefix(s[idx:], "\u2019") {
		rest = s[idx+len("\u2019"):]
	} else {
		rest = s[idx+1:]
	}
	for _, art := range articles {
		if articlesCase {
			if strings.EqualFold(prefix, art) {
				return rest
			}
		} else {
			if prefix == art {
				return rest
			}
		}
	}
	return s
}

func applyApostrophe(s string) string {
	idx := strings.IndexAny(s, "'\u2019")
	if idx < 0 {
		return s
	}
	return s[:idx]
}

func applyClassicFilter(tok Token) Token {
	switch tok.Type {
	case "<APOSTROPHE>":
		for _, suf := range []string{"'s", "'S", "\u2019s", "\u2019S"} {
			if strings.HasSuffix(tok.Term, suf) {
				tok.Term = strings.TrimSuffix(tok.Term, suf)
				break
			}
		}
	case "<ACRONYM>":
		tok.Term = strings.ReplaceAll(tok.Term, ".", "")
	default:
		for _, suf := range []string{"'s", "'S"} {
			if strings.HasSuffix(tok.Term, suf) {
				tok.Term = strings.TrimSuffix(tok.Term, suf)
				break
			}
		}
	}
	return tok
}
