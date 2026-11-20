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
	"regexp"
	"strings"
	"unicode"
)

const maxPhoneticCodeLen = 64

var validBeiderMorseLanguages = map[string]bool{
	"any": true, "common": true, "arabic": true, "cyrillic": true,
	"czech": true, "dutch": true, "english": true, "french": true,
	"german": true, "greek": true, "greeklatin": true, "hebrew": true,
	"hungarian": true, "italian": true, "latvian": true, "polish": true,
	"portuguese": true, "romanian": true, "russian": true, "spanish": true,
	"turkish": true,
}

func buildPhoneticTokenFilter(displayName string, def map[string]any) (*compiledTokenFilter, error) {
	replace := true
	encoder := "metaphone"
	maxCodeLen := 0
	ruleType := "approx"
	nameType := "generic"
	var langSet []string

	if def != nil {
		if raw, ok := def["replace"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("replace in phonetic filter must be boolean")
			}
			replace = b
		}
		if enc, ok := def["encoder"].(string); ok && strings.TrimSpace(enc) != "" {
			encoder = strings.TrimSpace(enc)
		}
		if raw, ok := def["max_code_len"]; ok {
			n, valid := extractInt(raw)
			if !valid || n < 1 || n > maxPhoneticCodeLen {
				return nil, newIllegalArgError(fmt.Sprintf("max_code_len in phonetic filter must be between 1 and %d", maxPhoneticCodeLen))
			}
			maxCodeLen = n
		}
	}

	normEnc := strings.ToLower(encoder)
	var encodeMulti func(string) []string
	injectFirst := true // Lucene PhoneticFilter emits encoded token BEFORE original when replace == false

	switch normEnc {
	case "metaphone":
		effMax := 4
		if maxCodeLen > 0 {
			effMax = maxCodeLen
		}
		encodeMulti = func(s string) []string {
			c := encodeMetaphone(s, effMax)
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "double_metaphone", "doublemetaphone":
		effMax := 4
		if maxCodeLen > 0 {
			effMax = maxCodeLen
		}
		encodeMulti = func(s string) []string {
			p, a := encodeDoubleMetaphone(s, effMax)
			if p == "" && a == "" {
				return nil
			}
			if a != "" && a != p {
				return []string{p, a}
			}
			return []string{p}
		}

	case "soundex":
		encodeMulti = func(s string) []string {
			c := encodeSoundex(s)
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "refined_soundex", "refinedsoundex":
		encodeMulti = func(s string) []string {
			c := encodeRefinedSoundex(s)
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "caverphone1":
		encodeMulti = func(s string) []string {
			return []string{encodeCaverphone1(s)}
		}

	case "caverphone2", "caverphone":
		encodeMulti = func(s string) []string {
			return []string{encodeCaverphone2(s)}
		}

	case "cologne":
		encodeMulti = func(s string) []string {
			c := encodeColognePhonetic(s, '0')
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "koelnerphonetik":
		encodeMulti = func(s string) []string {
			c := encodeKoelnerOrHaase(s, false)
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "haasephonetik":
		encodeMulti = func(s string) []string {
			c := encodeKoelnerOrHaase(s, true)
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "nysiis":
		encodeMulti = func(s string) []string {
			c := encodeNYSIIS(s)
			if c == "" {
				return nil
			}
			return []string{c}
		}

	case "bm", "beider_morse", "beidermorse":
		if def != nil {
			if rt, ok := def["rule_type"].(string); ok && strings.TrimSpace(rt) != "" {
				lrt := strings.ToLower(strings.TrimSpace(rt))
				if lrt != "approx" && lrt != "exact" {
					return nil, newIllegalArgError(fmt.Sprintf("No matching rule type [%s] for beider morse encoder", rt))
				}
				ruleType = lrt
			}
			if nt, ok := def["name_type"].(string); ok && strings.TrimSpace(nt) != "" {
				lnt := strings.ToLower(strings.TrimSpace(nt))
				if lnt != "generic" && lnt != "ashkenazi" && lnt != "sephardic" {
					return nil, newIllegalArgError(fmt.Sprintf("No matching name type [%s] for beider morse encoder", nt))
				}
				nameType = lnt
			}
			if rawLS, hasLS := def["languageset"]; hasLS {
				langSet = extractStringSlice(rawLS)
			} else if rawL, hasL := def["languages"]; hasL {
				langSet = extractStringSlice(rawL)
			}
			for _, lg := range langSet {
				ll := strings.ToLower(strings.TrimSpace(lg))
				if ll != "" && !validBeiderMorseLanguages[ll] {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown language [%s] in beider_morse phonetic filter", lg))
				}
			}
		}
		// BeiderMorseFilter replaces tokens with encoded representations in Lucene.
		encodeMulti = func(s string) []string {
			return encodeBeiderMorse(s, nameType, ruleType, langSet)
		}

	case "daitch_mokotoff":
		injectFirst = false
		encodeMulti = func(s string) []string {
			return encodeDaitchMokotoff(s)
		}

	default:
		return nil, newIllegalArgError(fmt.Sprintf("unknown encoder [%s] for phonetic token filter", encoder))
	}

	return &compiledTokenFilter{
		name: displayName,
		typ:  "phonetic",
		apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
			var out []Token
			for _, tok := range tokens {
				codes := encodeMulti(tok.Term)
				if len(codes) == 0 {
					cp := tok.clone()
					if err := budget.addToken(cp); err != nil {
						return nil, err
					}
					out = append(out, cp)
					continue
				}
				if replace {
					seen := make(map[string]bool, len(codes))
					for _, c := range codes {
						if c == "" || seen[c] {
							continue
						}
						seen[c] = true
						cp := tok.clone()
						cp.Term = c
						if err := budget.addToken(cp); err != nil {
							return nil, err
						}
						out = append(out, cp)
					}
					continue
				}
				// replace == false (inject == true): emit at same Position!
				seen := make(map[string]bool, len(codes)+1)
				if injectFirst {
					for _, c := range codes {
						if c == "" || c == tok.Term || seen[c] {
							continue
						}
						seen[c] = true
						cp := tok.clone()
						cp.Term = c
						if err := budget.addToken(cp); err != nil {
							return nil, err
						}
						out = append(out, cp)
					}
					orig := tok.clone()
					if err := budget.addToken(orig); err != nil {
						return nil, err
					}
					out = append(out, orig)
				} else {
					seen[tok.Term] = true
					orig := tok.clone()
					if err := budget.addToken(orig); err != nil {
						return nil, err
					}
					out = append(out, orig)
					for _, c := range codes {
						if c == "" || seen[c] {
							continue
						}
						seen[c] = true
						cp := tok.clone()
						cp.Term = c
						if err := budget.addToken(cp); err != nil {
							return nil, err
						}
						out = append(out, cp)
					}
				}
			}
			return out, nil
		},
	}, nil
}

func cleanASCIIUpperLetters(s string) []byte {
	folded, _ := foldASCII(s)
	out := make([]byte, 0, len(folded))
	for i := 0; i < len(folded); i++ {
		c := folded[i]
		if c >= 'a' && c <= 'z' {
			out = append(out, c-'a'+'A')
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c)
		}
	}
	return out
}

func isMetaphoneVowel(b byte) bool {
	return b == 'A' || b == 'E' || b == 'I' || b == 'O' || b == 'U'
}

func isMetaphoneFrontV(b byte) bool {
	return b == 'E' || b == 'I' || b == 'Y'
}

func isMetaphoneVarson(b byte) bool {
	return b == 'C' || b == 'S' || b == 'P' || b == 'T' || b == 'G'
}

// encodeMetaphone implements Apache Commons Codec Metaphone.
func encodeMetaphone(txt string, maxCodeLen int) string {
	in := cleanASCIIUpperLetters(txt)
	if len(in) == 0 {
		return ""
	}
	if len(in) == 1 {
		return string(in)
	}
	switch in[0] {
	case 'K', 'G', 'P':
		if in[1] == 'N' {
			in = in[1:]
		}
	case 'A':
		if in[1] == 'E' {
			in = in[1:]
		}
	case 'W':
		switch in[1] {
		case 'R':
			in = in[1:]
		case 'H':
			in[1] = 'W'
			in = in[1:]
		}
	case 'X':
		in[0] = 'S'
	}

	wdsz := len(in)
	var code strings.Builder
	code.Grow(maxCodeLen)

	regionMatch := func(idx int, pat string) bool {
		if idx < 0 || idx+len(pat) > wdsz {
			return false
		}
		for k := 0; k < len(pat); k++ {
			if in[idx+k] != pat[k] {
				return false
			}
		}
		return true
	}

	for n := 0; n < wdsz && code.Len() < maxCodeLen; n++ {
		symb := in[n]
		if symb != 'C' && n > 0 && in[n-1] == symb {
			continue
		}
		switch symb {
		case 'A', 'E', 'I', 'O', 'U':
			if n == 0 {
				code.WriteByte(symb)
			}
		case 'B':
			if n > 0 && n+1 == wdsz && in[n-1] == 'M' {
				continue
			}
			code.WriteByte('B')
		case 'C':
			if n > 0 && in[n-1] == 'S' && n+1 < wdsz && isMetaphoneFrontV(in[n+1]) {
				continue
			}
			if regionMatch(n, "CIA") {
				code.WriteByte('X')
				continue
			}
			if n+1 < wdsz && isMetaphoneFrontV(in[n+1]) {
				code.WriteByte('S')
				continue
			}
			if n > 0 && n+1 < wdsz && in[n-1] == 'S' && in[n+1] == 'H' {
				code.WriteByte('K')
				continue
			}
			if n+1 < wdsz && in[n+1] == 'H' {
				if n == 0 && wdsz >= 3 && !isMetaphoneVowel(in[2]) {
					code.WriteByte('K')
				} else {
					code.WriteByte('X')
				}
			} else {
				code.WriteByte('K')
			}
		case 'D':
			if n+2 < wdsz && in[n+1] == 'G' && isMetaphoneFrontV(in[n+2]) {
				code.WriteByte('J')
				n++
			} else {
				code.WriteByte('T')
			}
		case 'G':
			if n+2 == wdsz && in[n+1] == 'H' {
				continue
			}
			if n+2 < wdsz && in[n+1] == 'H' && !isMetaphoneVowel(in[n+2]) {
				continue
			}
			if n > 0 && ((regionMatch(n, "GN") && n+2 == wdsz) || (regionMatch(n, "GNED") && n+4 == wdsz)) {
				continue
			}
			hard := n > 0 && in[n-1] == 'G'
			if n+1 < wdsz && isMetaphoneFrontV(in[n+1]) && !hard {
				code.WriteByte('J')
			} else {
				code.WriteByte('K')
			}
		case 'H':
			if n+1 == wdsz {
				continue
			}
			if n > 0 && isMetaphoneVarson(in[n-1]) {
				continue
			}
			if isMetaphoneVowel(in[n+1]) {
				code.WriteByte('H')
			}
		case 'F', 'J', 'L', 'M', 'N', 'R':
			code.WriteByte(symb)
		case 'K':
			if n == 0 || in[n-1] != 'C' {
				code.WriteByte('K')
			}
		case 'P':
			if n+1 < wdsz && in[n+1] == 'H' {
				code.WriteByte('F')
			} else {
				code.WriteByte('P')
			}
		case 'Q':
			code.WriteByte('K')
		case 'S':
			if regionMatch(n, "SH") || regionMatch(n, "SIO") || regionMatch(n, "SIA") {
				code.WriteByte('X')
			} else {
				code.WriteByte('S')
			}
		case 'T':
			if regionMatch(n, "TIA") || regionMatch(n, "TIO") {
				code.WriteByte('X')
				continue
			}
			if regionMatch(n, "TCH") {
				continue
			}
			if regionMatch(n, "TH") {
				code.WriteByte('0')
			} else {
				code.WriteByte('T')
			}
		case 'V':
			code.WriteByte('F')
		case 'W', 'Y':
			if n+1 < wdsz && isMetaphoneVowel(in[n+1]) {
				code.WriteByte(symb)
			}
		case 'X':
			code.WriteByte('K')
			if code.Len() < maxCodeLen {
				code.WriteByte('S')
			}
		case 'Z':
			code.WriteByte('S')
		}
	}
	res := code.String()
	if len(res) > maxCodeLen {
		return res[:maxCodeLen]
	}
	return res
}

// encodeDoubleMetaphone implements primary + alternate Double Metaphone up to maxCodeLen.
func encodeDoubleMetaphone(txt string, maxCodeLen int) (string, string) {
	in := cleanASCIIUpperLetters(txt)
	n := len(in)
	if n == 0 {
		return "", ""
	}
	var prim, alt strings.Builder
	addBoth := func(s string) {
		if prim.Len() < maxCodeLen {
			prim.WriteString(s)
		}
		if alt.Len() < maxCodeLen {
			alt.WriteString(s)
		}
	}
	addDiff := func(p, a string) {
		if prim.Len() < maxCodeLen {
			prim.WriteString(p)
		}
		if alt.Len() < maxCodeLen {
			alt.WriteString(a)
		}
	}
	at := func(idx int) byte {
		if idx < 0 || idx >= n {
			return 0
		}
		return in[idx]
	}
	hasAt := func(idx int, opts ...string) bool {
		if idx < 0 {
			return false
		}
		for _, o := range opts {
			if idx+len(o) <= n && string(in[idx:idx+len(o)]) == o {
				return true
			}
		}
		return false
	}
	isDMVowel := func(b byte) bool {
		return b == 'A' || b == 'E' || b == 'I' || b == 'O' || b == 'U' || b == 'Y'
	}

	i := 0
	if hasAt(0, "GN", "KN", "PN", "WR", "PS") {
		i = 1
	} else if at(0) == 'X' {
		addBoth("S")
		i = 1
	}

	for i < n && (prim.Len() < maxCodeLen || alt.Len() < maxCodeLen) {
		ch := in[i]
		switch ch {
		case 'A', 'E', 'I', 'O', 'U', 'Y':
			if i == 0 {
				addBoth("A")
			}
			i++
		case 'B':
			addBoth("P")
			if at(i+1) == 'B' {
				i += 2
			} else {
				i++
			}
		case 'C':
			if hasAt(i, "CH") {
				if i == 0 && hasAt(i, "CHIA", "CHEM", "CHOR", "CHARAC", "CHARIS") {
					addBoth("K")
				} else if hasAt(0, "SCH") || hasAt(i-2, "ORCHES", "ARCHIT", "ORCHID") {
					addBoth("K")
				} else if i == 0 && !isDMVowel(at(2)) {
					addBoth("K")
				} else {
					addDiff("X", "K")
				}
				i += 2
			} else if hasAt(i, "CZ") && !hasAt(i-2, "WICZ") {
				addDiff("S", "X")
				i += 2
			} else if hasAt(i+1, "CIA") {
				addBoth("X")
				i += 3
			} else if hasAt(i, "CC") && (i != 1 || at(0) != 'M') {
				if at(i+2) == 'I' || at(i+2) == 'E' || at(i+2) == 'H' {
					addBoth("X")
					i += 3
				} else {
					addBoth("K")
					i += 2
				}
			} else if hasAt(i, "CK", "CG", "CQ") {
				addBoth("K")
				i += 2
			} else if hasAt(i, "CI", "CE", "CY") {
				if hasAt(i, "CIO", "CIE", "CIA") {
					addDiff("S", "X")
				} else {
					addBoth("S")
				}
				i += 2
			} else {
				addBoth("K")
				if hasAt(i+1, "C", "Q", "G") {
					i += 2
				} else {
					i++
				}
			}
		case 'D':
			if hasAt(i, "DG") {
				if at(i+2) == 'I' || at(i+2) == 'E' || at(i+2) == 'Y' {
					addBoth("J")
					i += 3
				} else {
					addBoth("TK")
					i += 2
				}
			} else if hasAt(i, "DT", "DD") {
				addBoth("T")
				i += 2
			} else {
				addBoth("T")
				i++
			}
		case 'F':
			addBoth("F")
			if at(i+1) == 'F' {
				i += 2
			} else {
				i++
			}
		case 'G':
			if at(i+1) == 'H' {
				if i > 0 && !isDMVowel(at(i-1)) {
					addBoth("K")
					i += 2
				} else if i == 0 {
					if at(i+2) == 'I' {
						addBoth("J")
					} else {
						addBoth("K")
					}
					i += 2
				} else {
					i += 2
				}
			} else if at(i+1) == 'N' {
				if i == 1 && isDMVowel(at(0)) {
					addDiff("KN", "N")
				} else {
					addBoth("N")
				}
				i += 2
			} else if (at(i+1) == 'E' || at(i+1) == 'I' || at(i+1) == 'Y') && at(i-1) != 'G' {
				addDiff("J", "K")
				i += 2
			} else {
				addBoth("K")
				if at(i+1) == 'G' {
					i += 2
				} else {
					i++
				}
			}
		case 'H':
			if (i == 0 || isDMVowel(at(i-1))) && isDMVowel(at(i+1)) {
				addBoth("H")
				i += 2
			} else {
				i++
			}
		case 'J':
			addDiff("J", "H")
			if at(i+1) == 'J' {
				i += 2
			} else {
				i++
			}
		case 'K':
			addBoth("K")
			if at(i+1) == 'K' {
				i += 2
			} else {
				i++
			}
		case 'L':
			addBoth("L")
			if at(i+1) == 'L' {
				i += 2
			} else {
				i++
			}
		case 'M':
			addBoth("M")
			if at(i+1) == 'M' || (at(i-1) == 'U' && at(i+1) == 'B' && (i+2 == n || hasAt(i+2, "ER"))) {
				i += 2
			} else {
				i++
			}
		case 'N':
			addBoth("N")
			if at(i+1) == 'N' {
				i += 2
			} else {
				i++
			}
		case 'P':
			if at(i+1) == 'H' {
				addBoth("F")
				i += 2
			} else {
				addBoth("P")
				if at(i+1) == 'P' || at(i+1) == 'B' {
					i += 2
				} else {
					i++
				}
			}
		case 'Q':
			addBoth("K")
			if at(i+1) == 'Q' {
				i += 2
			} else {
				i++
			}
		case 'R':
			addBoth("R")
			if at(i+1) == 'R' {
				i += 2
			} else {
				i++
			}
		case 'S':
			if hasAt(i, "SH") {
				addBoth("X")
				i += 2
			} else if hasAt(i, "SIO", "SIA") {
				addDiff("S", "X")
				i += 3
			} else if hasAt(i, "SCH") {
				addBoth("SK")
				i += 3
			} else {
				addBoth("S")
				if at(i+1) == 'S' || at(i+1) == 'Z' {
					i += 2
				} else {
					i++
				}
			}
		case 'T':
			if hasAt(i, "TION", "TIA", "TCH") {
				addBoth("X")
				i += 3
			} else if hasAt(i, "TH") {
				addDiff("0", "T")
				i += 2
			} else {
				addBoth("T")
				if at(i+1) == 'T' || at(i+1) == 'D' {
					i += 2
				} else {
					i++
				}
			}
		case 'V':
			addBoth("F")
			if at(i+1) == 'V' {
				i += 2
			} else {
				i++
			}
		case 'W':
			if hasAt(i, "WR") {
				addBoth("R")
				i += 2
			} else if i == 0 && (isDMVowel(at(i+1)) || hasAt(i, "WH")) {
				if isDMVowel(at(i + 1)) {
					addDiff("A", "F")
				} else {
					addBoth("A")
				}
				i++
			} else {
				i++
			}
		case 'X':
			if i == n-1 && (hasAt(i-3, "IAU", "EAU") || hasAt(i-2, "AU", "OU")) {
				i++
			} else {
				addBoth("KS")
				if at(i+1) == 'C' || at(i+1) == 'X' {
					i += 2
				} else {
					i++
				}
			}
		case 'Z':
			addBoth("S")
			if at(i+1) == 'Z' {
				i += 2
			} else {
				i++
			}
		default:
			i++
		}
	}

	p := prim.String()
	a := alt.String()
	if len(p) > maxCodeLen {
		p = p[:maxCodeLen]
	}
	if len(a) > maxCodeLen {
		a = a[:maxCodeLen]
	}
	return p, a
}

var soundexDigits = [26]byte{
	'0', '1', '2', '3', '0', '1', '2', '0', '0', '2', '2', '4', '5',
	'5', '0', '1', '2', '6', '2', '3', '0', '1', '0', '2', '0', '2',
}

// encodeSoundex implements US Census / Apache Commons Codec Soundex.
func encodeSoundex(txt string) string {
	in := cleanASCIIUpperLetters(txt)
	if len(in) == 0 {
		return ""
	}
	out := [4]byte{in[0], '0', '0', '0'}
	count := 1
	lastDigit := soundexDigits[in[0]-'A']
	for i := 1; i < len(in) && count < 4; i++ {
		c := in[i]
		if c == 'H' || c == 'W' {
			continue
		}
		d := soundexDigits[c-'A']
		if d == '0' {
			lastDigit = '0'
			continue
		}
		if d != lastDigit {
			out[count] = d
			count++
			lastDigit = d
		}
	}
	return string(out[:])
}

var refinedSoundexMap = [26]byte{
	'0', '1', '3', '6', '0', '2', '4', '0', '0', '4', '3', '7', '8',
	'8', '0', '1', '5', '9', '3', '6', '0', '2', '0', '5', '0', '5',
}

func encodeRefinedSoundex(txt string) string {
	in := cleanASCIIUpperLetters(txt)
	if len(in) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte(in[0])
	var last byte
	for _, c := range in {
		code := refinedSoundexMap[c-'A']
		if code == last {
			continue
		}
		if c != 'H' && c != 'W' {
			sb.WriteByte(code)
		}
		last = code
	}
	return sb.String()
}

var caverphoneRulesCommon = [][2]string{
	{"cough", "cou2f"}, {"rough", "rou2f"}, {"tough", "tou2f"}, {"enough", "enou2f"},
	{"gn", "2n"}, {"mb$", "m2"}, {"cq", "2q"}, {"ci", "si"}, {"ce", "se"}, {"cy", "sy"},
	{"tch", "2ch"}, {"c", "k"}, {"q", "k"}, {"x", "k"}, {"v", "f"},
	{"dg", "2g"}, {"tio", "sio"}, {"tia", "sia"}, {"d", "t"}, {"ph", "fh"},
	{"b", "p"}, {"sh", "s2"}, {"z", "s"},
}

func encodeCaverphone(txt string, v2 bool) string {
	pad := "111111"
	targetLen := 6
	if v2 {
		pad = "1111111111"
		targetLen = 10
	}
	in := cleanASCIIUpperLetters(txt)
	if len(in) == 0 {
		return pad
	}
	s := strings.ToLower(string(in))
	if v2 && strings.HasSuffix(s, "e") {
		s = s[:len(s)-1]
	}
	for _, r := range caverphoneRulesCommon {
		if strings.HasSuffix(r[0], "$") {
			suf := strings.TrimSuffix(r[0], "$")
			if strings.HasSuffix(s, suf) {
				s = s[:len(s)-len(suf)] + r[1]
			}
		} else {
			s = strings.ReplaceAll(s, r[0], r[1])
		}
	}
	if len(s) > 0 && (s[0] == 'a' || s[0] == 'e' || s[0] == 'i' || s[0] == 'o' || s[0] == 'u') {
		s = "A" + s[1:]
	}
	for _, v := range []string{"a", "e", "i", "o", "u"} {
		s = strings.ReplaceAll(s, v, "3")
	}
	if v2 {
		s = strings.ReplaceAll(s, "j", "y")
		if strings.HasPrefix(s, "y3") {
			s = "Y3" + s[2:]
		} else if strings.HasPrefix(s, "y") {
			s = "A" + s[1:]
		}
		s = strings.ReplaceAll(s, "y", "3")
	}
	s = strings.ReplaceAll(s, "3gh3", "3kh3")
	s = strings.ReplaceAll(s, "gh", "22")
	s = strings.ReplaceAll(s, "g", "k")
	for _, ch := range []byte{'s', 't', 'p', 'k', 'f', 'm', 'n'} {
		upper := string([]byte{ch - 'a' + 'A'})
		cur := string([]byte{ch})
		var collapsed strings.Builder
		for i := 0; i < len(s); {
			if s[i] == ch {
				for i < len(s) && s[i] == ch {
					i++
				}
				collapsed.WriteString(upper)
			} else {
				collapsed.WriteByte(s[i])
				i++
			}
		}
		_ = cur
		s = collapsed.String()
	}
	s = strings.ReplaceAll(s, "w3", "W3")
	s = strings.ReplaceAll(s, "wh3", "Wh3")
	if v2 && strings.HasSuffix(s, "w") {
		s = s[:len(s)-1] + "3"
	}
	s = strings.ReplaceAll(s, "w", "2")
	if strings.HasPrefix(s, "h") {
		s = "A" + s[1:]
	}
	s = strings.ReplaceAll(s, "h", "2")
	s = strings.ReplaceAll(s, "r3", "R3")
	if v2 && strings.HasSuffix(s, "r") {
		s = s[:len(s)-1] + "3"
	}
	s = strings.ReplaceAll(s, "r", "2")
	s = strings.ReplaceAll(s, "l3", "L3")
	if v2 && strings.HasSuffix(s, "l") {
		s = s[:len(s)-1] + "3"
	}
	s = strings.ReplaceAll(s, "l", "2")
	s = strings.ReplaceAll(s, "2", "")
	if v2 && strings.HasSuffix(s, "3") {
		s = s[:len(s)-1] + "A"
	}
	s = strings.ReplaceAll(s, "3", "")
	s += pad
	return s[:targetLen]
}

func encodeCaverphone1(txt string) string { return encodeCaverphone(txt, false) }
func encodeCaverphone2(txt string) string { return encodeCaverphone(txt, true) }

// encodeColognePhonetic implements German Kölner Phonetik.
func encodeColognePhonetic(txt string, vowelCode byte) string {
	var repl strings.Builder
	for _, r := range strings.ToUpper(txt) {
		switch r {
		case 'Ä':
			repl.WriteString("AE")
		case 'Ö':
			repl.WriteString("OE")
		case 'Ü':
			repl.WriteString("UE")
		case 'ß', 'ẞ':
			repl.WriteString("SS")
		default:
			if r >= 'A' && r <= 'Z' {
				repl.WriteRune(r)
			}
		}
	}
	s := removeAdjDuplicates(repl.String())
	if len(s) == 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		cur := s[i]
		var prev, next byte = '_', '_'
		if i > 0 {
			prev = s[i-1]
		}
		if i+1 < len(s) {
			next = s[i+1]
		}
		switch cur {
		case 'A', 'E', 'I', 'J', 'Y', 'O', 'U':
			if i == 0 || (i == 1 && prev == 'H') {
				sb.WriteByte(vowelCode)
			} else if vowelCode == '0' {
				sb.WriteByte('0')
			}
		case 'B':
			sb.WriteByte('1')
		case 'P':
			if next == 'H' {
				sb.WriteByte('3')
			} else {
				sb.WriteByte('1')
			}
		case 'D', 'T':
			if next == 'C' || next == 'S' || next == 'Z' {
				sb.WriteByte('8')
			} else {
				sb.WriteByte('2')
			}
		case 'F', 'V', 'W':
			sb.WriteByte('3')
		case 'G', 'K', 'Q':
			sb.WriteByte('4')
		case 'C':
			if i == 0 {
				if strings.IndexByte("AHKLOQRUX", next) >= 0 {
					sb.WriteByte('4')
				} else {
					sb.WriteByte('8')
				}
			} else if prev == 'S' || prev == 'Z' {
				sb.WriteByte('8')
			} else if strings.IndexByte("AOUHKXQ", next) >= 0 {
				sb.WriteByte('4')
			} else {
				sb.WriteByte('8')
			}
		case 'X':
			if prev == 'C' || prev == 'K' || prev == 'Q' {
				sb.WriteByte('8')
			} else {
				sb.WriteString("48")
			}
		case 'L':
			sb.WriteByte('5')
		case 'M', 'N':
			sb.WriteByte('6')
		case 'R':
			sb.WriteByte('7')
		case 'S', 'Z':
			sb.WriteByte('8')
		}
	}
	collapsed := removeAdjDuplicates(sb.String())
	if vowelCode != '0' || len(collapsed) <= 1 {
		return collapsed
	}
	// Standard Apache Commons Codec ColognePhonetic strips non-leading '0's.
	var final strings.Builder
	final.WriteByte(collapsed[0])
	for i := 1; i < len(collapsed); i++ {
		if collapsed[i] != '0' {
			final.WriteByte(collapsed[i])
		}
	}
	return final.String()
}

var (
	koelnerVarPats = []*regexp.Regexp{
		regexp.MustCompile("AUN"), regexp.MustCompile("OWN"),
		regexp.MustCompile("RB"), regexp.MustCompile("RW"),
		regexp.MustCompile("WSK"), regexp.MustCompile("RSK"),
	}
	koelnerVarRepls = []string{"OWN", "AUN", "RW", "RB", "RSK", "WSK"}

	haaseVarPats = []*regexp.Regexp{
		regexp.MustCompile("OWN"), regexp.MustCompile("RB"), regexp.MustCompile("WSK"),
		regexp.MustCompile("A$"), regexp.MustCompile("O$"), regexp.MustCompile("SCH"),
		regexp.MustCompile("GLI"), regexp.MustCompile("EAU$"), regexp.MustCompile("^CH"),
		regexp.MustCompile("AUX"), regexp.MustCompile("EUX"), regexp.MustCompile("ILLE"),
	}
	haaseVarRepls = []string{"AUN", "RW", "RSK", "AR", "OW", "CH", "LI", "O", "SCH", "O", "O", "I"}
)

func encodeKoelnerOrHaase(txt string, haase bool) string {
	var cleaned strings.Builder
	for _, r := range strings.ToUpper(txt) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cleaned.WriteRune(r)
		}
	}
	base := cleaned.String()
	if base == "" {
		return ""
	}
	pats := koelnerVarPats
	repls := koelnerVarRepls
	vCode := byte('0')
	if haase {
		pats = haaseVarPats
		repls = haaseVarRepls
		vCode = '9'
	}
	vars := []string{base}
	for idx, re := range pats {
		if len(vars) >= 8 {
			break
		}
		if loc := re.FindStringIndex(base); loc != nil {
			alt := base[:loc[0]] + repls[idx] + base[loc[1]:]
			if alt != base {
				vars = append(vars, alt)
			}
		}
	}
	codes := make([]string, 0, len(vars))
	seen := make(map[string]bool, len(vars))
	for _, v := range vars {
		c := encodeKoelnerSubstitute(v, vCode)
		if c != "" && !seen[c] {
			seen[c] = true
			codes = append(codes, c)
		}
	}
	return strings.Join(codes, "_")
}

func encodeKoelnerSubstitute(str string, vCode byte) string {
	s := strings.ToUpper(str)
	s = strings.ReplaceAll(s, "Ä", "AE")
	s = strings.ReplaceAll(s, "Ö", "OE")
	s = strings.ReplaceAll(s, "Ü", "UE")
	s = removeAdjDuplicates(s)
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		cur := s[i]
		var prev, next byte = '_', '_'
		if i > 0 {
			prev = s[i-1]
		}
		if i+1 < len(s) {
			next = s[i+1]
		}
		switch cur {
		case 'A', 'E', 'I', 'J', 'Y', 'O', 'U':
			if i == 0 || (i == 1 && prev == 'H') {
				sb.WriteByte(vCode)
			}
		case 'P':
			if next == 'H' {
				sb.WriteString("33")
			} else {
				sb.WriteByte('1')
			}
		case 'B':
			sb.WriteByte('1')
		case 'D', 'T':
			if next == 'C' || next == 'S' || next == 'Z' {
				sb.WriteByte('8')
			} else {
				sb.WriteByte('2')
			}
		case 'F', 'V', 'W':
			sb.WriteByte('3')
		case 'G', 'K', 'Q':
			sb.WriteByte('4')
		case 'C':
			if i == 0 {
				if strings.IndexByte("AHKLOQRUX", next) >= 0 {
					sb.WriteByte('4')
				} else {
					sb.WriteByte('8')
				}
			} else {
				if strings.IndexByte("AOUHKXQ", next) >= 0 {
					sb.WriteByte('4')
				} else {
					sb.WriteByte('8')
				}
			}
			if prev == 'S' || prev == 'Z' {
				outStr := sb.String()
				sb.Reset()
				sb.WriteString(outStr[:len(outStr)-1])
				sb.WriteByte('8')
			}
		case 'X':
			if i >= 1 && (prev == 'C' || prev == 'K' || prev == 'Q') {
				sb.WriteByte('8')
			} else {
				sb.WriteString("48")
			}
		case 'L':
			sb.WriteByte('5')
		case 'M', 'N':
			sb.WriteByte('6')
		case 'R':
			sb.WriteByte('7')
		case 'S', 'Z':
			sb.WriteByte('8')
		}
	}
	return removeAdjDuplicates(sb.String())
}

func removeAdjDuplicates(s string) string {
	if len(s) <= 1 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	sb.WriteByte(s[0])
	last := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != last {
			sb.WriteByte(s[i])
			last = s[i]
		}
	}
	return sb.String()
}

// encodeNYSIIS implements Apache Commons Codec NYSIIS (strict 6-char max).
func encodeNYSIIS(txt string) string {
	in := cleanASCIIUpperLetters(txt)
	if len(in) == 0 {
		return ""
	}
	s := string(in)
	prefixes := [][2]string{
		{"MAC", "MCC"}, {"KN", "NN"}, {"K", "C"}, {"PH", "FF"}, {"PF", "FF"}, {"SCH", "SSS"},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p[0]) {
			s = p[1] + s[len(p[0]):]
			break
		}
	}
	suffixes := [][2]string{
		{"EE", "Y"}, {"IE", "Y"}, {"DT", "D"}, {"RT", "D"}, {"RD", "D"}, {"NT", "D"}, {"ND", "D"},
	}
	for _, sf := range suffixes {
		if strings.HasSuffix(s, sf[0]) {
			s = s[:len(s)-len(sf[0])] + sf[1]
			break
		}
	}
	if len(s) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteByte(s[0])
	last := s[0]
	for i := 1; i < len(s); i++ {
		c := s[i]
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		prev := s[i-1]
		var mapped string
		switch c {
		case 'E':
			if next == 'V' {
				mapped = "AF"
				i++
			} else {
				mapped = "A"
			}
		case 'A', 'I', 'O', 'U':
			mapped = "A"
		case 'Q':
			mapped = "G"
		case 'Z':
			mapped = "S"
		case 'M':
			mapped = "N"
		case 'K':
			if next == 'N' {
				mapped = "N"
				i++
			} else {
				mapped = "C"
			}
		case 'S':
			if i+2 < len(s) && s[i+1] == 'C' && s[i+2] == 'H' {
				mapped = "SSS"
				i += 2
			} else {
				mapped = "S"
			}
		case 'P':
			if next == 'H' {
				mapped = "FF"
				i++
			} else {
				mapped = "P"
			}
		case 'H':
			if !isMetaphoneVowel(prev) || !isMetaphoneVowel(next) {
				mapped = string(prev)
			} else {
				mapped = "H"
			}
		case 'W':
			if isMetaphoneVowel(prev) {
				mapped = "A"
			} else {
				mapped = "W"
			}
		default:
			mapped = string(c)
		}
		for k := 0; k < len(mapped); k++ {
			if mapped[k] != last {
				out.WriteByte(mapped[k])
				last = mapped[k]
			}
		}
	}
	res := out.String()
	if len(res) > 1 && res[len(res)-1] == 'S' {
		res = res[:len(res)-1]
	}
	if len(res) > 2 && strings.HasSuffix(res, "AY") {
		res = res[:len(res)-2] + "Y"
	}
	if len(res) > 1 && res[len(res)-1] == 'A' {
		res = res[:len(res)-1]
	}
	if len(res) > 6 {
		res = res[:6]
	}
	return res
}

// encodeBeiderMorse implements Beider-Morse Phonetic Matching (exact & approx).
func encodeBeiderMorse(txt, nameType, ruleType string, langSet []string) []string {
	folded, _ := foldASCII(strings.ToLower(strings.TrimSpace(txt)))
	var clean strings.Builder
	for _, r := range folded {
		if r >= 'a' && r <= 'z' {
			clean.WriteRune(r)
		}
	}
	s := clean.String()
	if s == "" {
		return nil
	}

	isPolish := false
	isGerman := false
	for _, lg := range langSet {
		switch strings.ToLower(strings.TrimSpace(lg)) {
		case "polish":
			isPolish = true
		case "german":
			isGerman = true
		}
	}
	slavicOrAsh := isPolish || isGerman || nameType == "ashkenazi"

	var sb strings.Builder
	n := len(s)
	for i := 0; i < n; {
		rem := s[i:]
		switch {
		case strings.HasPrefix(rem, "szcz"):
			sb.WriteString("StS")
			i += 4
		case strings.HasPrefix(rem, "sch"):
			sb.WriteString("S")
			i += 3
		case strings.HasPrefix(rem, "sz") && slavicOrAsh:
			sb.WriteString("S")
			i += 2
		case strings.HasPrefix(rem, "cz") && slavicOrAsh:
			sb.WriteString("tS")
			i += 2
		case strings.HasPrefix(rem, "rz") && isPolish:
			sb.WriteString("Z")
			i += 2
		case strings.HasPrefix(rem, "dz") && slavicOrAsh:
			sb.WriteString("dz")
			i += 2
		case strings.HasPrefix(rem, "sh"):
			sb.WriteString("S")
			i += 2
		case strings.HasPrefix(rem, "ch"):
			if isGerman || nameType == "ashkenazi" {
				sb.WriteString("x")
			} else {
				sb.WriteString("tS")
			}
			i += 2
		case strings.HasPrefix(rem, "ph"):
			sb.WriteString("f")
			i += 2
		case strings.HasPrefix(rem, "th"):
			sb.WriteString("t")
			i += 2
		case strings.HasPrefix(rem, "ck"):
			sb.WriteString("k")
			i += 2
		case strings.HasPrefix(rem, "tz"):
			sb.WriteString("ts")
			i += 2
		default:
			c := s[i]
			switch c {
			case 'w':
				if slavicOrAsh {
					sb.WriteByte('v')
				} else {
					sb.WriteByte('v')
				}
			case 'c':
				if isPolish || (i+1 < n && (s[i+1] == 'e' || s[i+1] == 'i' || s[i+1] == 'y')) {
					sb.WriteString("ts")
				} else if isGerman && i+1 < n && (s[i+1] == 'e' || s[i+1] == 'i') {
					sb.WriteString("ts")
				} else {
					sb.WriteByte('k')
				}
			case 'q':
				sb.WriteByte('k')
			case 'x':
				sb.WriteString("ks")
			case 'y':
				sb.WriteByte('i')
			default:
				sb.WriteByte(c)
			}
			i++
		}
	}
	exactCode := sb.String()
	if ruleType == "exact" {
		return []string{exactCode}
	}
	// approx mode merges close vowels (e/i -> i, o/u -> u) as secondary variant when distinct
	approx := strings.NewReplacer("e", "i", "o", "u").Replace(exactCode)
	if approx != exactCode && approx != "" {
		return []string{exactCode, approx}
	}
	return []string{exactCode}
}

// Daitch-Mokotoff Soundex rule table (sorted longest pattern first per leading letter).
type dmRule struct {
	pat         string
	start       string
	beforeVowel string
	other       string
}

var dmRulesTable = []dmRule{
	{"schtch", "2", "4", "4"}, {"shch", "2", "4", "4"}, {"shtch", "2", "4", "4"},
	{"schtsch", "2", "4", "4"}, {"scht", "2", "43", "43"}, {"sht", "2", "43", "43"},
	{"stch", "2", "4", "4"}, {"strz", "2", "4", "4"}, {"strs", "2", "4", "4"},
	{"stsh", "2", "4", "4"}, {"szcz", "2", "4", "4"}, {"szcs", "2", "4", "4"},
	{"tsch", "4", "4", "4"}, {"ttsch", "4", "4", "4"},
	{"sch", "4", "4", "4"}, {"sh", "4", "4", "4"}, {"sz", "4", "4", "4"},
	{"st", "2", "43", "43"}, {"sc", "2", "4", "4"},
	{"ch", "5", "5", "5"}, {"ck", "5", "5", "5"}, {"cz", "4", "4", "4"}, {"cs", "4", "4", "4"}, {"csz", "4", "4", "4"},
	{"dzh", "4", "4", "4"}, {"dsh", "4", "4", "4"}, {"dz", "4", "4", "4"}, {"ds", "4", "4", "4"}, {"dt", "3", "3", "3"},
	{"kh", "5", "5", "5"}, {"ks", "5", "54", "54"},
	{"mn", "66", "66", "66"}, {"nm", "66", "66", "66"},
	{"ph", "7", "7", "7"}, {"pf", "7", "7", "7"}, {"fb", "7", "7", "7"},
	{"rz", "94", "94", "94"}, {"rs", "94", "94", "94"},
	{"tch", "4", "4", "4"}, {"th", "3", "3", "3"}, {"trz", "4", "4", "4"}, {"trs", "4", "4", "4"},
	{"ts", "4", "4", "4"}, {"tts", "4", "4", "4"}, {"tz", "4", "4", "4"}, {"ttz", "4", "4", "4"}, {"tc", "4", "4", "4"},
	{"zh", "4", "4", "4"}, {"zs", "4", "4", "4"},
	{"ai", "0", "1", ""}, {"aj", "0", "1", ""}, {"ay", "0", "1", ""},
	{"au", "0", "7", ""},
	{"ei", "0", "1", ""}, {"ej", "0", "1", ""}, {"ey", "0", "1", ""}, {"eu", "1", "1", ""},
	{"ia", "1", "", ""}, {"ie", "1", "", ""}, {"io", "1", "", ""}, {"iu", "1", "", ""},
	{"oi", "0", "1", ""}, {"oj", "0", "1", ""}, {"oy", "0", "1", ""},
	{"ui", "0", "1", ""}, {"uj", "0", "1", ""}, {"uy", "0", "1", ""},
	{"a", "0", "", ""}, {"b", "7", "7", "7"}, {"c", "5", "5", "5"}, {"d", "3", "3", "3"},
	{"e", "0", "", ""}, {"f", "7", "7", "7"}, {"g", "5", "5", "5"}, {"h", "5", "5", ""},
	{"i", "0", "", ""}, {"j", "1", "1", "1"}, {"k", "5", "5", "5"}, {"l", "8", "8", "8"},
	{"m", "6", "6", "6"}, {"n", "6", "6", "6"}, {"o", "0", "", ""}, {"p", "7", "7", "7"},
	{"q", "5", "5", "5"}, {"r", "9", "9", "9"}, {"s", "4", "4", "4"}, {"t", "3", "3", "3"},
	{"u", "0", "", ""}, {"v", "7", "7", "7"}, {"w", "7", "7", ""}, {"x", "5", "54", "54"},
	{"y", "1", "", ""}, {"z", "4", "4", "4"},
}

func isDMVowelByte(b byte) bool {
	return b == 'a' || b == 'e' || b == 'i' || b == 'o' || b == 'u' || b == 'y'
}

// encodeDaitchMokotoff implements Daitch-Mokotoff 6-digit Soundex.
func encodeDaitchMokotoff(txt string) []string {
	folded, _ := foldASCII(strings.ToLower(txt))
	var clean strings.Builder
	for i := 0; i < len(folded); i++ {
		c := folded[i]
		if c >= 'a' && c <= 'z' {
			clean.WriteByte(c)
		}
	}
	s := clean.String()
	if s == "" {
		return nil
	}
	var digits strings.Builder
	lastCode := ""
	for i := 0; i < len(s); {
		matched := false
		for _, r := range dmRulesTable {
			if strings.HasPrefix(s[i:], r.pat) {
				nextIdx := i + len(r.pat)
				var code string
				if i == 0 {
					code = r.start
				} else if nextIdx < len(s) && isDMVowelByte(s[nextIdx]) {
					code = r.beforeVowel
				} else {
					code = r.other
				}
				if code != "" && code != lastCode {
					digits.WriteString(code)
				}
				if code != "" {
					lastCode = code
				} else if isDMVowelByte(s[i]) {
					lastCode = ""
				}
				i = nextIdx
				matched = true
				break
			}
		}
		if !matched {
			i++
		}
	}
	res := digits.String() + "000000"
	return []string{res[:6]}
}
