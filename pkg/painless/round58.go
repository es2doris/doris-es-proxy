package painless

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Round 58 F20: Reference Identity (`===` / `!==`), Type-Safe `==` / `!=`,
// Optional Equality, and Elvis `?:`
// ============================================================================

//go:noinline
func newEmptyPainlessSlice() []any {
	return make([]any, 0, 1)
}

func isPrimitiveNumberRound58(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return true
	default:
		return false
	}
}

func isStrictNumericValueRound58(v any) bool {
	if isPrimitiveNumberRound58(v) {
		return true
	}
	switch v.(type) {
	case *painlessBigDecimal, *painlessBigInteger, *big.Int, *big.Float:
		return true
	default:
		return false
	}
}

func painlessRefEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if optA, okA := a.(*painlessOptional); okA {
		optB, okB := b.(*painlessOptional)
		if !okB {
			if optA != nil && !optA.present && b == painlessEmptyOptional {
				return optA.kind == "Optional"
			}
			return false
		}
		if optA == nil || optB == nil {
			return optA == optB
		}
		if !optA.present && !optB.present {
			return optA.kind == optB.kind
		}
		return optA == optB
	}
	if optB, okB := b.(*painlessOptional); okB {
		if optB != nil && !optB.present && a == painlessEmptyOptional {
			return optB.kind == "Optional"
		}
		return false
	}
	if a == painlessEmptyOptional || b == painlessEmptyOptional {
		return a == painlessEmptyOptional && b == painlessEmptyOptional
	}
	if sa, okA := a.([]any); okA {
		sb, okB := b.([]any)
		if !okB || len(sa) != len(sb) || cap(sa) != cap(sb) || cap(sa) == 0 {
			return false
		}
		return reflect.ValueOf(sa).Pointer() == reflect.ValueOf(sb).Pointer()
	}
	if _, okB := b.([]any); okB {
		return false
	}
	if ma, okA := a.(map[string]any); okA {
		mb, okB := b.(map[string]any)
		if !okB {
			return false
		}
		return reflect.ValueOf(ma).Pointer() == reflect.ValueOf(mb).Pointer()
	}
	if _, okB := b.(map[string]any); okB {
		return false
	}
	va := reflect.ValueOf(a)
	vb := reflect.ValueOf(b)
	if va.Kind() == reflect.Pointer || vb.Kind() == reflect.Pointer {
		return va.Kind() == reflect.Pointer && vb.Kind() == reflect.Pointer && va.Type() == vb.Type() && va.Pointer() == vb.Pointer()
	}
	if ba, okA := a.(bool); okA {
		bb, okB := b.(bool)
		return okB && ba == bb
	}
	if sa, okA := a.(string); okA {
		sb, okB := b.(string)
		return okB && sa == sb
	}
	if isPrimitiveNumberRound58(a) || isPrimitiveNumberRound58(b) {
		if !isPrimitiveNumberRound58(a) || !isPrimitiveNumberRound58(b) {
			return false
		}
		if isFloatingNaNPainless(a) || isFloatingNaNPainless(b) {
			return false
		}
		if ai, aInt := isIntegerValuePainless(a); aInt {
			if bi, bInt := isIntegerValuePainless(b); bInt {
				return ai == bi
			}
		}
		af, aOk := toFloat64WithRawPainless(a)
		bf, bOk := toFloat64WithRawPainless(b)
		return aOk && bOk && af == bf
	}
	return va.Type() == vb.Type() && reflect.DeepEqual(a, b)
}

func valuesEqualRound58(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if optA, okA := a.(*painlessOptional); okA {
		return optA.equals(b)
	}
	if optB, okB := b.(*painlessOptional); okB {
		return optB.equals(a)
	}
	if a == painlessEmptyOptional || b == painlessEmptyOptional {
		return a == painlessEmptyOptional && b == painlessEmptyOptional
	}
	if sa, okA := a.([]any); okA {
		sb, okB := b.([]any)
		if !okB || len(sa) != len(sb) {
			return false
		}
		for i := range sa {
			if !valuesEqualRound58(sa[i], sb[i]) {
				return false
			}
		}
		return true
	}
	if _, okB := b.([]any); okB {
		return false
	}
	if ma, okA := a.(map[string]any); okA {
		mb, okB := b.(map[string]any)
		if !okB || visiblePainlessMapLen(ma) != visiblePainlessMapLen(mb) {
			return false
		}
		for k, va := range ma {
			if isInternalPainlessMapKey(ma, k) {
				continue
			}
			vb, exists := mb[k]
			if !exists || !valuesEqualRound58(va, vb) {
				return false
			}
		}
		return true
	}
	if _, okB := b.(map[string]any); okB {
		return false
	}
	if otA, okA := a.(*painlessOffsetTime); okA {
		return otA.equals(b)
	}
	if _, okB := b.(*painlessOffsetTime); okB {
		return false
	}
	if clkA, okA := a.(*painlessClock); okA {
		return clkA.equals(b)
	}
	if _, okB := b.(*painlessClock); okB {
		return false
	}
	if uriA, okA := a.(*painlessURI); okA {
		return uriA.equals(b)
	}
	if _, okB := b.(*painlessURI); okB {
		return false
	}
	if urlA, okA := a.(*painlessURL); okA {
		return urlA.equals(b)
	}
	if _, okB := b.(*painlessURL); okB {
		return false
	}
	if vrA, okA := a.(*painlessValueRange); okA {
		vrB, okB := b.(*painlessValueRange)
		return okB && vrA != nil && vrB != nil && *vrA == *vrB
	}
	if _, okB := b.(*painlessValueRange); okB {
		return false
	}
	if bsA, okA := a.(*painlessBitSet); okA {
		bsB, okB := b.(*painlessBitSet)
		return okB && bsA.equals(bsB)
	}
	if _, okB := b.(*painlessBitSet); okB {
		return false
	}
	if uoA, okA := a.(*painlessUserObject); okA {
		if uoA != nil && uoA.class != nil && uoA.class.findMethod("equals") != nil {
			res, err := evalUserClassMethodWithArgsPainless(uoA, uoA.class, "equals", []any{b}, false, nil, nil, 0)
			if err == nil {
				if bv, isB := res.(bool); isB {
					return bv
				}
			}
		}
		return painlessRefEqual(a, b)
	}
	if _, okB := b.(*painlessUserObject); okB {
		return false
	}
	if isStrictNumericValueRound58(a) || isStrictNumericValueRound58(b) {
		if !isStrictNumericValueRound58(a) || !isStrictNumericValueRound58(b) {
			return false
		}
		if isFloatingNaNPainless(a) || isFloatingNaNPainless(b) {
			return false
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
		if ai, aInt := isIntegerValuePainless(a); aInt {
			if bi, bInt := isIntegerValuePainless(b); bInt {
				return ai == bi
			}
		}
		af, aOk := toFloat64WithRawPainless(a)
		bf, bOk := toFloat64WithRawPainless(b)
		return aOk && bOk && af == bf
	}
	if sa, okA := a.(string); okA {
		sb, okB := b.(string)
		return okB && sa == sb
	}
	if ba, okA := a.(bool); okA {
		bb, okB := b.(bool)
		return okB && ba == bb
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	if reflect.ValueOf(a).Kind() == reflect.Pointer {
		return painlessRefEqual(a, b)
	}
	return reflect.DeepEqual(a, b)
}

// ============================================================================
// Round 58 F21: IEEE-754 Float Arithmetic & Math.* Double Return Types
// ============================================================================

func toIEEEFloat64OperandRound58(v any) (float64, bool) {
	if v == nil {
		return 0, true
	}
	if !isStrictNumericValueRound58(v) {
		return 0, false
	}
	if fv, ok := toFloat64WithRawPainless(v); ok {
		return fv, true
	}
	return toFloat64(v)
}

func promoteFloatingResultRound58(a, b any, res float64) any {
	_, aF32 := a.(float32)
	_, bF32 := b.(float32)
	if aF32 && bF32 {
		return float32(res)
	}
	return res
}

func applyMulDivRound58(a, b any, op byte) any {
	ai, aIsInt := isIntegerValuePainless(a)
	bi, bIsInt := isIntegerValuePainless(b)
	if aIsInt && bIsInt {
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
	af, aOk := toIEEEFloat64OperandRound58(a)
	bf, bOk := toIEEEFloat64OperandRound58(b)
	if aOk && bOk {
		var res float64
		switch op {
		case '*':
			res = af * bf
		case '/':
			if bf == 0 {
				if af == 0 || math.IsNaN(af) {
					res = math.NaN()
				} else {
					sign := math.Copysign(1, af) * math.Copysign(1, bf)
					res = math.Copysign(math.Inf(1), sign)
				}
			} else {
				res = af / bf
			}
		case '%':
			if bf == 0 || math.IsInf(af, 0) || math.IsNaN(af) || math.IsNaN(bf) {
				res = math.NaN()
			} else {
				res = math.Mod(af, bf)
			}
		}
		return promoteFloatingResultRound58(a, b, res)
	}
	return float64(0)
}

func applyNumericAddSubRound58(a, b any, isAdd bool) (any, bool) {
	ai, aIsInt := isIntegerValuePainless(a)
	bi, bIsInt := isIntegerValuePainless(b)
	if aIsInt && bIsInt {
		if isAdd {
			return ai + bi, true
		}
		return ai - bi, true
	}
	af, aOk := toIEEEFloat64OperandRound58(a)
	bf, bOk := toIEEEFloat64OperandRound58(b)
	if aOk && bOk {
		res := af + bf
		if !isAdd {
			res = af - bf
		}
		return promoteFloatingResultRound58(a, b, res), true
	}
	return nil, false
}

func evalMathStaticCallRound58(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	switch fnName {
	case "Math.floorDiv", "Math.floorMod", "Math.addExact", "Math.subtractExact", "Math.multiplyExact",
		"Math.incrementExact", "Math.decrementExact", "Math.negateExact", "Math.toIntExact":
		return evalMathExactOrFloorRound57Painless(fnName, args, sourceMap, params, depth)
	}
	if !strings.HasPrefix(fnName, "Math.") {
		return nil, false, nil
	}

	evalRawArg := func(idx int) (any, float64, bool, error) {
		if idx >= len(args) {
			return nil, 0, false, nil
		}
		v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
		if err != nil {
			return nil, 0, false, err
		}
		if v == nil {
			return nil, 0, false, &painlessExceptionError{exType: "NullPointerException", message: "null numeric argument"}
		}
		if fv, ok := toFloat64WithRawPainless(v); ok {
			return v, fv, true, nil
		}
		if fv, ok := toFloat64(v); ok {
			return v, fv, true, nil
		}
		return v, 0, false, nil
	}

	switch fnName {
	case "Math.abs":
		v0, f, ok, err := evalRawArg(0)
		if err != nil {
			return nil, true, err
		}
		if !ok {
			return int64(0), true, nil
		}
		if iv, isInt := isIntegerValuePainless(v0); isInt {
			if iv < 0 {
				return -iv, true, nil
			}
			return iv, true, nil
		}
		res := math.Abs(f)
		if _, isF32 := v0.(float32); isF32 {
			return float32(res), true, nil
		}
		return res, true, nil
	case "Math.min", "Math.max":
		v1, f1, ok1, err1 := evalRawArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		v2, f2, ok2, err2 := evalRawArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		if !ok1 || !ok2 {
			return int64(0), true, nil
		}
		i1, int1 := isIntegerValuePainless(v1)
		i2, int2 := isIntegerValuePainless(v2)
		if int1 && int2 {
			if fnName == "Math.min" {
				if i1 < i2 {
					return i1, true, nil
				}
				return i2, true, nil
			}
			if i1 > i2 {
				return i1, true, nil
			}
			return i2, true, nil
		}
		var res float64
		if fnName == "Math.min" {
			res = javaFloatingMinPainless(f1, f2)
		} else {
			res = javaFloatingMaxPainless(f1, f2)
		}
		return promoteFloatingResultRound58(v1, v2, res), true, nil
	case "Math.clamp":
		vVal, vf, ok1, err1 := evalRawArg(0)
		if err1 != nil {
			return nil, true, err1
		}
		loVal, lof, ok2, err2 := evalRawArg(1)
		if err2 != nil {
			return nil, true, err2
		}
		hiVal, hif, ok3, err3 := evalRawArg(2)
		if err3 != nil {
			return nil, true, err3
		}
		if !ok1 || !ok2 || !ok3 {
			return int64(0), true, nil
		}
		iv, intV := isIntegerValuePainless(vVal)
		ilo, intLo := isIntegerValuePainless(loVal)
		ihi, intHi := isIntegerValuePainless(hiVal)
		if intV && intLo && intHi {
			if ilo > ihi {
				return nil, true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("%d > %d", ilo, ihi),
				}
			}
			if iv < ilo {
				return ilo, true, nil
			}
			if iv > ihi {
				return ihi, true, nil
			}
			return iv, true, nil
		}
		if math.IsNaN(lof) || math.IsNaN(hif) || lof > hif || (lof == 0 && hif == 0 && !math.Signbit(lof) && math.Signbit(hif)) {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("%v > %v", lof, hif),
			}
		}
		return javaFloatingMinPainless(hif, javaFloatingMaxPainless(vf, lof)), true, nil
	case "Math.round":
		v0, f, ok, err := evalRawArg(0)
		if err != nil {
			return nil, true, err
		}
		if !ok || math.IsNaN(f) {
			return int64(0), true, nil
		}
		if _, isF32 := v0.(float32); isF32 {
			if math.IsInf(f, 1) || f >= float64(math.MaxInt32) {
				return int64(math.MaxInt32), true, nil
			}
			if math.IsInf(f, -1) || f <= float64(math.MinInt32) {
				return int64(math.MinInt32), true, nil
			}
			return int64(math.Floor(f + 0.5)), true, nil
		}
		if math.IsInf(f, 1) || f >= float64(math.MaxInt64) {
			return int64(math.MaxInt64), true, nil
		}
		if math.IsInf(f, -1) || f <= float64(math.MinInt64) {
			return int64(math.MinInt64), true, nil
		}
		return int64(math.Floor(f + 0.5)), true, nil
	case "Math.floor", "Math.ceil", "Math.rint", "Math.sqrt",
		"Math.log", "Math.log10", "Math.log1p", "Math.exp", "Math.expm1",
		"Math.signum", "Math.sin", "Math.cos", "Math.tan",
		"Math.asin", "Math.acos", "Math.atan",
		"Math.sinh", "Math.cosh", "Math.tanh", "Math.cbrt",
		"Math.toRadians", "Math.toDegrees",
		"Math.ulp", "Math.nextUp", "Math.nextDown":
		_, f, ok, err := evalRawArg(0)
		if err != nil || !ok {
			return float64(0), true, err
		}
		return applyUnaryMathDoubleRound58(fnName, f), true, nil
	case "Math.pow", "Math.hypot", "Math.atan2", "Math.nextAfter",
		"Math.IEEEremainder", "Math.copySign", "Math.scalb":
		_, f1, ok1, err1 := evalRawArg(0)
		if err1 != nil {
			return float64(0), true, err1
		}
		_, f2, ok2, err2 := evalRawArg(1)
		if err2 != nil || !ok1 || !ok2 {
			return float64(0), true, err2
		}
		return applyBinaryMathDoubleRound58(fnName, f1, f2), true, nil
	case "Math.fma":
		v1, f1, ok1, err1 := evalRawArg(0)
		if err1 != nil {
			return float64(0), true, err1
		}
		v2, f2, ok2, err2 := evalRawArg(1)
		if err2 != nil {
			return float64(0), true, err2
		}
		v3, f3, ok3, err3 := evalRawArg(2)
		if err3 != nil || !ok1 || !ok2 || !ok3 {
			return float64(0), true, err3
		}
		res := math.FMA(f1, f2, f3)
		_, isF1 := v1.(float32)
		_, isF2 := v2.(float32)
		_, isF3 := v3.(float32)
		if isF1 && isF2 && isF3 {
			return float32(res), true, nil
		}
		return res, true, nil
	case "Math.getExponent":
		v0, f, ok, err := evalRawArg(0)
		if err != nil || !ok {
			return int64(0), true, err
		}
		if f == 0 {
			return int64(-1023), true, nil
		}
		if isNonFiniteFloatingPainless(v0) || math.IsNaN(f) || math.IsInf(f, 0) {
			return int64(1024), true, nil
		}
		_, exp := math.Frexp(math.Abs(f))
		return int64(exp - 1), true, nil
	default:
		return nil, false, nil
	}
}

func applyUnaryMathDoubleRound58(fnName string, f float64) float64 {
	switch fnName {
	case "Math.floor":
		return math.Floor(f)
	case "Math.ceil":
		return math.Ceil(f)
	case "Math.rint":
		return math.RoundToEven(f)
	case "Math.sqrt":
		return math.Sqrt(f)
	case "Math.log":
		return math.Log(f)
	case "Math.log10":
		return math.Log10(f)
	case "Math.log1p":
		return math.Log1p(f)
	case "Math.exp":
		return math.Exp(f)
	case "Math.expm1":
		return math.Expm1(f)
	case "Math.signum":
		if math.IsNaN(f) || f == 0 {
			return f
		}
		if f > 0 {
			return 1
		}
		return -1
	case "Math.sin":
		return math.Sin(f)
	case "Math.cos":
		return math.Cos(f)
	case "Math.tan":
		return math.Tan(f)
	case "Math.asin":
		return math.Asin(f)
	case "Math.acos":
		return math.Acos(f)
	case "Math.atan":
		return math.Atan(f)
	case "Math.sinh":
		return math.Sinh(f)
	case "Math.cosh":
		return math.Cosh(f)
	case "Math.tanh":
		return math.Tanh(f)
	case "Math.cbrt":
		return math.Cbrt(f)
	case "Math.toRadians":
		return f * math.Pi / 180.0
	case "Math.toDegrees":
		return f * 180.0 / math.Pi
	case "Math.ulp":
		if math.IsNaN(f) {
			return math.NaN()
		}
		if math.IsInf(f, 0) {
			return math.Inf(1)
		}
		if f == math.MaxFloat64 || f == -math.MaxFloat64 {
			return math.Pow(2, 971)
		}
		return math.Abs(math.Nextafter(f, math.Inf(1)) - f)
	case "Math.nextUp":
		return math.Nextafter(f, math.Inf(1))
	default: // Math.nextDown
		return math.Nextafter(f, math.Inf(-1))
	}
}

func applyBinaryMathDoubleRound58(fnName string, f1, f2 float64) float64 {
	switch fnName {
	case "Math.pow":
		return math.Pow(f1, f2)
	case "Math.hypot":
		return math.Hypot(f1, f2)
	case "Math.atan2":
		return math.Atan2(f1, f2)
	case "Math.nextAfter":
		return math.Nextafter(f1, f2)
	case "Math.IEEEremainder":
		return math.Remainder(f1, f2)
	case "Math.copySign":
		return math.Copysign(f1, f2)
	default: // Math.scalb
		return math.Ldexp(f1, int(f2))
	}
}

// ============================================================================
// Round 58 F22: Boolean, Relational & Conditional Exception Propagation
// ============================================================================

func evalConditionErr(sourceMap map[string]any, cond string, params map[string]any) (res bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			if pEx, ok := r.(*painlessExceptionError); ok {
				res = false
				err = pEx
			} else {
				panic(r)
			}
		}
	}()
	return evalConditionDepthErr(sourceMap, cond, params, 0)
}

func evalConditionDepthErr(sourceMap map[string]any, cond string, params map[string]any, depth int) (bool, error) {
	if depth > 64 {
		return false, fmt.Errorf("painless condition exceeded maximum recursion depth (64)")
	}
	cond = trimBalancedParens(cond)
	if cond == "" || cond == "false" {
		return false, nil
	}
	if cond == "true" {
		return true, nil
	}
	if aLHS, aOp, aRHS, aOk := findFirstTopLevelAssignOpRound59(cond); aOk {
		val, err := evalAssignExprRound59Painless(sourceMap, aLHS, aOp, aRHS, params, depth+1)
		if err != nil {
			return false, err
		}
		if b, ok := val.(bool); ok {
			return b, nil
		}
		if val == nil {
			return false, nil
		}
		if f, ok := toFloat64WithRawPainless(val); ok {
			return f != 0 && !math.IsNaN(f), nil
		}
		if f, ok := toFloat64(val); ok {
			return f != 0, nil
		}
		return true, nil
	}
	elvisIdx := findTopLevelOpPainless(cond, "?:")
	qIdx := findTopLevelOpPainless(cond, "?")
	if qIdx > 0 && (elvisIdx < 0 || qIdx < elvisIdx) {
		rest := cond[qIdx+1:]
		if cIdx := findMatchingTernaryColonPainless(rest); cIdx >= 0 {
			cb, err := evalConditionDepthErr(sourceMap, strings.TrimSpace(cond[:qIdx]), params, depth+1)
			if err != nil {
				return false, err
			}
			if cb {
				return evalConditionDepthErr(sourceMap, strings.TrimSpace(rest[:cIdx]), params, depth+1)
			}
			return evalConditionDepthErr(sourceMap, strings.TrimSpace(rest[cIdx+1:]), params, depth+1)
		}
	}
	if elvisIdx > 0 {
		leftVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:elvisIdx]), params, depth+1)
		if err != nil {
			return false, err
		}
		if leftVal != nil {
			if b, ok := leftVal.(bool); ok {
				return b, nil
			}
			if f, ok := toFloat64WithRawPainless(leftVal); ok {
				return f != 0 && !math.IsNaN(f), nil
			}
			return true, nil
		}
		return evalConditionDepthErr(sourceMap, strings.TrimSpace(cond[elvisIdx+2:]), params, depth+1)
	}
	if parts := splitTopLevelCondOp(cond, "||"); len(parts) > 1 {
		for _, p := range parts {
			ok, err := evalConditionDepthErr(sourceMap, p, params, depth+1)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if parts := splitTopLevelCondOp(cond, "&&"); len(parts) > 1 {
		for _, p := range parts {
			ok, err := evalConditionDepthErr(sourceMap, p, params, depth+1)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	}
	for _, bwOp := range []string{"|", "^", "&"} {
		if idx, _ := findLastTopLevelOpPainless(cond, bwOp); idx > 0 {
			leftExpr := strings.TrimSpace(cond[:idx])
			rightExpr := strings.TrimSpace(cond[idx+1:])
			if hasTopLevelBooleanOrRegexOp(trimBalancedParens(leftExpr)) || hasTopLevelBooleanOrRegexOp(trimBalancedParens(rightExpr)) {
				lb, errL := evalConditionDepthErr(sourceMap, leftExpr, params, depth+1)
				if errL != nil {
					return false, errL
				}
				rb, errR := evalConditionDepthErr(sourceMap, rightExpr, params, depth+1)
				if errR != nil {
					return false, errR
				}
				switch bwOp {
				case "|":
					return lb || rb, nil
				case "^":
					return lb != rb, nil
				case "&":
					return lb && rb, nil
				}
			}
		}
	}
	if idx, eqOp := findLastTopLevelAnyOpPainless(cond, []string{"!==", "===", "!=", "=="}); idx > 0 {
		lhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		if err != nil {
			return false, err
		}
		rhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+len(eqOp):]), params, depth+1)
		if err != nil {
			return false, err
		}
		switch eqOp {
		case "!==":
			return !painlessRefEqual(lhs, rhs), nil
		case "===":
			return painlessRefEqual(lhs, rhs), nil
		case "!=":
			return !valuesEqual(lhs, rhs), nil
		default: // "=="
			return valuesEqual(lhs, rhs), nil
		}
	}
	if idx := findTopLevelOpPainless(cond, "==~"); idx > 0 {
		lhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		if err != nil {
			return false, err
		}
		rhsRaw := strings.TrimSpace(cond[idx+3:])
		rhs, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return false, err
		}
		return evalRegexMatchPainlessErr(lhs, rhs, isRawRegexLiteralPainless(rhsRaw), true)
	}
	if idx := findTopLevelOpPainless(cond, "=~"); idx > 0 {
		lhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		if err != nil {
			return false, err
		}
		rhsRaw := strings.TrimSpace(cond[idx+2:])
		rhs, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return false, err
		}
		return evalRegexMatchPainlessErr(lhs, rhs, isRawRegexLiteralPainless(rhsRaw), false)
	}
	if idx := findTopLevelOpPainless(cond, "!~"); idx > 0 {
		lhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		if err != nil {
			return false, err
		}
		rhsRaw := strings.TrimSpace(cond[idx+2:])
		rhs, err := evalRHSExprDepth(sourceMap, rhsRaw, params, depth+1)
		if err != nil {
			return false, err
		}
		matched, err := evalRegexMatchPainlessErr(lhs, rhs, isRawRegexLiteralPainless(rhsRaw), false)
		return !matched, err
	}
	if idx, op := findLastTopLevelAnyOpPainless(cond, []string{">=", "<=", ">", "<"}); idx > 0 {
		lhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		if err != nil {
			return false, err
		}
		rhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[idx+len(op):]), params, depth+1)
		if err != nil {
			return false, err
		}
		if lhs == nil || rhs == nil {
			return false, &painlessExceptionError{
				exType:  "NullPointerException",
				message: fmt.Sprintf("Cannot apply relational operator %s to null operand", op),
			}
		}
		return compareOrderedValues(lhs, rhs, op), nil
	}
	if strings.HasPrefix(cond, "!") && !strings.HasPrefix(cond, "!=") {
		ok, err := evalConditionDepthErr(sourceMap, cond[1:], params, depth+1)
		if err != nil {
			return false, err
		}
		return !ok, nil
	}
	if idx := findTopLevelOpPainless(cond, " instanceof "); idx > 0 {
		lhs, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(cond[:idx]), params, depth+1)
		if err != nil {
			return false, err
		}
		typeName := strings.TrimSpace(cond[idx+len(" instanceof "):])
		return evalInstanceOfPainless(lhs, typeName), nil
	}

	val, err := evalRHSExprDepth(sourceMap, cond, params, depth+1)
	if err != nil {
		return false, err
	}
	if b, ok := val.(bool); ok {
		return b, nil
	}
	if val == nil {
		return false, nil
	}
	if f, ok := toFloat64WithRawPainless(val); ok {
		return f != 0 && !math.IsNaN(f), nil
	}
	if f, ok := toFloat64(val); ok {
		return f != 0, nil
	}
	return true, nil
}

// ============================================================================
// Round 58 F23: Null-Safe Navigation `?.` Short-Circuiting & Null Receiver NPE
// ============================================================================

func matchTrailingMethodCallWithNullSafePainless(s, mName string) (recExpr, argExpr string, isNullSafe, ok bool) {
	if !strings.HasSuffix(s, ")") || len(s) <= len(mName) {
		return "", "", false, false
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
		return "", "", false, false
	}
	prefix := s[:openParenIdx+1]
	if !strings.HasSuffix(prefix, mName) {
		return "", "", false, false
	}
	idx := len(prefix) - len(mName)
	if idx <= 0 {
		return "", "", false, false
	}
	rawRec := strings.TrimSpace(s[:idx])
	isNullSafe = strings.HasSuffix(rawRec, "?")
	recExpr = strings.TrimSpace(strings.TrimSuffix(rawRec, "?"))
	argExpr = strings.TrimSpace(s[openParenIdx+1 : len(s)-1])
	return recExpr, argExpr, isNullSafe, recExpr != ""
}

var knownStaticClassIdentifiersRound58 = map[string]bool{
	"Math": true, "StrictMath": true,
	"Integer": true, "Long": true, "Short": true, "Byte": true,
	"Double": true, "Float": true, "Boolean": true, "Character": true,
	"String": true, "Objects": true, "Arrays": true, "Collections": true,
	"List": true, "Map": true, "Set": true, "EnumSet": true,
	"Optional": true, "OptionalInt": true, "OptionalLong": true, "OptionalDouble": true,
	"Stream": true, "IntStream": true, "LongStream": true, "DoubleStream": true,
	"Collectors": true, "Comparator": true, "Predicate": true,
	"Pattern": true, "Matcher": true, "Base64": true, "UUID": true, "HexFormat": true,
	"Instant": true, "LocalDate": true, "LocalTime": true, "LocalDateTime": true,
	"ZonedDateTime": true, "OffsetDateTime": true, "OffsetTime": true,
	"ZoneId": true, "ZoneOffset": true, "Clock": true, "Duration": true, "Period": true,
	"Year": true, "YearMonth": true, "MonthDay": true, "DayOfWeek": true, "Month": true,
	"ChronoUnit": true, "ChronoField": true, "ValueRange": true, "TemporalAdjusters": true,
	"DateTimeFormatter": true,
	"BigDecimal":        true, "BigInteger": true, "MathContext": true, "RoundingMode": true,
	"BitSet": true, "URI": true, "URL": true, "URLEncoder": true, "URLDecoder": true,
	"Charset": true, "StandardCharsets": true, "System": true, "Digest": true,
	"Encoding": true, "Hex": true,
}

func isKnownStaticClassIdentifierRound58(recExpr string, params map[string]any) bool {
	s := strings.TrimSpace(recExpr)
	if s == "" || strings.ContainsAny(s, "()[]\"' ") {
		return false
	}
	if params != nil {
		if _, exists := params[s]; exists {
			return false
		}
	}
	for _, pfx := range []string{
		"java.time.format.", "java.time.temporal.", "java.time.",
		"java.math.", "java.lang.", "java.util.stream.",
		"java.util.regex.", "java.util.function.", "java.util.",
		"java.net.", "java.nio.charset.",
	} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimPrefix(s, pfx)
			break
		}
	}
	return knownStaticClassIdentifiersRound58[s]
}

func evalInstanceReceiverOnceRound58(recExpr, mName, mBare, argExpr string, isNullSafe bool, sourceMap, params map[string]any, depth int) (recVal any, writeBack func(any), shortCircuit bool, err error) {
	cleanRec := strings.TrimSpace(strings.TrimSuffix(recExpr, "?"))
	if cleanRec == "doc" || strings.HasPrefix(cleanRec, "doc.") || strings.HasPrefix(cleanRec, "doc?.") || strings.HasPrefix(cleanRec, "doc[") {
		if mBare == "containsKey" && cleanRec == "doc" {
			return sourceMap, nil, false, nil
		}
		expDocRec := cleanRec
		if strings.HasPrefix(cleanRec, "doc[") {
			expDocRec = strings.TrimSpace(expandDynamicBrackets(cleanRec, sourceMap, params, depth+1))
		}
		if (mBare == "forEach" || mBare == "containsAll" || mBare == "contains" || mBare == "indexOf" || mBare == "lastIndexOf" || mBare == "get" || mBare == "subList" || mBare == "join" || mBare == "length" || mBare == "size" || mBare == "isEmpty") &&
			(strings.HasPrefix(expDocRec, "doc.") || strings.HasPrefix(expDocRec, "doc?.")) &&
			!strings.HasSuffix(expDocRec, ".value") && !strings.Contains(expDocRec, ".value.") && !strings.Contains(expDocRec, ".values.") && !strings.Contains(expDocRec, "(") {
			docPath := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(expDocRec, "doc?."), "doc."), ".values")
			return resolveDocValuesSlice(sourceMap, docPath), nil, false, nil
		}
	}
	if (cleanRec == "ctx" || cleanRec == "ctx._source" || cleanRec == "ctx?._source") && (params == nil || params["ctx"] == nil) {
		return sourceMap, nil, false, nil
	}
	if cleanRec == "params" && params != nil {
		if _, hasExplicitParamsVar := params["params"]; !hasExplicitParamsVar {
			return params, nil, false, nil
		}
	}
	needsWriteBack := strings.Contains(cleanRec, "(") &&
		(mName == ".removeIf(" || mName == ".removeAll(" || mName == ".retainAll(" || mName == ".remove(" || mName == ".set(" || mName == ".addAll(" || mName == ".add(")
	if needsWriteBack {
		recVal, writeBack, err = resolveMutableReceiverPainless(sourceMap, cleanRec, params, depth+1)
	} else {
		recVal, err = evalRHSExprDepth(sourceMap, cleanRec, params, depth+1)
	}
	if err != nil {
		return nil, nil, true, err
	}
	if recVal == nil {
		if isNullSafe {
			return nil, nil, true, nil
		}
		return nil, nil, true, &painlessExceptionError{
			exType:  "NullPointerException",
			message: fmt.Sprintf("Cannot invoke method %s() on null object", mBare),
		}
	}
	if uo, isUO := recVal.(*painlessUserObject); isUO && uo != nil && uo.class != nil && len(uo.class.findMethod(mBare)) > 0 {
		uRes, uErr := evalUserObjectMethodPainless(uo, mBare, argExpr, sourceMap, params, depth+1)
		return uRes, nil, true, uErr
	}
	return recVal, writeBack, false, nil
}

// ============================================================================
// Round 58 F24: Regex Literals With Flags `/pattern/imsUuxdc`, Null NPE,
// and `PatternSyntaxException`
// ============================================================================

func isIdentFlagTailRound58(tail string) bool {
	for i := 0; i < len(tail); i++ {
		if !isIdentByte(tail[i]) {
			return false
		}
	}
	return true
}

func stripRegexCommentsModeRound58(pat string) string {
	var b strings.Builder
	inClass := false
	for i := 0; i < len(pat); i++ {
		ch := pat[i]
		if ch == '\\' && i+1 < len(pat) {
			b.WriteByte(ch)
			b.WriteByte(pat[i+1])
			i++
			continue
		}
		if ch == '[' && !inClass {
			inClass = true
			b.WriteByte(ch)
			continue
		}
		if ch == ']' && inClass {
			inClass = false
			b.WriteByte(ch)
			continue
		}
		if !inClass {
			if ch == '#' {
				for i < len(pat) && pat[i] != '\n' && pat[i] != '\r' {
					i++
				}
				continue
			}
			if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' {
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func compileJavaPatternWithFlagsRound58(rawBody string, flags int, literalRepr string) (*painlessPattern, error) {
	patStr := rawBody
	if flags&16 != 0 { // Pattern.LITERAL
		patStr = regexp.QuoteMeta(patStr)
	} else {
		if flags&4 != 0 { // Pattern.COMMENTS ('x')
			patStr = stripRegexCommentsModeRound58(patStr)
		}
		patStr = normalizeJavaNamedGroupsPainless(patStr)
	}
	var reFlags strings.Builder
	if flags&2 != 0 { // CASE_INSENSITIVE ('i')
		reFlags.WriteByte('i')
	}
	if flags&8 != 0 { // MULTILINE ('m')
		reFlags.WriteByte('m')
	}
	if flags&32 != 0 { // DOTALL ('s')
		reFlags.WriteByte('s')
	}
	if reFlags.Len() > 0 {
		patStr = "(?" + reFlags.String() + ")" + patStr
	}
	re, err := compilePainlessRegexp(patStr)
	if err != nil {
		return nil, &painlessExceptionError{
			exType:  "PatternSyntaxException",
			message: err.Error(),
		}
	}
	if literalRepr == "" {
		literalRepr = "/" + strings.ReplaceAll(rawBody, "/", `\/`) + "/"
	}
	return &painlessPattern{
		raw:     rawBody,
		flags:   flags,
		re:      re,
		literal: literalRepr,
	}, nil
}

func parseRegexLiteralWithFlagsRound58(expr string) (*painlessPattern, bool, error) {
	s := trimBalancedParens(strings.TrimSpace(expr))
	if len(s) < 3 || s[0] != '/' || s[1] == '/' || s[1] == '*' {
		return nil, false, nil
	}
	closeSlash := findMatchingRegexSlash(s, 0)
	if closeSlash <= 1 && !strings.ContainsAny(s, "\r\n") {
		if lastSlash := strings.LastIndexByte(s, '/'); lastSlash > 1 && !isEscapedAt(s, lastSlash) {
			if tailCand := s[lastSlash+1:]; tailCand == "" || isIdentFlagTailRound58(tailCand) {
				closeSlash = lastSlash
			}
		}
	}
	if closeSlash <= 1 {
		return nil, false, nil
	}
	tail := s[closeSlash+1:]
	if tail != "" && !isIdentFlagTailRound58(tail) {
		return nil, false, nil
	}
	flags := 0
	for i := 0; i < len(tail); i++ {
		switch tail[i] {
		case 'd':
			flags |= 1 // UNIX_LINES
		case 'i':
			flags |= 2 // CASE_INSENSITIVE
		case 'x':
			flags |= 4 // COMMENTS
		case 'm':
			flags |= 8 // MULTILINE
		case 's':
			flags |= 32 // DOTALL
		case 'u':
			flags |= 64 // UNICODE_CASE
		case 'c':
			flags |= 128 // CANON_EQ
		case 'U':
			flags |= 256 | 64 // UNICODE_CHARACTER_CLASS | UNICODE_CASE
		default:
			return nil, true, &painlessExceptionError{
				exType:  "PatternSyntaxException",
				message: fmt.Sprintf("Unknown inline regex flag '%c' in %s", tail[i], s),
			}
		}
	}
	rawBody := strings.ReplaceAll(s[1:closeSlash], `\/`, `/`)
	pp, err := compileJavaPatternWithFlagsRound58(rawBody, flags, s)
	return pp, true, err
}

func evalRegexMatchPainlessErr(lhsVal, rhsVal any, isRegexLit, fullMatch bool) (bool, error) {
	if lhsVal == nil || rhsVal == nil {
		return false, &painlessExceptionError{
			exType:  "NullPointerException",
			message: "Cannot invoke regex match on null",
		}
	}
	lhsStr := fmt.Sprintf("%v", lhsVal)
	if pp, ok := rhsVal.(*painlessPattern); ok && pp != nil && pp.re != nil {
		if fullMatch {
			re, err := compilePainlessRegexp("^(?:" + pp.re.String() + ")$")
			if err != nil {
				return false, &painlessExceptionError{exType: "PatternSyntaxException", message: err.Error()}
			}
			return re.MatchString(lhsStr), nil
		}
		return pp.re.MatchString(lhsStr), nil
	}
	pat := strings.TrimSpace(fmt.Sprintf("%v", rhsVal))
	if isRegexLit || isRawRegexLiteralPainless(pat) {
		if pp, ok, err := parseRegexLiteralWithFlagsRound58(pat); ok {
			if err != nil {
				return false, err
			}
			return evalRegexMatchPainlessErr(lhsStr, pp, false, fullMatch)
		}
	}
	pat = normalizeJavaNamedGroupsPainless(pat)
	if fullMatch {
		pat = "^(?:" + pat + ")$"
	}
	re, err := compilePainlessRegexp(pat)
	if err != nil {
		return false, &painlessExceptionError{
			exType:  "PatternSyntaxException",
			message: err.Error(),
		}
	}
	return re.MatchString(lhsStr), nil
}

// ============================================================================
// Round 58 F25: JSR-310 `java.time` Range & `DateTimeFormatter.ofPattern` Validation
// ============================================================================

func isIsoLeapYearRound58(year int64) bool {
	return (year%4 == 0 && year%100 != 0) || (year%400 == 0)
}

func maxDaysInMonthRound58(year int64, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isIsoLeapYearRound58(year) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

func validateJavaYearRound58(year int64) error {
	if year < -999_999_999 || year > 999_999_999 {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for Year (valid values -999999999 - 999999999): %d", year),
		}
	}
	return nil
}

func validateJavaMonthRound58(month int) error {
	if month < 1 || month > 12 {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for MonthOfYear (valid values 1 - 12): %d", month),
		}
	}
	return nil
}

func validateJavaDateRound58(year int64, month, day int) error {
	if err := validateJavaYearRound58(year); err != nil {
		return err
	}
	if err := validateJavaMonthRound58(month); err != nil {
		return err
	}
	maxDay := maxDaysInMonthRound58(year, month)
	if day < 1 || day > maxDay {
		if day == 29 && month == 2 {
			return &painlessExceptionError{
				exType:  "DateTimeException",
				message: fmt.Sprintf("Invalid date 'February 29' as '%d' is not a leap year", year),
			}
		}
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for DayOfMonth (valid values 1 - %d): %d", maxDay, day),
		}
	}
	return nil
}

func validateJavaYearDayRound58(year int64, dayOfYear int) error {
	if err := validateJavaYearRound58(year); err != nil {
		return err
	}
	maxDOY := 365
	if isIsoLeapYearRound58(year) {
		maxDOY = 366
	}
	if dayOfYear < 1 || dayOfYear > maxDOY {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for DayOfYear (valid values 1 - %d): %d", maxDOY, dayOfYear),
		}
	}
	return nil
}

func validateJavaTimeRound58(hour, minute, second, nano int) error {
	if hour < 0 || hour > 23 {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for HourOfDay (valid values 0 - 23): %d", hour),
		}
	}
	if minute < 0 || minute > 59 {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for MinuteOfHour (valid values 0 - 59): %d", minute),
		}
	}
	if second < 0 || second > 59 {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for SecondOfMinute (valid values 0 - 59): %d", second),
		}
	}
	if nano < 0 || nano > 999_999_999 {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid value for NanoOfSecond (valid values 0 - 999999999): %d", nano),
		}
	}
	return nil
}

func validateJavaMonthDayRound58(month, day int) error {
	if err := validateJavaMonthRound58(month); err != nil {
		return err
	}
	maxDay := maxDaysInMonthRound58(2020, month)
	if day < 1 || day > maxDay {
		return &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Illegal value for DayOfMonth field, value %d is not valid for month %d", day, month),
		}
	}
	return nil
}

const validJavaDateTimePatternLettersRound58 = "GuyYDMdQqMLwWEecFahKkHmsSAnNVvzOXxZp"

func validateJavaDateTimePatternRound58(pattern string) error {
	inQuote := false
	optDepth := 0
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '\'' {
			if i+1 < len(pattern) && pattern[i+1] == '\'' {
				i++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch ch {
		case '[':
			optDepth++
			continue
		case ']':
			optDepth--
			if optDepth < 0 {
				return &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Pattern invalid as it contains ] without previous [ in %q", pattern),
				}
			}
			continue
		case '{', '}', '#':
			return &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("Pattern includes reserved character: '%c'", ch),
			}
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			if !strings.ContainsRune(validJavaDateTimePatternLettersRound58, rune(ch)) {
				return &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("Unknown pattern letter: %c", ch),
				}
			}
		}
	}
	if inQuote {
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Pattern ends with an incomplete string literal: %q", pattern),
		}
	}
	return nil
}

func evalJavaTimeFactoryRound58(fnName string, args []string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	evalInt := func(idx int) (int64, error) {
		if idx >= len(args) {
			return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "missing argument"}
		}
		v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
		if err != nil {
			return 0, err
		}
		if v == nil {
			return 0, &painlessExceptionError{exType: "NullPointerException", message: "null temporal argument"}
		}
		if iv, ok := toInt64Painless(v); ok {
			return iv, nil
		}
		if fv, ok := toFloat64(v); ok {
			return int64(fv), nil
		}
		return 0, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid numeric temporal value: %v", v)}
	}

	evalInts := func(indices ...int) ([]int64, error) {
		out := make([]int64, len(indices))
		for i, idx := range indices {
			v, err := evalInt(idx)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}

	evalMonth := func(idx int) (int, error) {
		if idx >= len(args) {
			return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "missing month argument"}
		}
		v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[idx]), params, depth+1)
		if err != nil {
			return 0, err
		}
		if v == nil {
			return 0, &painlessExceptionError{exType: "NullPointerException", message: "month"}
		}
		if iv, ok := isIntegerValuePainless(v); ok {
			if err := validateJavaMonthRound58(int(iv)); err != nil {
				return 0, err
			}
			return int(iv), nil
		}
		if fv, ok := isRawFloatingValPainless(v); ok {
			if err := validateJavaMonthRound58(int(fv)); err != nil {
				return 0, err
			}
			return int(fv), nil
		}
		if mi := parseMonthIndexPainless(v); mi >= 1 && mi <= 12 {
			return mi, nil
		}
		return 0, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Invalid value for MonthOfYear: %v", v)}
	}

	switch fnName {
	case "Year.of":
		y, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		if err := validateJavaYearRound58(y); err != nil {
			return nil, true, err
		}
		return painlessYear{year: y}, true, nil
	case "YearMonth.of":
		y, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		if err := validateJavaYearRound58(y); err != nil {
			return nil, true, err
		}
		m, err := evalMonth(1)
		if err != nil {
			return nil, true, err
		}
		tm := time.Date(int(y), time.Month(m), 1, 0, 0, 0, 0, time.UTC)
		return tm.Format("2006-01"), true, nil
	case "MonthDay.of":
		m, err := evalMonth(0)
		if err != nil {
			return nil, true, err
		}
		d, err := evalInt(1)
		if err != nil {
			return nil, true, err
		}
		if err := validateJavaMonthDayRound58(m, int(d)); err != nil {
			return nil, true, err
		}
		return painlessMonthDay{month: m, day: int(d)}, true, nil
	case "Month.of":
		m, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		if err := validateJavaMonthRound58(int(m)); err != nil {
			return nil, true, err
		}
		return monthNamePainless(int(m)), true, nil
	case "DayOfWeek.of":
		d, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		if d < 1 || d > 7 {
			return nil, true, &painlessExceptionError{
				exType:  "DateTimeException",
				message: fmt.Sprintf("Invalid value for DayOfWeek: %d", d),
			}
		}
		return dayOfWeekNamePainless(int(d)), true, nil
	case "LocalDate.of":
		y, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		m, err := evalMonth(1)
		if err != nil {
			return nil, true, err
		}
		d, err := evalInt(2)
		if err != nil {
			return nil, true, err
		}
		if err := validateJavaDateRound58(y, m, int(d)); err != nil {
			return nil, true, err
		}
		tm := time.Date(int(y), time.Month(m), int(d), 0, 0, 0, 0, time.UTC)
		return tm.Format("2006-01-02"), true, nil
	case "LocalDate.ofYearDay":
		y, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		doy, err := evalInt(1)
		if err != nil {
			return nil, true, err
		}
		if err := validateJavaYearDayRound58(y, int(doy)); err != nil {
			return nil, true, err
		}
		tm := time.Date(int(y), time.January, int(doy), 0, 0, 0, 0, time.UTC)
		return tm.Format("2006-01-02"), true, nil
	case "LocalTime.of":
		if len(args) < 2 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "LocalTime.of requires at least 2 arguments"}
		}
		idxs := []int{0, 1}
		if len(args) >= 3 {
			idxs = append(idxs, 2)
		}
		if len(args) >= 4 {
			idxs = append(idxs, 3)
		}
		vals, err := evalInts(idxs...)
		if err != nil {
			return nil, true, err
		}
		var sec, nano int64
		if len(vals) >= 3 {
			sec = vals[2]
		}
		if len(vals) >= 4 {
			nano = vals[3]
		}
		if err := validateJavaTimeRound58(int(vals[0]), int(vals[1]), int(sec), int(nano)); err != nil {
			return nil, true, err
		}
		return formatLocalTimePainless(int(vals[0]), int(vals[1]), int(sec), int(nano)), true, nil
	case "LocalTime.ofSecondOfDay":
		sec, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		if sec < 0 || sec > 86399 {
			return nil, true, &painlessExceptionError{
				exType:  "DateTimeException",
				message: fmt.Sprintf("Invalid value for SecondOfDay (valid values 0 - 86399): %d", sec),
			}
		}
		s := int(sec)
		return formatLocalTimePainless(s/3600, (s%3600)/60, s%60, 0), true, nil
	case "LocalTime.ofNanoOfDay":
		nano, err := evalInt(0)
		if err != nil {
			return nil, true, err
		}
		if nano < 0 || nano > 86_399_999_999_999 {
			return nil, true, &painlessExceptionError{
				exType:  "DateTimeException",
				message: fmt.Sprintf("Invalid value for NanoOfDay (valid values 0 - 86399999999999): %d", nano),
			}
		}
		sec := int(nano / 1_000_000_000)
		ns := int(nano % 1_000_000_000)
		return formatLocalTimePainless(sec/3600, (sec%3600)/60, sec%60, ns), true, nil
	case "LocalDateTime.of":
		if len(args) == 2 {
			dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			tVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if dVal == nil || tVal == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "LocalDateTime.of(null)"}
			}
			dt, okD := parsePainlessDateTime(dVal)
			tm, okT := parsePainlessDateTime(tVal)
			if !okD || !okT {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: "Invalid LocalDate or LocalTime"}
			}
			tStr := formatLocalTimePainless(tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond())
			return fmt.Sprintf("%04d-%02d-%02dT%s", dt.Year(), int(dt.Month()), dt.Day(), tStr), true, nil
		}
		if len(args) >= 5 {
			y, err := evalInt(0)
			if err != nil {
				return nil, true, err
			}
			m, err := evalMonth(1)
			if err != nil {
				return nil, true, err
			}
			idxs := []int{2, 3, 4}
			if len(args) >= 6 {
				idxs = append(idxs, 5)
			}
			if len(args) >= 7 {
				idxs = append(idxs, 6)
			}
			vals, err := evalInts(idxs...)
			if err != nil {
				return nil, true, err
			}
			d, hr, min := vals[0], vals[1], vals[2]
			var sec, nano int64
			if len(vals) >= 4 {
				sec = vals[3]
			}
			if len(vals) >= 5 {
				nano = vals[4]
			}
			if err := validateJavaDateRound58(y, m, int(d)); err != nil {
				return nil, true, err
			}
			if err := validateJavaTimeRound58(int(hr), int(min), int(sec), int(nano)); err != nil {
				return nil, true, err
			}
			tm := time.Date(int(y), time.Month(m), int(d), int(hr), int(min), int(sec), int(nano), time.UTC)
			if nano > 0 {
				return tm.Format("2006-01-02T15:04:05.999999999"), true, nil
			}
			return tm.Format("2006-01-02T15:04:05"), true, nil
		}
		return nil, true, nil
	case "ZonedDateTime.of", "OffsetDateTime.of":
		if len(args) == 2 {
			ldtVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			zVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if ldtVal == nil || zVal == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: fnName + "(null)"}
			}
			tm, ok := parsePainlessDateTime(ldtVal)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: "Invalid LocalDateTime"}
			}
			loc, errLoc := parseStrictZoneOrOffsetLocRound58(zVal, fnName == "OffsetDateTime.of")
			if errLoc != nil {
				return nil, true, errLoc
			}
			return time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), loc).Format(time.RFC3339Nano), true, nil
		}
		if len(args) == 3 {
			dVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			tVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			zVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[2]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			if dVal == nil || tVal == nil || zVal == nil {
				return nil, true, &painlessExceptionError{exType: "NullPointerException", message: fnName + "(null)"}
			}
			dt, okD := parsePainlessDateTime(dVal)
			tm, okT := parsePainlessDateTime(tVal)
			if !okD || !okT {
				return nil, true, &painlessExceptionError{exType: "DateTimeException", message: "Invalid LocalDate or LocalTime"}
			}
			loc, errLoc := parseStrictZoneOrOffsetLocRound58(zVal, fnName == "OffsetDateTime.of")
			if errLoc != nil {
				return nil, true, errLoc
			}
			return time.Date(dt.Year(), dt.Month(), dt.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), loc).Format(time.RFC3339Nano), true, nil
		}
		if len(args) >= 7 {
			y, err := evalInt(0)
			if err != nil {
				return nil, true, err
			}
			m, err := evalMonth(1)
			if err != nil {
				return nil, true, err
			}
			vals, err := evalInts(2, 3, 4, 5, 6)
			if err != nil {
				return nil, true, err
			}
			d, hr, min, sec, nano := vals[0], vals[1], vals[2], vals[3], vals[4]
			if err := validateJavaDateRound58(y, m, int(d)); err != nil {
				return nil, true, err
			}
			if err := validateJavaTimeRound58(int(hr), int(min), int(sec), int(nano)); err != nil {
				return nil, true, err
			}
			loc := time.UTC
			if len(args) >= 8 {
				zVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[7]), params, depth+1)
				if err != nil {
					return nil, true, err
				}
				if zVal == nil {
					return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "zone"}
				}
				loc, err = parseStrictZoneOrOffsetLocRound58(zVal, fnName == "OffsetDateTime.of")
				if err != nil {
					return nil, true, err
				}
			}
			tm := time.Date(int(y), time.Month(m), int(d), int(hr), int(min), int(sec), int(nano), loc)
			return tm.Format(time.RFC3339Nano), true, nil
		}
		return nil, true, nil
	default:
		return nil, false, nil
	}
}

func parseStrictZoneOrOffsetLocRound58(zVal any, requireOffset bool) (*time.Location, error) {
	s := strings.TrimSpace(fmt.Sprintf("%v", zVal))
	if requireOffset {
		u := strings.ToUpper(s)
		isOffsetForm := u == "Z" || u == "UTC" || u == "GMT" || u == "UT" ||
			(len(s) > 0 && (s[0] == '+' || s[0] == '-')) ||
			strings.HasPrefix(u, "UTC+") || strings.HasPrefix(u, "UTC-") ||
			strings.HasPrefix(u, "GMT+") || strings.HasPrefix(u, "GMT-") ||
			strings.HasPrefix(u, "UT+") || strings.HasPrefix(u, "UT-")
		if !isOffsetForm {
			return nil, &painlessExceptionError{
				exType:  "DateTimeException",
				message: fmt.Sprintf("Invalid ZoneOffset: %v", zVal),
			}
		}
	}
	if offSec, ok := parseZoneOffsetSecondsPainless(zVal); ok {
		if offSec == 0 {
			return time.UTC, nil
		}
		return time.FixedZone(formatZoneOffsetSecondsPainless(offSec), offSec), nil
	}
	if requireOffset {
		return nil, &painlessExceptionError{
			exType:  "DateTimeException",
			message: fmt.Sprintf("Invalid ZoneOffset: %v", zVal),
		}
	}
	if s == "" {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: "Invalid empty ZoneId"}
	}
	if s == "UTC" || s == "GMT" || s == "UT" || s == "Z" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(s)
	if err != nil {
		return nil, &painlessExceptionError{exType: "DateTimeException", message: fmt.Sprintf("Unknown time-zone ID: %s", s)}
	}
	return loc, nil
}

func evalTemporalWithFieldRound58(mName string, tm time.Time, n int64, isLocalDateOnly, isYearMonthOnly *bool) (time.Time, error) {
	switch mName {
	case ".withYear(":
		if err := validateJavaYearRound58(n); err != nil {
			return tm, err
		}
		day := tm.Day()
		if maxD := maxDaysInMonthRound58(n, int(tm.Month())); day > maxD {
			day = maxD
		}
		return time.Date(int(n), tm.Month(), day, tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location()), nil
	case ".withMonth(":
		if err := validateJavaMonthRound58(int(n)); err != nil {
			return tm, err
		}
		day := tm.Day()
		if maxD := maxDaysInMonthRound58(int64(tm.Year()), int(n)); day > maxD {
			day = maxD
		}
		return time.Date(tm.Year(), time.Month(int(n)), day, tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location()), nil
	case ".withDayOfMonth(":
		if err := validateJavaDateRound58(int64(tm.Year()), int(tm.Month()), int(n)); err != nil {
			return tm, err
		}
		*isYearMonthOnly = false
		return time.Date(tm.Year(), tm.Month(), int(n), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location()), nil
	case ".withDayOfYear(":
		if err := validateJavaYearDayRound58(int64(tm.Year()), int(n)); err != nil {
			return tm, err
		}
		*isYearMonthOnly = false
		return time.Date(tm.Year(), time.January, int(n), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location()), nil
	case ".withHour(":
		if err := validateJavaTimeRound58(int(n), tm.Minute(), tm.Second(), tm.Nanosecond()); err != nil {
			return tm, err
		}
		*isLocalDateOnly = false
		*isYearMonthOnly = false
		return time.Date(tm.Year(), tm.Month(), tm.Day(), int(n), tm.Minute(), tm.Second(), tm.Nanosecond(), tm.Location()), nil
	case ".withMinute(":
		if err := validateJavaTimeRound58(tm.Hour(), int(n), tm.Second(), tm.Nanosecond()); err != nil {
			return tm, err
		}
		*isLocalDateOnly = false
		*isYearMonthOnly = false
		return time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), int(n), tm.Second(), tm.Nanosecond(), tm.Location()), nil
	case ".withSecond(":
		if err := validateJavaTimeRound58(tm.Hour(), tm.Minute(), int(n), tm.Nanosecond()); err != nil {
			return tm, err
		}
		*isLocalDateOnly = false
		*isYearMonthOnly = false
		return time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), int(n), tm.Nanosecond(), tm.Location()), nil
	case ".withNano(":
		if err := validateJavaTimeRound58(tm.Hour(), tm.Minute(), tm.Second(), int(n)); err != nil {
			return tm, err
		}
		*isLocalDateOnly = false
		*isYearMonthOnly = false
		return time.Date(tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), int(n), tm.Location()), nil
	default:
		return tm, nil
	}
}

// ============================================================================
// Round 58 F26: Collection, String & Stream Bounds and Immutability Contracts
// ============================================================================

func evalListSubListRound58(tv []any, args []string, sourceMap, params map[string]any, depth int) (any, error) {
	if len(args) < 2 {
		return newEmptyPainlessSlice(), nil
	}
	sVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err != nil {
		return nil, err
	}
	eVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
	if err != nil {
		return nil, err
	}
	sf, sOk := toInt64Painless(sVal)
	if !sOk {
		if ff, ok := toFloat64(sVal); ok {
			sf, sOk = int64(ff), true
		}
	}
	ef, eOk := toInt64Painless(eVal)
	if !eOk {
		if ff, ok := toFloat64(eVal); ok {
			ef, eOk = int64(ff), true
		}
	}
	if !sOk || !eOk {
		return newEmptyPainlessSlice(), nil
	}
	start, end := int(sf), int(ef)
	if start < 0 || end > len(tv) {
		return nil, &painlessExceptionError{
			exType:  "IndexOutOfBoundsException",
			message: fmt.Sprintf("subList(%d, %d) out of bounds for size %d", start, end, len(tv)),
		}
	}
	if start > end {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("fromIndex(%d) > toIndex(%d)", start, end),
		}
	}
	budget := getOrInitEvalBudget(params)
	if isUnmodContainerPainless(budget, tv) {
		sub := allocUnmodSlicePainless(end - start)
		sub = append(sub, tv[start:end]...)
		markUnmodSlicePainless(budget, sub)
		return sub, nil
	}
	if end == start {
		return newEmptyPainlessSlice(), nil
	}
	sub := make([]any, end-start)
	copy(sub, tv[start:end])
	return sub, nil
}

func evalStringSubstringRound58(s string, args []string, sourceMap, params map[string]any, depth int) (any, error) {
	if len(args) == 0 {
		return s, nil
	}
	startVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err != nil {
		return nil, err
	}
	sf, sOk := toInt64Painless(startVal)
	if !sOk {
		if ff, ok := toFloat64(startVal); ok {
			sf, sOk = int64(ff), true
		}
	}
	if !sOk {
		return s, nil
	}
	runes := []rune(s)
	start := int(sf)
	end := len(runes)
	if len(args) >= 2 {
		endVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
		if err != nil {
			return nil, err
		}
		ef, eOk := toInt64Painless(endVal)
		if !eOk {
			if ff, ok := toFloat64(endVal); ok {
				ef, eOk = int64(ff), true
			}
		}
		if eOk {
			end = int(ef)
		}
		if start < 0 || end > len(runes) || start > end {
			return nil, &painlessExceptionError{
				exType:  "StringIndexOutOfBoundsException",
				message: fmt.Sprintf("Range [%d, %d) out of bounds for length %d", start, end, len(runes)),
			}
		}
		return string(runes[start:end]), nil
	}
	if start < 0 || start > len(runes) {
		return nil, &painlessExceptionError{
			exType:  "StringIndexOutOfBoundsException",
			message: fmt.Sprintf("String index out of range: %d", start),
		}
	}
	return string(runes[start:]), nil
}

func evalStringCharAtOrCodePointRound58(s string, argVal any, asCodePoint bool) (any, error) {
	if argVal == nil {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "null index"}
	}
	iv, ok := toInt64Painless(argVal)
	if !ok {
		if ff, fOk := toFloat64(argVal); fOk {
			iv, ok = int64(ff), true
		}
	}
	if !ok {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Invalid index: %v", argVal)}
	}
	idx := int(iv)
	runes := []rune(s)
	if idx < 0 || idx >= len(runes) {
		return nil, &painlessExceptionError{
			exType:  "StringIndexOutOfBoundsException",
			message: fmt.Sprintf("String index out of range: %d", idx),
		}
	}
	if asCodePoint {
		return int64(runes[idx]), nil
	}
	return string(runes[idx]), nil
}

func evalStringRepeatRound58(s string, argVal any) (any, error) {
	if argVal == nil {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "null count"}
	}
	iv, ok := toInt64Painless(argVal)
	if !ok {
		if ff, fOk := toFloat64(argVal); fOk {
			iv, ok = int64(ff), true
		}
	}
	if !ok {
		return "", nil
	}
	if iv < 0 {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("count is negative: %d", iv),
		}
	}
	n := int(iv)
	if n == 0 || s == "" {
		return "", nil
	}
	if len(s)*n > MaxPainlessSliceItems*64 {
		n = (MaxPainlessSliceItems * 64) / len(s)
	}
	return strings.Repeat(s, n), nil
}

func evalCollectionsNCopiesRound58(args []string, sourceMap, params map[string]any, depth int) (any, error) {
	if len(args) < 2 {
		out := allocUnmodSlicePainless(0)
		markUnmodSlicePainless(getOrInitEvalBudget(params), out)
		return out, nil
	}
	nVal, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[0]), params, depth+1)
	if err != nil {
		return nil, err
	}
	if nVal == nil {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "null length"}
	}
	ni, ok := toInt64Painless(nVal)
	if !ok {
		if nf, fOk := toFloat64(nVal); fOk {
			ni, ok = int64(nf), true
		}
	}
	if !ok {
		out := allocUnmodSlicePainless(0)
		markUnmodSlicePainless(getOrInitEvalBudget(params), out)
		return out, nil
	}
	if ni < 0 {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("List length = %d", ni),
		}
	}
	val, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(args[1]), params, depth+1)
	if err != nil {
		return nil, err
	}
	n := int(ni)
	if n > MaxPainlessSliceItems {
		n = MaxPainlessSliceItems
	}
	budget := getOrInitEvalBudget(params)
	out := allocUnmodSlicePainless(n)
	for i := 0; i < n; i++ {
		out = append(out, val)
	}
	markUnmodSlicePainless(budget, out)
	return out, nil
}
