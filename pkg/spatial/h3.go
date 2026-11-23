// Package spatial implements pure-Go, zero-CGO geospatial indexing primitives,
// including IEEE/Uber H3 v3/v4 discrete global grid operations.
package spatial

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	// MaxRes is the maximum supported H3 cell resolution (0..15).
	MaxRes = 15

	numIcosaFaces = 20
	numBaseCells  = 122
	numHexVerts   = 6
	numPentVerts  = 5
	numPentagons  = 12

	h3CellMode       = 1
	h3MaxOffset      = 63
	h3ModeOffset     = 59
	h3ReservedOffset = 56
	h3ResOffset      = 52
	h3BCOffset       = 45
	h3PerDigitOffset = 3

	h3HighBitMask  = uint64(1) << h3MaxOffset
	h3ModeMask     = uint64(15) << h3ModeOffset
	h3ReservedMask = uint64(7) << h3ReservedOffset
	h3ResMask      = uint64(15) << h3ResOffset
	h3BCMask       = uint64(127) << h3BCOffset
	h3DigitMask    = uint64(7)
	h3Init         = uint64(35184372088831)

	maxFaceCoord     = 2
	invalidBaseCell  = 127
	invalidRotations = -1
	invalidFace      = -1

	overageIJ = 1
	overageKI = 2
	overageJK = 3

	centerDigit   = 0
	kAxesDigit    = 1
	jAxesDigit    = 2
	jkAxesDigit   = 3
	iAxesDigit    = 4
	ikAxesDigit   = 5
	ijAxesDigit   = 6
	invalidDigit  = 7
	numDigits     = 7
	pentSkipDigit = kAxesDigit

	overageNone     = 0
	overageFaceEdge = 1
	overageNewFace  = 2

	pi            = 3.14159265358979323846
	pi2           = 1.5707963267948966
	twoPi         = 6.28318530717958647692528676655900576839433
	degToRad      = 0.0174532925199432957692369076848861271111
	radToDeg      = 57.29577951308232087679815481410517033240547
	h3Epsilon     = 0.0000000000000001
	sqrt3_2       = 0.8660254037844386467637231707529361834714
	sin60         = sqrt3_2
	ap7RotRads    = 0.333473172251832115336090755351601070065900389
	res0UGnomonic = 0.38196601125010500003
	sqrt7         = 2.6457513110645905905016157536392604257102
	earthRadiusKm = 6371.007180918475
	fltEpsilon    = 1.1920928955078125e-07
	dblEpsilon    = 2.2204460492503131e-16

	maxGridCellsLimit = 1_000_000
)

var (
	// ErrInvalidResolution indicates an out-of-range H3 resolution.
	ErrInvalidResolution = errors.New("h3: invalid resolution")
	// ErrInvalidCell indicates an invalid H3 cell index or string.
	ErrInvalidCell = errors.New("h3: invalid cell index")
	// ErrInvalidCoordinate indicates NaN or infinite coordinates.
	ErrInvalidCoordinate = errors.New("h3: invalid coordinate")
	// ErrResolutionMismatch indicates an incompatible parent/child resolution.
	ErrResolutionMismatch = errors.New("h3: resolution mismatch")
	// ErrCellLimitExceeded indicates a region query would exceed safe cell budget.
	ErrCellLimitExceeded = errors.New("h3: cell count limit exceeded")
	errPentagonNeighbor  = errors.New("h3: pentagon deleted k neighbor")
)

type latLng struct {
	lat float64
	lng float64
}

type vec2d struct {
	x float64
	y float64
}

type vec3d struct {
	x float64
	y float64
	z float64
}

type coordIJK struct {
	i int
	j int
	k int
}

type faceIJK struct {
	face  int
	coord coordIJK
}

type faceOrientIJK struct {
	face      int
	translate coordIJK
	ccwRot60  int
}

type baseCellRotation struct {
	baseCell int
	ccwRot60 int
}

type baseCellDataEntry struct {
	homeFijk     faceIJK
	isPentagon   bool
	cwOffsetPent [2]int
}

var unitVecs = [7]coordIJK{
	{0, 0, 0},
	{0, 0, 1},
	{0, 1, 0},
	{0, 1, 1},
	{1, 0, 0},
	{1, 0, 1},
	{1, 1, 0},
}

var ringDirections = [6]int{
	jAxesDigit,
	jkAxesDigit,
	kAxesDigit,
	ikAxesDigit,
	iAxesDigit,
	ijAxesDigit,
}

var newDigitII = [7][7]int{
	{centerDigit, kAxesDigit, jAxesDigit, jkAxesDigit, iAxesDigit, ikAxesDigit, ijAxesDigit},
	{kAxesDigit, iAxesDigit, jkAxesDigit, ijAxesDigit, ikAxesDigit, jAxesDigit, centerDigit},
	{jAxesDigit, jkAxesDigit, kAxesDigit, iAxesDigit, ijAxesDigit, centerDigit, ikAxesDigit},
	{jkAxesDigit, ijAxesDigit, iAxesDigit, ikAxesDigit, centerDigit, kAxesDigit, jAxesDigit},
	{iAxesDigit, ikAxesDigit, ijAxesDigit, centerDigit, jAxesDigit, jkAxesDigit, kAxesDigit},
	{ikAxesDigit, jAxesDigit, centerDigit, kAxesDigit, jkAxesDigit, ijAxesDigit, iAxesDigit},
	{ijAxesDigit, centerDigit, ikAxesDigit, jAxesDigit, kAxesDigit, iAxesDigit, jkAxesDigit},
}

var newAdjustmentII = [7][7]int{
	{centerDigit, centerDigit, centerDigit, centerDigit, centerDigit, centerDigit, centerDigit},
	{centerDigit, kAxesDigit, centerDigit, kAxesDigit, centerDigit, ikAxesDigit, centerDigit},
	{centerDigit, centerDigit, jAxesDigit, jkAxesDigit, centerDigit, centerDigit, jAxesDigit},
	{centerDigit, kAxesDigit, jkAxesDigit, jkAxesDigit, centerDigit, centerDigit, centerDigit},
	{centerDigit, centerDigit, centerDigit, centerDigit, iAxesDigit, iAxesDigit, ijAxesDigit},
	{centerDigit, ikAxesDigit, centerDigit, centerDigit, iAxesDigit, ikAxesDigit, centerDigit},
	{centerDigit, centerDigit, jAxesDigit, centerDigit, ijAxesDigit, centerDigit, ijAxesDigit},
}

var newDigitIII = [7][7]int{
	{centerDigit, kAxesDigit, jAxesDigit, jkAxesDigit, iAxesDigit, ikAxesDigit, ijAxesDigit},
	{kAxesDigit, jAxesDigit, jkAxesDigit, iAxesDigit, ikAxesDigit, ijAxesDigit, centerDigit},
	{jAxesDigit, jkAxesDigit, iAxesDigit, ikAxesDigit, ijAxesDigit, centerDigit, kAxesDigit},
	{jkAxesDigit, iAxesDigit, ikAxesDigit, ijAxesDigit, centerDigit, kAxesDigit, jAxesDigit},
	{iAxesDigit, ikAxesDigit, ijAxesDigit, centerDigit, kAxesDigit, jAxesDigit, jkAxesDigit},
	{ikAxesDigit, ijAxesDigit, centerDigit, kAxesDigit, jAxesDigit, jkAxesDigit, iAxesDigit},
	{ijAxesDigit, centerDigit, kAxesDigit, jAxesDigit, jkAxesDigit, iAxesDigit, ikAxesDigit},
}

var newAdjustmentIII = [7][7]int{
	{centerDigit, centerDigit, centerDigit, centerDigit, centerDigit, centerDigit, centerDigit},
	{centerDigit, kAxesDigit, centerDigit, jkAxesDigit, centerDigit, kAxesDigit, centerDigit},
	{centerDigit, centerDigit, jAxesDigit, jAxesDigit, centerDigit, centerDigit, ijAxesDigit},
	{centerDigit, jkAxesDigit, jAxesDigit, jkAxesDigit, centerDigit, centerDigit, centerDigit},
	{centerDigit, centerDigit, centerDigit, centerDigit, iAxesDigit, ikAxesDigit, iAxesDigit},
	{centerDigit, kAxesDigit, centerDigit, centerDigit, ikAxesDigit, ikAxesDigit, centerDigit},
	{centerDigit, centerDigit, ijAxesDigit, centerDigit, iAxesDigit, centerDigit, ijAxesDigit},
}

var maxDimByCIIres = [17]int{
	2, -1, 14, -1, 98, -1, 686, -1, 4802, -1, 33614, -1, 235298, -1, 1647086, -1, 11529602,
}

var unitScaleByCIIres = [17]int{
	1, -1, 7, -1, 49, -1, 343, -1, 2401, -1, 16807, -1, 117649, -1, 823543, -1, 5764801,
}

func h3GetHighBit(h uint64) int { return int((h & h3HighBitMask) >> h3MaxOffset) }
func h3GetMode(h uint64) int    { return int((h & h3ModeMask) >> h3ModeOffset) }
func h3SetMode(h uint64, v int) uint64 {
	return (h &^ h3ModeMask) | ((uint64(v) & 0xF) << h3ModeOffset) // #nosec G115 -- H3 mode is a 4-bit field (0..15)
}
func h3GetBaseCell(h uint64) int { return int((h & h3BCMask) >> h3BCOffset) }
func h3SetBaseCell(h uint64, bc int) uint64 {
	return (h &^ h3BCMask) | ((uint64(bc) & 0x7F) << h3BCOffset) // #nosec G115 -- H3 base cell is a 7-bit field (0..121)
}
func h3GetResolution(h uint64) int { return int((h & h3ResMask) >> h3ResOffset) }
func h3SetResolution(h uint64, res int) uint64 {
	return (h &^ h3ResMask) | ((uint64(res) & 0xF) << h3ResOffset) // #nosec G115 -- H3 resolution is 4-bit field (0..15)
}
func h3GetReservedBits(h uint64) int { return int((h & h3ReservedMask) >> h3ReservedOffset) }
func h3GetIndexDigit(h uint64, res int) int {
	return int((h >> uint((MaxRes-res)*h3PerDigitOffset)) & h3DigitMask)
}
func h3SetIndexDigit(h uint64, res, digit int) uint64 {
	shift := uint((MaxRes - res) * h3PerDigitOffset)                        // #nosec G115 -- H3 res is bounded 1..MaxRes
	return (h &^ (h3DigitMask << shift)) | ((uint64(digit) & 0x7) << shift) // #nosec G115 -- H3 digit is a 3-bit field (0..7)
}

func isResolutionClassIII(res int) bool { return res%2 != 0 }

// IsResClassIII reports whether h is at an odd (Class III) resolution.
func IsResClassIII(h uint64) bool { return h3GetResolution(h)%2 != 0 }

// Resolution returns the H3 resolution (0..15) of cell h, or -1 if h is invalid.
func Resolution(h uint64) int {
	if !IsValidCell(h) {
		return -1
	}
	return h3GetResolution(h)
}

// IsValidCell reports whether h is a valid H3 cell (hexagon or pentagon) index.
func IsValidCell(h uint64) bool {
	if h3GetHighBit(h) != 0 {
		return false
	}
	if h3GetMode(h) != h3CellMode {
		return false
	}
	if h3GetReservedBits(h) != 0 {
		return false
	}
	baseCell := h3GetBaseCell(h)
	if baseCell < 0 || baseCell >= numBaseCells {
		return false
	}
	res := h3GetResolution(h)
	if res < 0 || res > MaxRes {
		return false
	}
	foundFirstNonZeroDigit := false
	for r := 1; r <= res; r++ {
		digit := h3GetIndexDigit(h, r)
		if !foundFirstNonZeroDigit && digit != centerDigit {
			foundFirstNonZeroDigit = true
			if isBaseCellPentagon(baseCell) && digit == kAxesDigit {
				return false
			}
		}
		if digit < centerDigit || digit >= numDigits {
			return false
		}
	}
	for r := res + 1; r <= MaxRes; r++ {
		if h3GetIndexDigit(h, r) != invalidDigit {
			return false
		}
	}
	return true
}

// CellToString formats an H3 cell index as lowercase hexadecimal.
func CellToString(h uint64) string {
	return strconv.FormatUint(h, 16)
}

// StringToCell parses a hexadecimal H3 cell string and validates it as an H3 cell.
func StringToCell(s string) (uint64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || len(trimmed) > 16 {
		return 0, fmt.Errorf("%w: %q", ErrInvalidCell, s)
	}
	h, err := strconv.ParseUint(trimmed, 16, 64)
	if err != nil || !IsValidCell(h) {
		return 0, fmt.Errorf("%w: %q", ErrInvalidCell, s)
	}
	return h, nil
}

// IsPentagon reports whether h is a valid H3 pentagon cell.
func IsPentagon(h uint64) bool {
	if !IsValidCell(h) {
		return false
	}
	return isPentagonUnchecked(h)
}

func isPentagonUnchecked(h uint64) bool {
	return isBaseCellPentagon(h3GetBaseCell(h)) && h3LeadingNonZeroDigit(h) == 0
}

func isBaseCellPentagon(bc int) bool {
	if bc < 0 || bc >= numBaseCells {
		return false
	}
	return baseCellData[bc].isPentagon
}

func isBaseCellPolarPentagon(bc int) bool {
	return bc == 4 || bc == 117
}

func h3LeadingNonZeroDigit(h uint64) int {
	res := h3GetResolution(h)
	for r := 1; r <= res; r++ {
		if d := h3GetIndexDigit(h, r); d != 0 {
			return d
		}
	}
	return centerDigit
}

func degsToRads(degrees float64) float64 { return degrees * degToRad }
func radsToDegs(radians float64) float64 { return radians * radToDeg }

func posAngleRads(rads float64) float64 {
	tmp := rads
	if rads < 0 {
		tmp += twoPi
	}
	if rads >= twoPi {
		tmp -= twoPi
	}
	return tmp
}

func constrainLng(lng float64) float64 {
	for lng > pi {
		lng -= 2 * pi
	}
	for lng < -pi {
		lng += 2 * pi
	}
	return lng
}

func geoToVec3d(geo latLng) vec3d {
	r := math.Cos(geo.lat)
	return vec3d{
		x: math.Cos(geo.lng) * r,
		y: math.Sin(geo.lng) * r,
		z: math.Sin(geo.lat),
	}
}

func pointSquareDist(v1, v2 vec3d) float64 {
	dx := v1.x - v2.x
	dy := v1.y - v2.y
	dz := v1.z - v2.z
	return dx*dx + dy*dy + dz*dz
}

func geoAzimuthRads(p1, p2 latLng) float64 {
	return math.Atan2(
		math.Cos(p2.lat)*math.Sin(p2.lng-p1.lng),
		math.Cos(p1.lat)*math.Sin(p2.lat)-math.Sin(p1.lat)*math.Cos(p2.lat)*math.Cos(p2.lng-p1.lng),
	)
}

func geoAzDistanceRads(p1 latLng, az, distance float64) latLng {
	if distance < h3Epsilon {
		return p1
	}
	az = posAngleRads(az)
	var p2 latLng
	if az < h3Epsilon || math.Abs(az-pi) < h3Epsilon {
		if az < h3Epsilon {
			p2.lat = p1.lat + distance
		} else {
			p2.lat = p1.lat - distance
		}
		if math.Abs(p2.lat-pi2) < h3Epsilon {
			p2.lat = pi2
			p2.lng = 0
		} else if math.Abs(p2.lat+pi2) < h3Epsilon {
			p2.lat = -pi2
			p2.lng = 0
		} else {
			p2.lng = constrainLng(p1.lng)
		}
	} else {
		sinlat := math.Sin(p1.lat)*math.Cos(distance) + math.Cos(p1.lat)*math.Sin(distance)*math.Cos(az)
		if sinlat > 1.0 {
			sinlat = 1.0
		}
		if sinlat < -1.0 {
			sinlat = -1.0
		}
		p2.lat = math.Asin(sinlat)
		if math.Abs(p2.lat-pi2) < h3Epsilon {
			p2.lat = pi2
			p2.lng = 0
		} else if math.Abs(p2.lat+pi2) < h3Epsilon {
			p2.lat = -pi2
			p2.lng = 0
		} else {
			sinlng := math.Sin(az) * math.Sin(distance) / math.Cos(p2.lat)
			coslng := (math.Cos(distance) - math.Sin(p1.lat)*math.Sin(p2.lat)) / math.Cos(p1.lat) / math.Cos(p2.lat)
			if sinlng > 1.0 {
				sinlng = 1.0
			}
			if sinlng < -1.0 {
				sinlng = -1.0
			}
			if coslng > 1.0 {
				coslng = 1.0
			}
			if coslng < -1.0 {
				coslng = -1.0
			}
			p2.lng = constrainLng(p1.lng + math.Atan2(sinlng, coslng))
		}
	}
	return p2
}

func greatCircleDistanceRads(a, b latLng) float64 {
	sinLat := math.Sin((b.lat - a.lat) / 2.0)
	sinLng := math.Sin((b.lng - a.lng) / 2.0)
	A := sinLat*sinLat + math.Cos(a.lat)*math.Cos(b.lat)*sinLng*sinLng
	if A > 1.0 {
		A = 1.0
	}
	return 2 * math.Atan2(math.Sqrt(A), math.Sqrt(1-A))
}

func greatCircleDistanceKm(a, b latLng) float64 {
	return greatCircleDistanceRads(a, b) * earthRadiusKm
}

func v2dMag(v vec2d) float64 { return math.Sqrt(v.x*v.x + v.y*v.y) }

func v2dIntersect(p0, p1, p2, p3 vec2d) vec2d {
	s1 := vec2d{x: p1.x - p0.x, y: p1.y - p0.y}
	s2 := vec2d{x: p3.x - p2.x, y: p3.y - p2.y}
	t := (s2.x*(p0.y-p2.y) - s2.y*(p0.x-p2.x)) / (-s2.x*s1.y + s1.x*s2.y)
	return vec2d{x: p0.x + t*s1.x, y: p0.y + t*s1.y}
}

func v2dAlmostEquals(v1, v2 vec2d) bool {
	return math.Abs(v1.x-v2.x) < fltEpsilon && math.Abs(v1.y-v2.y) < fltEpsilon
}

func ijkNormalize(c *coordIJK) {
	if c.i < 0 {
		c.j -= c.i
		c.k -= c.i
		c.i = 0
	}
	if c.j < 0 {
		c.i -= c.j
		c.k -= c.j
		c.j = 0
	}
	if c.k < 0 {
		c.i -= c.k
		c.j -= c.k
		c.k = 0
	}
	minVal := c.i
	if c.j < minVal {
		minVal = c.j
	}
	if c.k < minVal {
		minVal = c.k
	}
	if minVal > 0 {
		c.i -= minVal
		c.j -= minVal
		c.k -= minVal
	}
}

func ijkScale(c *coordIJK, factor int) {
	c.i *= factor
	c.j *= factor
	c.k *= factor
}

func ijkAdd(h1, h2 coordIJK) coordIJK {
	return coordIJK{i: h1.i + h2.i, j: h1.j + h2.j, k: h1.k + h2.k}
}

func ijkSub(h1, h2 coordIJK) coordIJK {
	return coordIJK{i: h1.i - h2.i, j: h1.j - h2.j, k: h1.k - h2.k}
}

func unitIjkToDigit(ijk coordIJK) int {
	c := ijk
	ijkNormalize(&c)
	for d := centerDigit; d < numDigits; d++ {
		if c == unitVecs[d] {
			return d
		}
	}
	return invalidDigit
}

func upAp7(ijk *coordIJK) {
	i := ijk.i - ijk.k
	j := ijk.j - ijk.k
	ijk.i = int(math.Round(float64(3*i-j) / 7.0))
	ijk.j = int(math.Round(float64(i+2*j) / 7.0))
	ijk.k = 0
	ijkNormalize(ijk)
}

func upAp7r(ijk *coordIJK) {
	i := ijk.i - ijk.k
	j := ijk.j - ijk.k
	ijk.i = int(math.Round(float64(2*i+j) / 7.0))
	ijk.j = int(math.Round(float64(3*j-i) / 7.0))
	ijk.k = 0
	ijkNormalize(ijk)
}

func downAp7(ijk *coordIJK) {
	iVec := coordIJK{3, 0, 1}
	jVec := coordIJK{1, 3, 0}
	kVec := coordIJK{0, 1, 3}
	ijkScale(&iVec, ijk.i)
	ijkScale(&jVec, ijk.j)
	ijkScale(&kVec, ijk.k)
	*ijk = ijkAdd(ijkAdd(iVec, jVec), kVec)
	ijkNormalize(ijk)
}

func downAp7r(ijk *coordIJK) {
	iVec := coordIJK{3, 1, 0}
	jVec := coordIJK{0, 3, 1}
	kVec := coordIJK{1, 0, 3}
	ijkScale(&iVec, ijk.i)
	ijkScale(&jVec, ijk.j)
	ijkScale(&kVec, ijk.k)
	*ijk = ijkAdd(ijkAdd(iVec, jVec), kVec)
	ijkNormalize(ijk)
}

func downAp3(ijk *coordIJK) {
	iVec := coordIJK{2, 0, 1}
	jVec := coordIJK{1, 2, 0}
	kVec := coordIJK{0, 1, 2}
	ijkScale(&iVec, ijk.i)
	ijkScale(&jVec, ijk.j)
	ijkScale(&kVec, ijk.k)
	*ijk = ijkAdd(ijkAdd(iVec, jVec), kVec)
	ijkNormalize(ijk)
}

func downAp3r(ijk *coordIJK) {
	iVec := coordIJK{2, 1, 0}
	jVec := coordIJK{0, 2, 1}
	kVec := coordIJK{1, 0, 2}
	ijkScale(&iVec, ijk.i)
	ijkScale(&jVec, ijk.j)
	ijkScale(&kVec, ijk.k)
	*ijk = ijkAdd(ijkAdd(iVec, jVec), kVec)
	ijkNormalize(ijk)
}

func neighborIJK(ijk *coordIJK, digit int) {
	if digit > centerDigit && digit < numDigits {
		*ijk = ijkAdd(*ijk, unitVecs[digit])
		ijkNormalize(ijk)
	}
}

func ijkRotate60ccw(ijk *coordIJK) {
	iVec := coordIJK{1, 1, 0}
	jVec := coordIJK{0, 1, 1}
	kVec := coordIJK{1, 0, 1}
	ijkScale(&iVec, ijk.i)
	ijkScale(&jVec, ijk.j)
	ijkScale(&kVec, ijk.k)
	*ijk = ijkAdd(ijkAdd(iVec, jVec), kVec)
	ijkNormalize(ijk)
}

func ijkRotate60cw(ijk *coordIJK) {
	iVec := coordIJK{1, 0, 1}
	jVec := coordIJK{1, 1, 0}
	kVec := coordIJK{0, 1, 1}
	ijkScale(&iVec, ijk.i)
	ijkScale(&jVec, ijk.j)
	ijkScale(&kVec, ijk.k)
	*ijk = ijkAdd(ijkAdd(iVec, jVec), kVec)
	ijkNormalize(ijk)
}

func rotate60ccw(digit int) int {
	switch digit {
	case kAxesDigit:
		return ikAxesDigit
	case ikAxesDigit:
		return iAxesDigit
	case iAxesDigit:
		return ijAxesDigit
	case ijAxesDigit:
		return jAxesDigit
	case jAxesDigit:
		return jkAxesDigit
	case jkAxesDigit:
		return kAxesDigit
	default:
		return digit
	}
}

func rotate60cw(digit int) int {
	switch digit {
	case kAxesDigit:
		return jkAxesDigit
	case jkAxesDigit:
		return jAxesDigit
	case jAxesDigit:
		return ijAxesDigit
	case ijAxesDigit:
		return iAxesDigit
	case iAxesDigit:
		return ikAxesDigit
	case ikAxesDigit:
		return kAxesDigit
	default:
		return digit
	}
}

func h3RotatePent60ccw(h uint64) uint64 {
	foundFirstNonZeroDigit := false
	res := h3GetResolution(h)
	for r := 1; r <= res; r++ {
		h = h3SetIndexDigit(h, r, rotate60ccw(h3GetIndexDigit(h, r)))
		if !foundFirstNonZeroDigit && h3GetIndexDigit(h, r) != 0 {
			foundFirstNonZeroDigit = true
			if h3LeadingNonZeroDigit(h) == kAxesDigit {
				h = h3Rotate60ccw(h)
			}
		}
	}
	return h
}

func h3Rotate60ccw(h uint64) uint64 {
	res := h3GetResolution(h)
	for r := 1; r <= res; r++ {
		h = h3SetIndexDigit(h, r, rotate60ccw(h3GetIndexDigit(h, r)))
	}
	return h
}

func h3Rotate60cw(h uint64) uint64 {
	res := h3GetResolution(h)
	for r := 1; r <= res; r++ {
		h = h3SetIndexDigit(h, r, rotate60cw(h3GetIndexDigit(h, r)))
	}
	return h
}

func hex2dToCoordIJK(v vec2d) coordIJK {
	var h coordIJK
	a1 := math.Abs(v.x)
	a2 := math.Abs(v.y)

	x2 := a2 / sin60
	x1 := a1 + x2/2.0

	m1 := int(x1)
	m2 := int(x2)
	r1 := x1 - float64(m1)
	r2 := x2 - float64(m2)

	if r1 < 0.5 {
		if r1 < 1.0/3.0 {
			if r2 < (1.0+r1)/2.0 {
				h.i = m1
				h.j = m2
			} else {
				h.i = m1
				h.j = m2 + 1
			}
		} else {
			if r2 < (1.0 - r1) {
				h.j = m2
			} else {
				h.j = m2 + 1
			}
			if (1.0-r1) <= r2 && r2 < (2.0*r1) {
				h.i = m1 + 1
			} else {
				h.i = m1
			}
		}
	} else {
		if r1 < 2.0/3.0 {
			if r2 < (1.0 - r1) {
				h.j = m2
			} else {
				h.j = m2 + 1
			}
			if (2.0*r1-1.0) < r2 && r2 < (1.0-r1) {
				h.i = m1
			} else {
				h.i = m1 + 1
			}
		} else {
			if r2 < (r1 / 2.0) {
				h.i = m1 + 1
				h.j = m2
			} else {
				h.i = m1 + 1
				h.j = m2 + 1
			}
		}
	}

	if v.x < 0.0 {
		if h.j%2 == 0 {
			axisi := h.j / 2
			diff := h.i - axisi
			h.i = h.i - 2*diff
		} else {
			axisi := (h.j + 1) / 2
			diff := h.i - axisi
			h.i = h.i - (2*diff + 1)
		}
	}
	if v.y < 0.0 {
		h.i = h.i - (2*h.j+1)/2
		h.j = -h.j
	}
	ijkNormalize(&h)
	return h
}

func ijkToHex2d(h coordIJK) vec2d {
	i := float64(h.i - h.k)
	j := float64(h.j - h.k)
	return vec2d{
		x: i - 0.5*j,
		y: j * sqrt3_2,
	}
}

func geoToClosestFace(g latLng) (face int, sqd float64) {
	v3d := geoToVec3d(g)
	face = 0
	sqd = 5.0
	for f := 0; f < numIcosaFaces; f++ {
		sqdT := pointSquareDist(faceCenterPoint[f], v3d)
		if sqdT < sqd {
			face = f
			sqd = sqdT
		}
	}
	return face, sqd
}

func geoToHex2d(g latLng, res int) (face int, v vec2d) {
	var sqd float64
	face, sqd = geoToClosestFace(g)
	arg := 1 - sqd/2
	if arg > 1 {
		arg = 1
	} else if arg < -1 {
		arg = -1
	}
	r := math.Acos(arg)
	if r < h3Epsilon {
		return face, vec2d{}
	}
	theta := posAngleRads(faceAxesAzRadsCII[face][0] - posAngleRads(geoAzimuthRads(faceCenterGeo[face], g)))
	if isResolutionClassIII(res) {
		theta = posAngleRads(theta - ap7RotRads)
	}
	r = math.Tan(r) / res0UGnomonic
	for i := 0; i < res; i++ {
		r *= sqrt7
	}
	return face, vec2d{x: r * math.Cos(theta), y: r * math.Sin(theta)}
}

func hex2dToGeo(v vec2d, face, res int, substrate bool) latLng {
	r := v2dMag(v)
	if r < h3Epsilon {
		return faceCenterGeo[face]
	}
	theta := math.Atan2(v.y, v.x)
	for i := 0; i < res; i++ {
		r /= sqrt7
	}
	if substrate {
		r /= 3.0
		if isResolutionClassIII(res) {
			r /= sqrt7
		}
	}
	r = math.Atan(r * res0UGnomonic)
	if !substrate && isResolutionClassIII(res) {
		theta = posAngleRads(theta + ap7RotRads)
	}
	theta = posAngleRads(faceAxesAzRadsCII[face][0] - theta)
	return geoAzDistanceRads(faceCenterGeo[face], theta, r)
}

func geoToFaceIjk(g latLng, res int) faceIJK {
	face, v := geoToHex2d(g, res)
	return faceIJK{face: face, coord: hex2dToCoordIJK(v)}
}

func faceIjkToGeo(h faceIJK, res int) latLng {
	v := ijkToHex2d(h.coord)
	return hex2dToGeo(v, h.face, res, false)
}

func baseCellIsCwOffset(baseCell, testFace int) bool {
	return baseCellData[baseCell].cwOffsetPent[0] == testFace ||
		baseCellData[baseCell].cwOffsetPent[1] == testFace
}

func faceIjkToH3(fijk faceIJK, res int) uint64 {
	h := h3Init
	h = h3SetMode(h, h3CellMode)
	h = h3SetResolution(h, res)

	if res == 0 {
		if fijk.coord.i > maxFaceCoord || fijk.coord.j > maxFaceCoord || fijk.coord.k > maxFaceCoord {
			return 0
		}
		bc := faceIjkBaseCells[fijk.face][fijk.coord.i][fijk.coord.j][fijk.coord.k].baseCell
		return h3SetBaseCell(h, bc)
	}

	fijkBC := fijk
	ijk := &fijkBC.coord
	for r := res - 1; r >= 0; r-- {
		lastIJK := *ijk
		var lastCenter coordIJK
		if isResolutionClassIII(r + 1) {
			upAp7(ijk)
			lastCenter = *ijk
			downAp7(&lastCenter)
		} else {
			upAp7r(ijk)
			lastCenter = *ijk
			downAp7r(&lastCenter)
		}
		diff := ijkSub(lastIJK, lastCenter)
		ijkNormalize(&diff)
		h = h3SetIndexDigit(h, r+1, unitIjkToDigit(diff))
	}

	if fijkBC.coord.i > maxFaceCoord || fijkBC.coord.j > maxFaceCoord || fijkBC.coord.k > maxFaceCoord {
		return 0
	}
	entry := faceIjkBaseCells[fijkBC.face][fijkBC.coord.i][fijkBC.coord.j][fijkBC.coord.k]
	baseCell := entry.baseCell
	h = h3SetBaseCell(h, baseCell)
	numRots := entry.ccwRot60

	if isBaseCellPentagon(baseCell) {
		if h3LeadingNonZeroDigit(h) == kAxesDigit {
			if baseCellIsCwOffset(baseCell, fijkBC.face) {
				h = h3Rotate60cw(h)
			} else {
				h = h3Rotate60ccw(h)
			}
		}
		for i := 0; i < numRots; i++ {
			h = h3RotatePent60ccw(h)
		}
	} else {
		for i := 0; i < numRots; i++ {
			h = h3Rotate60ccw(h)
		}
	}
	return h
}

func adjustOverageClassII(fijk *faceIJK, res int, pentLeading4, substrate bool) int {
	ijk := &fijk.coord
	maxDim := maxDimByCIIres[res]
	if substrate {
		maxDim *= 3
	}
	if substrate && ijk.i+ijk.j+ijk.k == maxDim {
		return overageFaceEdge
	}
	if ijk.i+ijk.j+ijk.k > maxDim {
		var fijkOrient faceOrientIJK
		if ijk.k > 0 {
			if ijk.j > 0 {
				fijkOrient = faceNeighbors[fijk.face][overageJK]
			} else {
				fijkOrient = faceNeighbors[fijk.face][overageKI]
				if pentLeading4 {
					origin := coordIJK{i: maxDim}
					tmp := ijkSub(*ijk, origin)
					ijkRotate60cw(&tmp)
					*ijk = ijkAdd(tmp, origin)
				}
			}
		} else {
			fijkOrient = faceNeighbors[fijk.face][overageIJ]
		}
		fijk.face = fijkOrient.face
		for i := 0; i < fijkOrient.ccwRot60; i++ {
			ijkRotate60ccw(ijk)
		}
		transVec := fijkOrient.translate
		unitScale := unitScaleByCIIres[res]
		if substrate {
			unitScale *= 3
		}
		ijkScale(&transVec, unitScale)
		*ijk = ijkAdd(*ijk, transVec)
		ijkNormalize(ijk)
		if substrate && ijk.i+ijk.j+ijk.k == maxDim {
			return overageFaceEdge
		}
		return overageNewFace
	}
	return overageNone
}

func adjustPentVertOverage(fijk *faceIJK, res int) int {
	for {
		overage := adjustOverageClassII(fijk, res, false, true)
		if overage != overageNewFace {
			return overage
		}
	}
}

func h3ToFaceIjkWithInitializedFijk(h uint64, fijk *faceIJK) bool {
	ijk := &fijk.coord
	res := h3GetResolution(h)
	possibleOverage := isBaseCellPentagon(h3GetBaseCell(h)) || (res != 0 && (fijk.coord.i != 0 || fijk.coord.j != 0 || fijk.coord.k != 0))
	for r := 1; r <= res; r++ {
		if isResolutionClassIII(r) {
			downAp7(ijk)
		} else {
			downAp7r(ijk)
		}
		neighborIJK(ijk, h3GetIndexDigit(h, r))
	}
	return possibleOverage
}

func h3ToFaceIjk(h uint64) (faceIJK, error) {
	baseCell := h3GetBaseCell(h)
	if baseCell < 0 || baseCell >= numBaseCells {
		return faceIJK{}, ErrInvalidCell
	}
	if isBaseCellPentagon(baseCell) && h3LeadingNonZeroDigit(h) == 5 {
		h = h3Rotate60cw(h)
	}
	fijk := baseCellData[baseCell].homeFijk
	if !h3ToFaceIjkWithInitializedFijk(h, &fijk) {
		return fijk, nil
	}
	origIJK := fijk.coord
	res := h3GetResolution(h)
	origRes := res
	if isResolutionClassIII(res) {
		downAp7r(&fijk.coord)
		res++
	}
	pentLeading4 := isBaseCellPentagon(baseCell) && h3LeadingNonZeroDigit(h) == 4
	if adjustOverageClassII(&fijk, res, pentLeading4, false) != overageNone {
		if isBaseCellPentagon(baseCell) {
			for adjustOverageClassII(&fijk, res, false, false) != overageNone {
			}
		}
		if res != origRes {
			upAp7r(&fijk.coord)
		}
	} else if res != origRes {
		fijk.coord = origIJK
	}
	return fijk, nil
}

// LatLonToCell encodes decimal degrees (lat, lon) at resolution res (0..15) into an H3 cell index.
func LatLonToCell(lat, lon float64, res int) (uint64, error) {
	if res < 0 || res > MaxRes {
		return 0, fmt.Errorf("%w: %d", ErrInvalidResolution, res)
	}
	if math.IsNaN(lat) || math.IsInf(lat, 0) || math.IsNaN(lon) || math.IsInf(lon, 0) {
		return 0, fmt.Errorf("%w: (%v, %v)", ErrInvalidCoordinate, lat, lon)
	}
	g := latLng{lat: degsToRads(lat), lng: degsToRads(lon)}
	fijk := geoToFaceIjk(g, res)
	h := faceIjkToH3(fijk, res)
	if h == 0 {
		return 0, ErrInvalidCell
	}
	return h, nil
}

// CellToLatLon returns the center coordinate (lat, lon) in decimal degrees of cell h.
// Returns (0, 0) if h is invalid.
func CellToLatLon(h uint64) (lat, lon float64) {
	if !IsValidCell(h) {
		return 0, 0
	}
	fijk, err := h3ToFaceIjk(h)
	if err != nil {
		return 0, 0
	}
	g := faceIjkToGeo(fijk, h3GetResolution(h))
	return radsToDegs(g.lat), radsToDegs(g.lng)
}

func faceIjkToVerts(fijk *faceIJK, res *int) [numHexVerts]faceIJK {
	vertsCII := [numHexVerts]coordIJK{
		{2, 1, 0},
		{1, 2, 0},
		{0, 2, 1},
		{0, 1, 2},
		{1, 0, 2},
		{2, 0, 1},
	}
	vertsCIII := [numHexVerts]coordIJK{
		{5, 4, 0},
		{1, 5, 0},
		{0, 5, 4},
		{0, 1, 5},
		{4, 0, 5},
		{5, 0, 1},
	}
	verts := vertsCII
	if isResolutionClassIII(*res) {
		verts = vertsCIII
	}
	downAp3(&fijk.coord)
	downAp3r(&fijk.coord)
	if isResolutionClassIII(*res) {
		downAp7r(&fijk.coord)
		*res++
	}
	var out [numHexVerts]faceIJK
	for v := 0; v < numHexVerts; v++ {
		out[v].face = fijk.face
		out[v].coord = ijkAdd(fijk.coord, verts[v])
		ijkNormalize(&out[v].coord)
	}
	return out
}

func faceIjkPentToVerts(fijk *faceIJK, res *int) [numPentVerts]faceIJK {
	vertsCII := [numPentVerts]coordIJK{
		{2, 1, 0},
		{1, 2, 0},
		{0, 2, 1},
		{0, 1, 2},
		{1, 0, 2},
	}
	vertsCIII := [numPentVerts]coordIJK{
		{5, 4, 0},
		{1, 5, 0},
		{0, 5, 4},
		{0, 1, 5},
		{4, 0, 5},
	}
	verts := vertsCII
	if isResolutionClassIII(*res) {
		verts = vertsCIII
	}
	downAp3(&fijk.coord)
	downAp3r(&fijk.coord)
	if isResolutionClassIII(*res) {
		downAp7r(&fijk.coord)
		*res++
	}
	var out [numPentVerts]faceIJK
	for v := 0; v < numPentVerts; v++ {
		out[v].face = fijk.face
		out[v].coord = ijkAdd(fijk.coord, verts[v])
		ijkNormalize(&out[v].coord)
	}
	return out
}

// CellToBoundary returns the polygon boundary vertices [lat, lon] in decimal degrees for cell h.
// Returns nil if h is invalid.
func CellToBoundary(h uint64) [][2]float64 {
	if !IsValidCell(h) {
		return nil
	}
	fijk, err := h3ToFaceIjk(h)
	if err != nil {
		return nil
	}
	res := h3GetResolution(h)
	if isPentagonUnchecked(h) {
		return faceIjkPentToCellBoundary(fijk, res)
	}
	return faceIjkToCellBoundary(fijk, res)
}

func faceIjkPentToCellBoundary(center faceIJK, res int) [][2]float64 {
	adjRes := res
	centerIJK := center
	fijkVerts := faceIjkPentToVerts(&centerIJK, &adjRes)

	boundary := make([][2]float64, 0, 10)
	var lastFijk faceIJK
	for vert := 0; vert < numPentVerts+1; vert++ {
		v := vert % numPentVerts
		fijk := fijkVerts[v]
		adjustPentVertOverage(&fijk, adjRes)

		if isResolutionClassIII(res) && vert > 0 {
			tmpFijk := fijk
			orig2d0 := ijkToHex2d(lastFijk.coord)
			currentToLastDir := adjacentFaceDir[tmpFijk.face][lastFijk.face]
			if currentToLastDir != invalidFace {
				fijkOrient := faceNeighbors[tmpFijk.face][currentToLastDir]
				tmpFijk.face = fijkOrient.face
				ijk := &tmpFijk.coord
				for i := 0; i < fijkOrient.ccwRot60; i++ {
					ijkRotate60ccw(ijk)
				}
				transVec := fijkOrient.translate
				ijkScale(&transVec, unitScaleByCIIres[adjRes]*3)
				*ijk = ijkAdd(*ijk, transVec)
				ijkNormalize(ijk)

				orig2d1 := ijkToHex2d(*ijk)
				maxDim := float64(maxDimByCIIres[adjRes])
				v0 := vec2d{3.0 * maxDim, 0.0}
				v1 := vec2d{-1.5 * maxDim, 3.0 * sqrt3_2 * maxDim}
				v2 := vec2d{-1.5 * maxDim, -3.0 * sqrt3_2 * maxDim}

				var edge0, edge1 vec2d
				switch adjacentFaceDir[tmpFijk.face][fijk.face] {
				case overageIJ:
					edge0, edge1 = v0, v1
				case overageJK:
					edge0, edge1 = v1, v2
				default:
					edge0, edge1 = v2, v0
				}
				inter := v2dIntersect(orig2d0, orig2d1, edge0, edge1)
				pt := hex2dToGeo(inter, tmpFijk.face, adjRes, true)
				boundary = append(boundary, [2]float64{radsToDegs(pt.lat), radsToDegs(pt.lng)})
			}
		}

		if vert < numPentVerts {
			vec := ijkToHex2d(fijk.coord)
			pt := hex2dToGeo(vec, fijk.face, adjRes, true)
			boundary = append(boundary, [2]float64{radsToDegs(pt.lat), radsToDegs(pt.lng)})
		}
		lastFijk = fijk
	}
	return boundary
}

func faceIjkToCellBoundary(center faceIJK, res int) [][2]float64 {
	adjRes := res
	centerIJK := center
	fijkVerts := faceIjkToVerts(&centerIJK, &adjRes)

	boundary := make([][2]float64, 0, 7)
	lastFace := -1
	lastOverage := overageNone
	for vert := 0; vert < numHexVerts+1; vert++ {
		v := vert % numHexVerts
		fijk := fijkVerts[v]
		overage := adjustOverageClassII(&fijk, adjRes, false, true)

		if isResolutionClassIII(res) && vert > 0 && fijk.face != lastFace && lastOverage != overageFaceEdge {
			lastV := (v + 5) % numHexVerts
			orig2d0 := ijkToHex2d(fijkVerts[lastV].coord)
			orig2d1 := ijkToHex2d(fijkVerts[v].coord)

			maxDim := float64(maxDimByCIIres[adjRes])
			v0 := vec2d{3.0 * maxDim, 0.0}
			v1 := vec2d{-1.5 * maxDim, 3.0 * sqrt3_2 * maxDim}
			v2 := vec2d{-1.5 * maxDim, -3.0 * sqrt3_2 * maxDim}

			face2 := fijk.face
			if lastFace != centerIJK.face {
				face2 = lastFace
			}
			var edge0, edge1 vec2d
			switch adjacentFaceDir[centerIJK.face][face2] {
			case overageIJ:
				edge0, edge1 = v0, v1
			case overageJK:
				edge0, edge1 = v1, v2
			default:
				edge0, edge1 = v2, v0
			}
			inter := v2dIntersect(orig2d0, orig2d1, edge0, edge1)
			if !v2dAlmostEquals(orig2d0, inter) && !v2dAlmostEquals(orig2d1, inter) {
				pt := hex2dToGeo(inter, centerIJK.face, adjRes, true)
				boundary = append(boundary, [2]float64{radsToDegs(pt.lat), radsToDegs(pt.lng)})
			}
		}

		if vert < numHexVerts {
			vec := ijkToHex2d(fijk.coord)
			pt := hex2dToGeo(vec, fijk.face, adjRes, true)
			boundary = append(boundary, [2]float64{radsToDegs(pt.lat), radsToDegs(pt.lng)})
		}
		lastFace = fijk.face
		lastOverage = overage
	}
	return boundary
}

// CellToParent returns the ancestor cell index of h at parentRes.
func CellToParent(h uint64, parentRes int) (uint64, error) {
	if !IsValidCell(h) {
		return 0, ErrInvalidCell
	}
	childRes := h3GetResolution(h)
	if parentRes < 0 || parentRes > MaxRes {
		return 0, fmt.Errorf("%w: %d", ErrInvalidResolution, parentRes)
	}
	if parentRes > childRes {
		return 0, fmt.Errorf("%w: parent %d > child %d", ErrResolutionMismatch, parentRes, childRes)
	}
	if parentRes == childRes {
		return h, nil
	}
	parentH := h3SetResolution(h, parentRes)
	for r := parentRes + 1; r <= childRes; r++ {
		parentH = h3SetIndexDigit(parentH, r, int(h3DigitMask))
	}
	return parentH, nil
}

func zeroIndexDigits(h uint64, start, end int) uint64 {
	if start > end {
		return h
	}
	m := ^uint64(0)
	m <<= uint(h3PerDigitOffset * (end - start + 1))
	m = ^m
	m <<= uint(h3PerDigitOffset * (MaxRes - end))
	m = ^m
	return h & m
}

// CellToCenterChild returns the center child cell index of h at childRes.
func CellToCenterChild(h uint64, childRes int) (uint64, error) {
	if !IsValidCell(h) {
		return 0, ErrInvalidCell
	}
	parentRes := h3GetResolution(h)
	if childRes < parentRes || childRes > MaxRes {
		return 0, fmt.Errorf("%w: child %d for parent %d", ErrInvalidResolution, childRes, parentRes)
	}
	out := zeroIndexDigits(h, parentRes+1, childRes)
	return h3SetResolution(out, childRes), nil
}

func ipow7(n int) int64 {
	res := int64(1)
	for i := 0; i < n; i++ {
		res *= 7
	}
	return res
}

type iterCellsChildren struct {
	h         uint64
	parentRes int
	skipDigit int
}

func iterInitParent(h uint64, childRes int) iterCellsChildren {
	parentRes := h3GetResolution(h)
	if childRes < parentRes || childRes > MaxRes || h == 0 {
		return iterCellsChildren{parentRes: -1, skipDigit: -1}
	}
	cur := h3SetResolution(zeroIndexDigits(h, parentRes+1, childRes), childRes)
	skip := -1
	if isPentagonUnchecked(cur) {
		skip = childRes
	}
	return iterCellsChildren{h: cur, parentRes: parentRes, skipDigit: skip}
}

func (it *iterCellsChildren) incrementResDigit(res int) {
	it.h += uint64(1) << uint(h3PerDigitOffset*(MaxRes-res))
}

func (it *iterCellsChildren) step() {
	if it.h == 0 {
		return
	}
	childRes := h3GetResolution(it.h)
	it.incrementResDigit(childRes)
	for i := childRes; i >= it.parentRes; i-- {
		if i == it.parentRes {
			it.h = 0
			it.parentRes = -1
			it.skipDigit = -1
			return
		}
		digit := h3GetIndexDigit(it.h, i)
		if i == it.skipDigit && digit == pentSkipDigit {
			it.incrementResDigit(i)
			it.skipDigit--
			return
		}
		if digit == invalidDigit {
			it.incrementResDigit(i)
		} else {
			break
		}
	}
}

// CellToChildren returns all child cells of h at childRes.
func CellToChildren(h uint64, childRes int) ([]uint64, error) {
	if !IsValidCell(h) {
		return nil, ErrInvalidCell
	}
	parentRes := h3GetResolution(h)
	if childRes < parentRes || childRes > MaxRes {
		return nil, fmt.Errorf("%w: child %d for parent %d", ErrInvalidResolution, childRes, parentRes)
	}
	diff := childRes - parentRes
	if diff > 8 {
		return nil, fmt.Errorf("%w: child resolution gap %d too large", ErrCellLimitExceeded, diff)
	}
	var count int64
	p7 := ipow7(diff)
	if isPentagonUnchecked(h) {
		count = 1 + 5*(p7-1)/6
	} else {
		count = p7
	}
	out := make([]uint64, 0, count)
	for it := iterInitParent(h, childRes); it.h != 0; it.step() {
		out = append(out, it.h)
	}
	return out, nil
}

func h3NeighborRotations(origin uint64, dir int, rotations *int) (uint64, error) {
	current := origin
	if dir < centerDigit || dir >= invalidDigit {
		return 0, ErrInvalidCell
	}
	*rotations = *rotations % 6
	for i := 0; i < *rotations; i++ {
		dir = rotate60ccw(dir)
	}
	newRotations := 0
	oldBaseCell := h3GetBaseCell(current)
	if oldBaseCell < 0 || oldBaseCell >= numBaseCells {
		return 0, ErrInvalidCell
	}
	oldLeadingDigit := h3LeadingNonZeroDigit(current)

	r := h3GetResolution(current) - 1
	for {
		if r == -1 {
			nextBC := baseCellNeighbors[oldBaseCell][dir]
			newRotations = baseCellNeighbor60CCWRots[oldBaseCell][dir]
			if nextBC == invalidBaseCell {
				nextBC = baseCellNeighbors[oldBaseCell][ikAxesDigit]
				newRotations = baseCellNeighbor60CCWRots[oldBaseCell][ikAxesDigit]
				current = h3Rotate60ccw(current)
				*rotations++
			}
			current = h3SetBaseCell(current, nextBC)
			break
		}
		oldDigit := h3GetIndexDigit(current, r+1)
		if oldDigit == invalidDigit {
			return 0, ErrInvalidCell
		}
		var nextDir int
		if isResolutionClassIII(r + 1) {
			current = h3SetIndexDigit(current, r+1, newDigitII[oldDigit][dir])
			nextDir = newAdjustmentII[oldDigit][dir]
		} else {
			current = h3SetIndexDigit(current, r+1, newDigitIII[oldDigit][dir])
			nextDir = newAdjustmentIII[oldDigit][dir]
		}
		if nextDir != centerDigit {
			dir = nextDir
			r--
		} else {
			break
		}
	}

	newBaseCell := h3GetBaseCell(current)
	if isBaseCellPentagon(newBaseCell) {
		alreadyAdjustedK := false
		if h3LeadingNonZeroDigit(current) == kAxesDigit {
			if oldBaseCell != newBaseCell {
				if baseCellIsCwOffset(newBaseCell, baseCellData[oldBaseCell].homeFijk.face) {
					current = h3Rotate60cw(current)
				} else {
					current = h3Rotate60ccw(current)
				}
				alreadyAdjustedK = true
			} else {
				switch oldLeadingDigit {
				case centerDigit:
					return 0, errPentagonNeighbor
				case jkAxesDigit:
					current = h3Rotate60ccw(current)
					*rotations++
				case ikAxesDigit:
					current = h3Rotate60cw(current)
					*rotations += 5
				default:
					return 0, ErrInvalidCell
				}
			}
		}
		for i := 0; i < newRotations; i++ {
			current = h3RotatePent60ccw(current)
		}
		if oldBaseCell != newBaseCell {
			if isBaseCellPolarPentagon(newBaseCell) {
				if oldBaseCell != 118 && oldBaseCell != 8 && h3LeadingNonZeroDigit(current) != jkAxesDigit {
					*rotations++
				}
			} else if h3LeadingNonZeroDigit(current) == ikAxesDigit && !alreadyAdjustedK {
				*rotations++
			}
		}
	} else {
		for i := 0; i < newRotations; i++ {
			current = h3Rotate60ccw(current)
		}
	}
	*rotations = (*rotations + newRotations) % 6
	return current, nil
}

// GridDisk returns all cells within grid distance k of cell h (including h).
// Returns nil if h is invalid or k < 0.
func GridDisk(h uint64, k int) []uint64 {
	if !IsValidCell(h) || k < 0 {
		return nil
	}
	if k == 0 {
		return []uint64{h}
	}
	// Try fast hexagonal spiral when no pentagon distortion is encountered.
	if fast, ok := gridDiskUnsafe(h, k); ok {
		return fast
	}
	// Safe BFS handling pentagons and distortion regions without recursion overflow.
	type node struct {
		cell uint64
		dist int
	}
	visited := map[uint64]struct{}{h: {}}
	queue := []node{{cell: h, dist: 0}}
	out := []uint64{h}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if cur.dist >= k {
			continue
		}
		for _, d := range ringDirections {
			rot := 0
			nbr, err := h3NeighborRotations(cur.cell, d, &rot)
			if err != nil {
				continue
			}
			if _, seen := visited[nbr]; seen {
				continue
			}
			visited[nbr] = struct{}{}
			out = append(out, nbr)
			queue = append(queue, node{cell: nbr, dist: cur.dist + 1})
		}
	}
	return out
}

func gridDiskUnsafe(origin uint64, k int) ([]uint64, bool) {
	if isPentagonUnchecked(origin) {
		return nil, false
	}
	maxSize := 1 + 3*k*(k+1)
	if maxSize > maxGridCellsLimit {
		return nil, false
	}
	out := make([]uint64, 0, maxSize)
	out = append(out, origin)
	cur := origin
	rotations := 0
	for ring := 1; ring <= k; ring++ {
		nextOrigin, err := h3NeighborRotations(cur, iAxesDigit, &rotations)
		if err != nil || isPentagonUnchecked(nextOrigin) {
			return nil, false
		}
		cur = nextOrigin
		for i := 0; i < 6; i++ {
			for j := 0; j < ring; j++ {
				out = append(out, cur)
				next, err := h3NeighborRotations(cur, ringDirections[i], &rotations)
				if err != nil || isPentagonUnchecked(next) {
					return nil, false
				}
				cur = next
			}
		}
	}
	return out, true
}

func getRes0Cells() []uint64 {
	out := make([]uint64, numBaseCells)
	for bc := 0; bc < numBaseCells; bc++ {
		h := h3Init
		h = h3SetMode(h, h3CellMode)
		h = h3SetBaseCell(h, bc)
		out[bc] = h
	}
	return out
}

func getPentagons(res int) [numPentagons]uint64 {
	var out [numPentagons]uint64
	idx := 0
	for bc := 0; bc < numBaseCells; bc++ {
		if baseCellData[bc].isPentagon {
			h := h3Init
			h = h3SetMode(h, h3CellMode)
			h = h3SetResolution(h, res)
			h = h3SetBaseCell(h, bc)
			for r := 1; r <= res; r++ {
				h = h3SetIndexDigit(h, r, 0)
			}
			out[idx] = h
			idx++
		}
	}
	return out
}

func hexRadiusKm(h uint64) float64 {
	cLat, cLon := CellToLatLon(h)
	verts := CellToBoundary(h)
	if len(verts) == 0 {
		return 0
	}
	c := latLng{lat: degsToRads(cLat), lng: degsToRads(cLon)}
	v := latLng{lat: degsToRads(verts[0][0]), lng: degsToRads(verts[0][1])}
	return greatCircleDistanceKm(c, v)
}

type geoBBox struct {
	north float64
	south float64
	east  float64
	west  float64
}

func (b geoBBox) isTransmeridian() bool { return b.east < b.west }

func (b geoBBox) contains(p latLng) bool {
	if p.lat < b.south || p.lat > b.north {
		return false
	}
	if b.isTransmeridian() {
		return p.lng >= b.west || p.lng <= b.east
	}
	return p.lng >= b.west && p.lng <= b.east
}

func normalizeLngForBBox(lng float64, isTransmeridian bool) float64 {
	if isTransmeridian && lng < 0 {
		return lng + twoPi
	}
	return lng
}

func loopToRads(pts [][2]float64) []latLng {
	if len(pts) == 0 {
		return nil
	}
	// Strip duplicate closing vertex if present.
	n := len(pts)
	if n > 1 && pts[0][0] == pts[n-1][0] && pts[0][1] == pts[n-1][1] {
		n--
	}
	out := make([]latLng, n)
	for i := 0; i < n; i++ {
		out[i] = latLng{lat: degsToRads(pts[i][0]), lng: degsToRads(pts[i][1])}
	}
	return out
}

func bboxFromLoop(loop []latLng) geoBBox {
	if len(loop) == 0 {
		return geoBBox{}
	}
	b := geoBBox{
		south: math.MaxFloat64,
		west:  math.MaxFloat64,
		north: -math.MaxFloat64,
		east:  -math.MaxFloat64,
	}
	minPosLng := math.MaxFloat64
	maxNegLng := -math.MaxFloat64
	isTrans := false
	for i, coord := range loop {
		next := loop[(i+1)%len(loop)]
		if coord.lat < b.south {
			b.south = coord.lat
		}
		if coord.lng < b.west {
			b.west = coord.lng
		}
		if coord.lat > b.north {
			b.north = coord.lat
		}
		if coord.lng > b.east {
			b.east = coord.lng
		}
		if coord.lng > 0 && coord.lng < minPosLng {
			minPosLng = coord.lng
		}
		if coord.lng < 0 && coord.lng > maxNegLng {
			maxNegLng = coord.lng
		}
		if math.Abs(coord.lng-next.lng) > pi {
			isTrans = true
		}
	}
	if isTrans {
		b.east = maxNegLng
		b.west = minPosLng
	}
	return b
}

func pointInsideLoop(loop []latLng, b geoBBox, coord latLng) bool {
	if !b.contains(coord) || len(loop) < 3 {
		return false
	}
	isTrans := b.isTransmeridian()
	contains := false
	lat := coord.lat
	lng := normalizeLngForBBox(coord.lng, isTrans)
	for i := 0; i < len(loop); i++ {
		a := loop[i]
		c := loop[(i+1)%len(loop)]
		if a.lat > c.lat {
			a, c = c, a
		}
		if lat == a.lat || lat == c.lat {
			lat += dblEpsilon
		}
		if lat < a.lat || lat > c.lat {
			continue
		}
		aLng := normalizeLngForBBox(a.lng, isTrans)
		cLng := normalizeLngForBBox(c.lng, isTrans)
		if aLng == lng || cLng == lng {
			lng -= dblEpsilon
		}
		ratio := (lat - a.lat) / (c.lat - a.lat)
		testLng := normalizeLngForBBox(aLng+(cLng-aLng)*ratio, isTrans)
		if testLng > lng {
			contains = !contains
		}
	}
	return contains
}

func pointInsidePolygonLoops(outer []latLng, outerBox geoBBox, holes [][]latLng, holeBoxes []geoBBox, coord latLng) bool {
	if !pointInsideLoop(outer, outerBox, coord) {
		return false
	}
	for i, h := range holes {
		if pointInsideLoop(h, holeBoxes[i], coord) {
			return false
		}
	}
	return true
}

func lineHexEstimateCount(origin, dest latLng, pentRadiusKm float64) int64 {
	if pentRadiusKm <= 0 {
		return 1
	}
	dist := greatCircleDistanceKm(origin, dest)
	est := int64(math.Ceil(dist / (2 * pentRadiusKm)))
	if est < 1 {
		return 1
	}
	return est
}

// PolygonToCells implements Uber H3 polygonToCells semantics, returning all H3 cells
// at resolution res whose center point is contained inside outer and outside holes.
// Coordinates are decimal degree [lat, lon] pairs.
func PolygonToCells(outer [][2]float64, holes [][][2]float64, res int) ([]uint64, error) {
	if res < 0 || res > MaxRes {
		return nil, fmt.Errorf("%w: %d", ErrInvalidResolution, res)
	}
	outerLoop := loopToRads(outer)
	if len(outerLoop) < 3 {
		return nil, nil
	}
	holeLoops := make([][]latLng, 0, len(holes))
	holeBoxes := make([]geoBBox, 0, len(holes))
	for _, hole := range holes {
		hl := loopToRads(hole)
		if len(hl) >= 3 {
			holeLoops = append(holeLoops, hl)
			holeBoxes = append(holeBoxes, bboxFromLoop(hl))
		}
	}
	outerBox := bboxFromLoop(outerLoop)

	pents := getPentagons(res)
	pentRadiusKm := hexRadiusKm(pents[0])

	searchSet := make(map[uint64]struct{})
	traceLoop := func(loop []latLng) error {
		for i := 0; i < len(loop); i++ {
			o := loop[i]
			d := loop[(i+1)%len(loop)]
			steps := lineHexEstimateCount(o, d, pentRadiusKm)
			if steps > maxGridCellsLimit {
				return ErrCellLimitExceeded
			}
			for j := int64(0); j < steps; j++ {
				t0 := float64(steps-j) / float64(steps)
				t1 := float64(j) / float64(steps)
				lat := o.lat*t0 + d.lat*t1
				lng := o.lng*t0 + d.lng*t1
				h, err := LatLonToCell(radsToDegs(lat), radsToDegs(lng), res)
				if err != nil {
					return err
				}
				searchSet[h] = struct{}{}
			}
		}
		return nil
	}
	if err := traceLoop(outerLoop); err != nil {
		return nil, err
	}
	for _, hl := range holeLoops {
		if err := traceLoop(hl); err != nil {
			return nil, err
		}
	}

	outSet := make(map[uint64]struct{})
	queue := make([]uint64, 0, len(searchSet))
	for h := range searchSet {
		queue = append(queue, h)
	}
	for len(queue) > 0 {
		nextQueue := make([]uint64, 0)
		for _, searchHex := range queue {
			ring := GridDisk(searchHex, 1)
			for _, hex := range ring {
				if _, exists := outSet[hex]; exists {
					continue
				}
				cLat, cLon := CellToLatLon(hex)
				if !pointInsidePolygonLoops(outerLoop, outerBox, holeLoops, holeBoxes, latLng{lat: degsToRads(cLat), lng: degsToRads(cLon)}) {
					continue
				}
				outSet[hex] = struct{}{}
				if len(outSet) > maxGridCellsLimit {
					return nil, ErrCellLimitExceeded
				}
				nextQueue = append(nextQueue, hex)
			}
		}
		queue = nextQueue
	}

	out := make([]uint64, 0, len(outSet))
	for h := range outSet {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// PolygonIntersectingCells returns all H3 cells at resolution res that intersect
// (contain part of or lie inside) the polygon defined by outer and optional holes.
func PolygonIntersectingCells(outer [][2]float64, holes [][][2]float64, res int) ([]uint64, error) {
	if res < 0 || res > MaxRes {
		return nil, fmt.Errorf("%w: %d", ErrInvalidResolution, res)
	}
	outerLoop := loopToRads(outer)
	if len(outerLoop) < 3 {
		return nil, nil
	}
	holeLoops := make([][]latLng, 0, len(holes))
	holeBoxes := make([]geoBBox, 0, len(holes))
	for _, hole := range holes {
		hl := loopToRads(hole)
		if len(hl) >= 3 {
			holeLoops = append(holeLoops, hl)
			holeBoxes = append(holeBoxes, bboxFromLoop(hl))
		}
	}
	outerBox := bboxFromLoop(outerLoop)

	pents := getPentagons(res)
	pentRadiusKm := hexRadiusKm(pents[0])

	outSet := make(map[uint64]struct{})
	outerEdgeCells := make(map[uint64]struct{})
	visited := make(map[uint64]struct{})
	queue := make([]uint64, 0)
	addSeed := func(h uint64) {
		if _, ok := visited[h]; !ok {
			visited[h] = struct{}{}
			queue = append(queue, h)
		}
	}

	// Seed with all cells traced along outer and hole boundaries plus center-contained cells.
	centerCells, err := PolygonToCells(outer, holes, res)
	if err != nil {
		return nil, err
	}
	for _, h := range centerCells {
		outSet[h] = struct{}{}
		addSeed(h)
	}

	traceBoundary := func(loop []latLng, isOuter bool) error {
		for i := 0; i < len(loop); i++ {
			o := loop[i]
			d := loop[(i+1)%len(loop)]
			steps := lineHexEstimateCount(o, d, pentRadiusKm*0.5)
			if steps > maxGridCellsLimit {
				return ErrCellLimitExceeded
			}
			for j := int64(0); j <= steps; j++ {
				t0 := float64(steps-j) / float64(steps)
				t1 := float64(j) / float64(steps)
				lat := o.lat*t0 + d.lat*t1
				lng := o.lng*t0 + d.lng*t1
				h, err := LatLonToCell(radsToDegs(lat), radsToDegs(lng), res)
				if err != nil {
					return err
				}
				if isOuter {
					outerEdgeCells[h] = struct{}{}
				}
				addSeed(h)
			}
		}
		return nil
	}
	if err := traceBoundary(outerLoop, true); err != nil {
		return nil, err
	}
	for _, hl := range holeLoops {
		if err := traceBoundary(hl, false); err != nil {
			return nil, err
		}
	}

	cellIntersects := func(h uint64) bool {
		if _, ok := outSet[h]; ok {
			return true
		}
		if _, ok := outerEdgeCells[h]; ok {
			return true
		}
		cLat, cLon := CellToLatLon(h)
		if pointInsidePolygonLoops(outerLoop, outerBox, holeLoops, holeBoxes, latLng{lat: degsToRads(cLat), lng: degsToRads(cLon)}) {
			return true
		}
		verts := CellToBoundary(h)
		for _, v := range verts {
			if pointInsidePolygonLoops(outerLoop, outerBox, holeLoops, holeBoxes, latLng{lat: degsToRads(v[0]), lng: degsToRads(v[1])}) {
				return true
			}
		}
		// Check edge-edge intersections against outer loop and holes (shifted cleanly around cell center lon).
		if cellEdgesIntersectLoops(cLon, verts, outer, holes) {
			return true
		}
		return false
	}

	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if !cellIntersects(cur) {
			continue
		}
		outSet[cur] = struct{}{}
		if len(outSet) > maxGridCellsLimit {
			return nil, ErrCellLimitExceeded
		}
		for _, nbr := range GridDisk(cur, 1) {
			addSeed(nbr)
		}
	}

	out := make([]uint64, 0, len(outSet))
	for h := range outSet {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func unwrapDegLon(lon, refLon float64) float64 {
	d := lon - refLon
	for d > 180 {
		lon -= 360
		d -= 360
	}
	for d < -180 {
		lon += 360
		d += 360
	}
	return lon
}

func unwrapPolygonAround(pts [][2]float64, refLon float64) [][2]float64 {
	if len(pts) == 0 {
		return nil
	}
	out := make([][2]float64, len(pts))
	curRef := unwrapDegLon(pts[0][1], refLon)
	out[0] = [2]float64{pts[0][0], curRef}
	for i := 1; i < len(pts); i++ {
		curRef = unwrapDegLon(pts[i][1], curRef)
		out[i] = [2]float64{pts[i][0], curRef}
	}
	return out
}

func orient2D(ax, ay, bx, by, cx, cy float64) float64 {
	return (bx-ax)*(cy-ay) - (by-ay)*(cx-ax)
}

func segmentsIntersectDeg(ax, ay, bx, by, cx, cy, dx, dy float64) bool {
	if math.Max(ax, bx) < math.Min(cx, dx) || math.Max(cx, dx) < math.Min(ax, bx) ||
		math.Max(ay, by) < math.Min(cy, dy) || math.Max(cy, dy) < math.Min(ay, by) {
		return false
	}
	o1 := orient2D(ax, ay, bx, by, cx, cy)
	o2 := orient2D(ax, ay, bx, by, dx, dy)
	o3 := orient2D(cx, cy, dx, dy, ax, ay)
	o4 := orient2D(cx, cy, dx, dy, bx, by)
	if ((o1 > 0 && o2 < 0) || (o1 < 0 && o2 > 0)) && ((o3 > 0 && o4 < 0) || (o3 < 0 && o4 > 0)) {
		return true
	}
	onSeg := func(px, py, qx, qy, rx, ry float64) bool {
		return rx >= math.Min(px, qx)-1e-12 && rx <= math.Max(px, qx)+1e-12 &&
			ry >= math.Min(py, qy)-1e-12 && ry <= math.Max(py, qy)+1e-12
	}
	if o1 == 0 && onSeg(ax, ay, bx, by, cx, cy) {
		return true
	}
	if o2 == 0 && onSeg(ax, ay, bx, by, dx, dy) {
		return true
	}
	if o3 == 0 && onSeg(cx, cy, dx, dy, ax, ay) {
		return true
	}
	if o4 == 0 && onSeg(cx, cy, dx, dy, bx, by) {
		return true
	}
	return false
}

func cellEdgesIntersectLoops(cLon float64, cellVerts [][2]float64, outer [][2]float64, holes [][][2]float64) bool {
	if len(cellVerts) < 3 {
		return false
	}
	cv := unwrapPolygonAround(cellVerts, cLon)
	checkLoop := func(ring [][2]float64) bool {
		if len(ring) < 2 {
			return false
		}
		for _, shift := range [3]float64{0, -360, 360} {
			for i := 0; i < len(cv); i++ {
				a := cv[i]
				b := cv[(i+1)%len(cv)]
				for j := 0; j < len(ring); j++ {
					p := ring[j]
					q := ring[(j+1)%len(ring)]
					pLon := unwrapDegLon(p[1], cLon) + shift
					qLon := unwrapDegLon(q[1], pLon)
					if segmentsIntersectDeg(a[1], a[0], b[1], b[0], pLon, p[0], qLon, q[0]) {
						return true
					}
				}
			}
		}
		return false
	}
	if checkLoop(outer) {
		return true
	}
	for _, hole := range holes {
		if checkLoop(hole) {
			return true
		}
	}
	return false
}

// BBoxToCells returns all H3 cells at resolution res intersecting the latitude/longitude
// bounding box [bottomLat, topLat] x [leftLon, rightLon] (in decimal degrees).
// When leftLon > rightLon, the bounding box is treated as crossing the antimeridian.
func BBoxToCells(topLat, leftLon, bottomLat, rightLon float64, res int) ([]uint64, error) {
	if res < 0 || res > MaxRes {
		return nil, fmt.Errorf("%w: %d", ErrInvalidResolution, res)
	}
	if math.IsNaN(topLat) || math.IsInf(topLat, 0) ||
		math.IsNaN(leftLon) || math.IsInf(leftLon, 0) ||
		math.IsNaN(bottomLat) || math.IsInf(bottomLat, 0) ||
		math.IsNaN(rightLon) || math.IsInf(rightLon, 0) {
		return nil, ErrInvalidCoordinate
	}
	if bottomLat > topLat {
		return nil, fmt.Errorf("%w: bottomLat %v > topLat %v", ErrInvalidCoordinate, bottomLat, topLat)
	}
	if topLat > 90 {
		topLat = 90
	}
	if bottomLat < -90 {
		bottomLat = -90
	}
	// Full longitude wrap or global box.
	lonSpan := rightLon - leftLon
	if lonSpan >= 360.0-1e-12 || (leftLon == -180 && rightLon == 180) {
		if res <= 4 && topLat >= 90-1e-12 && bottomLat <= -90+1e-12 {
			out := make([]uint64, 0)
			for _, bc := range getRes0Cells() {
				children, err := CellToChildren(bc, res)
				if err != nil {
					return nil, err
				}
				out = append(out, children...)
			}
			sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
			return out, nil
		}
		// Normalize into a continuous [-180, 180] box.
		leftLon = -180
		rightLon = 180
	} else {
		leftLon = radsToDegs(constrainLng(degsToRads(leftLon)))
		rightLon = radsToDegs(constrainLng(degsToRads(rightLon)))
	}

	if topLat == bottomLat && leftLon == rightLon {
		h, err := LatLonToCell(topLat, leftLon, res)
		if err != nil {
			return nil, err
		}
		return []uint64{h}, nil
	}

	isTrans := leftLon > rightLon
	normBox := func(lon float64) float64 {
		if isTrans && lon < 0 {
			return lon + 360
		}
		return lon
	}
	boxW := leftLon
	boxE := normBox(rightLon)

	inBoxDeg := func(lat, lon float64) bool {
		if lat < bottomLat || lat > topLat {
			return false
		}
		if leftLon == -180 && rightLon == 180 {
			return true
		}
		nl := normBox(lon)
		return nl >= boxW && nl <= boxE
	}

	// Build normalized box rectangle loop(s) to check edge/polygon intersection.
	pointInCell := func(pLat, pLon float64, cv [][2]float64) bool {
		inside := false
		for i := 0; i < len(cv); i++ {
			a := cv[i]
			b := cv[(i+1)%len(cv)]
			if (a[0] > pLat) != (b[0] > pLat) {
				interLon := (b[1]-a[1])*(pLat-a[0])/(b[0]-a[0]) + a[1]
				if pLon < interLon {
					inside = !inside
				}
			}
		}
		return inside
	}

	seededInside := make(map[uint64]struct{})
	cellIntersectsBBox := func(h uint64) bool {
		if _, ok := seededInside[h]; ok {
			return true
		}
		cLat, cLon := CellToLatLon(h)
		if inBoxDeg(cLat, cLon) {
			return true
		}
		verts := CellToBoundary(h)
		for _, v := range verts {
			if inBoxDeg(v[0], v[1]) {
				return true
			}
		}
		cv := unwrapPolygonAround(verts, cLon)
		corners := [4][2]float64{
			{bottomLat, leftLon},
			{bottomLat, rightLon},
			{topLat, rightLon},
			{topLat, leftLon},
		}
		for _, c := range corners {
			for _, shift := range [3]float64{0, -360, 360} {
				if pointInCell(c[0], c[1]+shift, cv) {
					return true
				}
			}
		}
		// Check cell edges against bbox edges in shifted continuous longitude intervals.
		boxIntervals := [][2]float64{{leftLon, rightLon}}
		if isTrans {
			boxIntervals = [][2]float64{{leftLon, 180}, {-180, rightLon}}
		}
		for _, iv := range boxIntervals {
			w, e := iv[0], iv[1]
			rectEdges := [4][4]float64{
				{w, bottomLat, e, bottomLat},
				{e, bottomLat, e, topLat},
				{e, topLat, w, topLat},
				{w, topLat, w, bottomLat},
			}
			for _, shift := range [3]float64{0, -360, 360} {
				for i := 0; i < len(cv); i++ {
					a := cv[i]
					b := cv[(i+1)%len(cv)]
					for _, re := range rectEdges {
						if segmentsIntersectDeg(a[1]+shift, a[0], b[1]+shift, b[0], re[0], re[1], re[2], re[3]) {
							return true
						}
					}
				}
			}
		}
		return false
	}

	pents := getPentagons(res)
	pentRadiusKm := hexRadiusKm(pents[0])

	visited := make(map[uint64]struct{})
	outSet := make(map[uint64]struct{})
	queue := make([]uint64, 0, 16)
	enqueue := func(h uint64) {
		if _, ok := visited[h]; !ok {
			visited[h] = struct{}{}
			queue = append(queue, h)
		}
	}
	addSeed := func(h uint64) {
		seededInside[h] = struct{}{}
		enqueue(h)
	}

	// Seed corners, center, and perimeter edges.
	seedLine := func(lat0, lon0, lat1, lon1 float64) error {
		p0 := latLng{lat: degsToRads(lat0), lng: degsToRads(lon0)}
		p1 := latLng{lat: degsToRads(lat1), lng: degsToRads(lon1)}
		steps := lineHexEstimateCount(p0, p1, pentRadiusKm*0.5)
		if steps > maxGridCellsLimit {
			return ErrCellLimitExceeded
		}
		for j := int64(0); j <= steps; j++ {
			t := float64(j) / float64(steps)
			lat := lat0 + (lat1-lat0)*t
			lon := lon0 + (lon1-lon0)*t
			cLon := radsToDegs(constrainLng(degsToRads(lon)))
			h, err := LatLonToCell(lat, cLon, res)
			if err != nil {
				return err
			}
			addSeed(h)
		}
		return nil
	}
	if err := seedLine(bottomLat, boxW, bottomLat, boxE); err != nil {
		return nil, err
	}
	if err := seedLine(topLat, boxW, topLat, boxE); err != nil {
		return nil, err
	}
	if err := seedLine(bottomLat, boxW, topLat, boxW); err != nil {
		return nil, err
	}
	if err := seedLine(bottomLat, boxE, topLat, boxE); err != nil {
		return nil, err
	}
	midLat := (bottomLat + topLat) / 2
	midLon := radsToDegs(constrainLng(degsToRads((boxW + boxE) / 2)))
	if hMid, err := LatLonToCell(midLat, midLon, res); err == nil {
		addSeed(hMid)
	}

	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if !cellIntersectsBBox(cur) {
			continue
		}
		outSet[cur] = struct{}{}
		if len(outSet) > maxGridCellsLimit {
			return nil, ErrCellLimitExceeded
		}
		for _, nbr := range GridDisk(cur, 1) {
			enqueue(nbr)
		}
	}

	out := make([]uint64, 0, len(outSet))
	for h := range outSet {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

var faceCenterGeo = [numIcosaFaces]latLng{
	{0.803582649718989942, 1.248397419617396099},   // face 0
	{1.307747883455638156, 2.536945009877921159},   // face 1
	{1.054751253523952054, -1.347517358900396623},  // face 2
	{0.600191595538186799, -0.450603909469755746},  // face 3
	{0.491715428198773866, 0.401988202911306943},   // face 4
	{0.172745327415618701, 1.678146885280433686},   // face 5
	{0.605929321571350690, 2.953923329812411617},   // face 6
	{0.427370518328979641, -1.888876200336285401},  // face 7
	{-0.079066118549212831, -0.733429513380867741}, // face 8
	{-0.230961644455383637, 0.506495587332349035},  // face 9
	{0.079066118549212831, 2.408163140208925497},   // face 10
	{0.230961644455383637, -2.635097066257444203},  // face 11
	{-0.172745327415618701, -1.463445768309359553}, // face 12
	{-0.605929321571350690, -0.187669323777381622}, // face 13
	{-0.427370518328979641, 1.252716453253507838},  // face 14
	{-0.600191595538186799, 2.690988744120037492},  // face 15
	{-0.491715428198773866, -2.739604450678486295}, // face 16
	{-0.803582649718989942, -1.893195233972397139}, // face 17
	{-1.307747883455638156, -0.604647643711872080}, // face 18
	{-1.054751253523952054, 1.794075294689396615},  // face 19
}

var faceCenterPoint = [numIcosaFaces]vec3d{
	{0.2199307791404606, 0.6583691780274996, 0.7198475378926182},    // face 0
	{-0.2139234834501421, 0.1478171829550703, 0.9656017935214205},   // face 1
	{0.1092625278784797, -0.4811951572873210, 0.8697775121287253},   // face 2
	{0.7428567301586791, -0.3593941678278028, 0.5648005936517033},   // face 3
	{0.8112534709140969, 0.3448953237639384, 0.4721387736413930},    // face 4
	{-0.1055498149613921, 0.9794457296411413, 0.1718874610009365},   // face 5
	{-0.8075407579970092, 0.1533552485898818, 0.5695261994882688},   // face 6
	{-0.2846148069787907, -0.8644080972654206, 0.4144792552473539},  // face 7
	{0.7405621473854482, -0.6673299564565524, -0.0789837646326737},  // face 8
	{0.8512303986474293, 0.4722343788582681, -0.2289137388687808},   // face 9
	{-0.7405621473854481, 0.6673299564565524, 0.0789837646326737},   // face 10
	{-0.8512303986474292, -0.4722343788582682, 0.2289137388687808},  // face 11
	{0.1055498149613919, -0.9794457296411413, -0.1718874610009365},  // face 12
	{0.8075407579970092, -0.1533552485898819, -0.5695261994882688},  // face 13
	{0.2846148069787908, 0.8644080972654204, -0.4144792552473539},   // face 14
	{-0.7428567301586791, 0.3593941678278027, -0.5648005936517033},  // face 15
	{-0.8112534709140971, -0.3448953237639382, -0.4721387736413930}, // face 16
	{-0.2199307791404607, -0.6583691780274996, -0.7198475378926182}, // face 17
	{0.2139234834501420, -0.1478171829550704, -0.9656017935214205},  // face 18
	{-0.1092625278784796, 0.4811951572873210, -0.8697775121287253},  // face 19
}

var faceAxesAzRadsCII = [numIcosaFaces][3]float64{
	{5.619958268523939882, 3.525563166130744542, 1.431168063737548730}, // face 0
	{5.760339081714187279, 3.665943979320991689, 1.571548876927796127}, // face 1
	{0.780213654393430055, 4.969003859179821079, 2.874608756786625655}, // face 2
	{0.430469363979999913, 4.619259568766391033, 2.524864466373195467}, // face 3
	{6.130269123335111400, 4.035874020941915804, 1.941478918548720291}, // face 4
	{2.692877706530642877, 0.598482604137447119, 4.787272808923838195}, // face 5
	{2.982963003477243874, 0.888567901084048369, 5.077358105870439581}, // face 6
	{3.532912002790141181, 1.438516900396945656, 5.627307105183336758}, // face 7
	{3.494305004259568154, 1.399909901866372864, 5.588700106652763840}, // face 8
	{3.003214169499538391, 0.908819067106342928, 5.097609271892733906}, // face 9
	{5.930472956509811562, 3.836077854116615875, 1.741682751723420374}, // face 10
	{0.138378484090254847, 4.327168688876645809, 2.232773586483450311}, // face 11
	{0.448714947059150361, 4.637505151845541521, 2.543110049452346120}, // face 12
	{0.158629650112549365, 4.347419854898940135, 2.253024752505744869}, // face 13
	{5.891865957979238535, 3.797470855586042958, 1.703075753192847583}, // face 14
	{2.711123289609793325, 0.616728187216597771, 4.805518392002988683}, // face 15
	{3.294508837434268316, 1.200113735041072948, 5.388903939827463911}, // face 16
	{3.804819692245439833, 1.710424589852244509, 5.899214794638635174}, // face 17
	{3.664438879055192436, 1.570043776661997111, 5.758833981448388027}, // face 18
	{2.361378999196363184, 0.266983896803167583, 4.455774101589558636}, // face 19
}

var faceNeighbors = [numIcosaFaces][4]faceOrientIJK{
	{{0, coordIJK{0, 0, 0}, 0}, {4, coordIJK{2, 0, 2}, 1}, {1, coordIJK{2, 2, 0}, 5}, {5, coordIJK{0, 2, 2}, 3}},     // face 0
	{{1, coordIJK{0, 0, 0}, 0}, {0, coordIJK{2, 0, 2}, 1}, {2, coordIJK{2, 2, 0}, 5}, {6, coordIJK{0, 2, 2}, 3}},     // face 1
	{{2, coordIJK{0, 0, 0}, 0}, {1, coordIJK{2, 0, 2}, 1}, {3, coordIJK{2, 2, 0}, 5}, {7, coordIJK{0, 2, 2}, 3}},     // face 2
	{{3, coordIJK{0, 0, 0}, 0}, {2, coordIJK{2, 0, 2}, 1}, {4, coordIJK{2, 2, 0}, 5}, {8, coordIJK{0, 2, 2}, 3}},     // face 3
	{{4, coordIJK{0, 0, 0}, 0}, {3, coordIJK{2, 0, 2}, 1}, {0, coordIJK{2, 2, 0}, 5}, {9, coordIJK{0, 2, 2}, 3}},     // face 4
	{{5, coordIJK{0, 0, 0}, 0}, {10, coordIJK{2, 2, 0}, 3}, {14, coordIJK{2, 0, 2}, 3}, {0, coordIJK{0, 2, 2}, 3}},   // face 5
	{{6, coordIJK{0, 0, 0}, 0}, {11, coordIJK{2, 2, 0}, 3}, {10, coordIJK{2, 0, 2}, 3}, {1, coordIJK{0, 2, 2}, 3}},   // face 6
	{{7, coordIJK{0, 0, 0}, 0}, {12, coordIJK{2, 2, 0}, 3}, {11, coordIJK{2, 0, 2}, 3}, {2, coordIJK{0, 2, 2}, 3}},   // face 7
	{{8, coordIJK{0, 0, 0}, 0}, {13, coordIJK{2, 2, 0}, 3}, {12, coordIJK{2, 0, 2}, 3}, {3, coordIJK{0, 2, 2}, 3}},   // face 8
	{{9, coordIJK{0, 0, 0}, 0}, {14, coordIJK{2, 2, 0}, 3}, {13, coordIJK{2, 0, 2}, 3}, {4, coordIJK{0, 2, 2}, 3}},   // face 9
	{{10, coordIJK{0, 0, 0}, 0}, {5, coordIJK{2, 2, 0}, 3}, {6, coordIJK{2, 0, 2}, 3}, {15, coordIJK{0, 2, 2}, 3}},   // face 10
	{{11, coordIJK{0, 0, 0}, 0}, {6, coordIJK{2, 2, 0}, 3}, {7, coordIJK{2, 0, 2}, 3}, {16, coordIJK{0, 2, 2}, 3}},   // face 11
	{{12, coordIJK{0, 0, 0}, 0}, {7, coordIJK{2, 2, 0}, 3}, {8, coordIJK{2, 0, 2}, 3}, {17, coordIJK{0, 2, 2}, 3}},   // face 12
	{{13, coordIJK{0, 0, 0}, 0}, {8, coordIJK{2, 2, 0}, 3}, {9, coordIJK{2, 0, 2}, 3}, {18, coordIJK{0, 2, 2}, 3}},   // face 13
	{{14, coordIJK{0, 0, 0}, 0}, {9, coordIJK{2, 2, 0}, 3}, {5, coordIJK{2, 0, 2}, 3}, {19, coordIJK{0, 2, 2}, 3}},   // face 14
	{{15, coordIJK{0, 0, 0}, 0}, {16, coordIJK{2, 0, 2}, 1}, {19, coordIJK{2, 2, 0}, 5}, {10, coordIJK{0, 2, 2}, 3}}, // face 15
	{{16, coordIJK{0, 0, 0}, 0}, {17, coordIJK{2, 0, 2}, 1}, {15, coordIJK{2, 2, 0}, 5}, {11, coordIJK{0, 2, 2}, 3}}, // face 16
	{{17, coordIJK{0, 0, 0}, 0}, {18, coordIJK{2, 0, 2}, 1}, {16, coordIJK{2, 2, 0}, 5}, {12, coordIJK{0, 2, 2}, 3}}, // face 17
	{{18, coordIJK{0, 0, 0}, 0}, {19, coordIJK{2, 0, 2}, 1}, {17, coordIJK{2, 2, 0}, 5}, {13, coordIJK{0, 2, 2}, 3}}, // face 18
	{{19, coordIJK{0, 0, 0}, 0}, {15, coordIJK{2, 0, 2}, 1}, {18, coordIJK{2, 2, 0}, 5}, {14, coordIJK{0, 2, 2}, 3}}, // face 19
}

var adjacentFaceDir = [numIcosaFaces][numIcosaFaces]int{
	{0, overageKI, -1, -1, overageIJ, overageJK, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}, // face 0
	{overageIJ, 0, overageKI, -1, -1, -1, overageJK, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}, // face 1
	{-1, overageIJ, 0, overageKI, -1, -1, -1, overageJK, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}, // face 2
	{-1, -1, overageIJ, 0, overageKI, -1, -1, -1, overageJK, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}, // face 3
	{overageKI, -1, -1, overageIJ, 0, -1, -1, -1, -1, overageJK, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}, // face 4
	{overageJK, -1, -1, -1, -1, 0, -1, -1, -1, -1, overageIJ, -1, -1, -1, overageKI, -1, -1, -1, -1, -1}, // face 5
	{-1, overageJK, -1, -1, -1, -1, 0, -1, -1, -1, overageKI, overageIJ, -1, -1, -1, -1, -1, -1, -1, -1}, // face 6
	{-1, -1, overageJK, -1, -1, -1, -1, 0, -1, -1, -1, overageKI, overageIJ, -1, -1, -1, -1, -1, -1, -1}, // face 7
	{-1, -1, -1, overageJK, -1, -1, -1, -1, 0, -1, -1, -1, overageKI, overageIJ, -1, -1, -1, -1, -1, -1}, // face 8
	{-1, -1, -1, -1, overageJK, -1, -1, -1, -1, 0, -1, -1, -1, overageKI, overageIJ, -1, -1, -1, -1, -1}, // face 9
	{-1, -1, -1, -1, -1, overageIJ, overageKI, -1, -1, -1, 0, -1, -1, -1, -1, overageJK, -1, -1, -1, -1}, // face 10
	{-1, -1, -1, -1, -1, -1, overageIJ, overageKI, -1, -1, -1, 0, -1, -1, -1, -1, overageJK, -1, -1, -1}, // face 11
	{-1, -1, -1, -1, -1, -1, -1, overageIJ, overageKI, -1, -1, -1, 0, -1, -1, -1, -1, overageJK, -1, -1}, // face 12
	{-1, -1, -1, -1, -1, -1, -1, -1, overageIJ, overageKI, -1, -1, -1, 0, -1, -1, -1, -1, overageJK, -1}, // face 13
	{-1, -1, -1, -1, -1, overageKI, -1, -1, -1, overageIJ, -1, -1, -1, -1, 0, -1, -1, -1, -1, overageJK}, // face 14
	{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, overageJK, -1, -1, -1, -1, 0, overageIJ, -1, -1, overageKI}, // face 15
	{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, overageJK, -1, -1, -1, overageKI, 0, overageIJ, -1, -1}, // face 16
	{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, overageJK, -1, -1, -1, overageKI, 0, overageIJ, -1}, // face 17
	{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, overageJK, -1, -1, -1, overageKI, 0, overageIJ}, // face 18
	{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, overageJK, overageIJ, -1, -1, overageKI, 0}, // face 19
}

var baseCellNeighbors = [numBaseCells][7]int{
	{0, 1, 5, 2, 4, 3, 8},                           // 0
	{1, 7, 6, 9, 0, 3, 2},                           // 1
	{2, 6, 10, 11, 0, 1, 5},                         // 2
	{3, 13, 1, 7, 4, 12, 0},                         // 3
	{4, invalidBaseCell, 15, 8, 3, 0, 12},           // 4
	{5, 2, 18, 10, 8, 0, 16},                        // 5
	{6, 14, 11, 17, 1, 9, 2},                        // 6
	{7, 21, 9, 19, 3, 13, 1},                        // 7
	{8, 5, 22, 16, 4, 0, 15},                        // 8
	{9, 19, 14, 20, 1, 7, 6},                        // 9
	{10, 11, 24, 23, 5, 2, 18},                      // 10
	{11, 17, 23, 25, 2, 6, 10},                      // 11
	{12, 28, 13, 26, 4, 15, 3},                      // 12
	{13, 26, 21, 29, 3, 12, 7},                      // 13
	{14, invalidBaseCell, 17, 27, 9, 20, 6},         // 14
	{15, 22, 28, 31, 4, 8, 12},                      // 15
	{16, 18, 33, 30, 8, 5, 22},                      // 16
	{17, 11, 14, 6, 35, 25, 27},                     // 17
	{18, 24, 30, 32, 5, 10, 16},                     // 18
	{19, 34, 20, 36, 7, 21, 9},                      // 19
	{20, 14, 19, 9, 40, 27, 36},                     // 20
	{21, 38, 19, 34, 13, 29, 7},                     // 21
	{22, 16, 41, 33, 15, 8, 31},                     // 22
	{23, 24, 11, 10, 39, 37, 25},                    // 23
	{24, invalidBaseCell, 32, 37, 10, 23, 18},       // 24
	{25, 23, 17, 11, 45, 39, 35},                    // 25
	{26, 42, 29, 43, 12, 28, 13},                    // 26
	{27, 40, 35, 46, 14, 20, 17},                    // 27
	{28, 31, 42, 44, 12, 15, 26},                    // 28
	{29, 43, 38, 47, 13, 26, 21},                    // 29
	{30, 32, 48, 50, 16, 18, 33},                    // 30
	{31, 41, 44, 53, 15, 22, 28},                    // 31
	{32, 30, 24, 18, 52, 50, 37},                    // 32
	{33, 30, 49, 48, 22, 16, 41},                    // 33
	{34, 19, 38, 21, 54, 36, 51},                    // 34
	{35, 46, 45, 56, 17, 27, 25},                    // 35
	{36, 20, 34, 19, 55, 40, 54},                    // 36
	{37, 39, 52, 57, 24, 23, 32},                    // 37
	{38, invalidBaseCell, 34, 51, 29, 47, 21},       // 38
	{39, 37, 25, 23, 59, 57, 45},                    // 39
	{40, 27, 36, 20, 60, 46, 55},                    // 40
	{41, 49, 53, 61, 22, 33, 31},                    // 41
	{42, 58, 43, 62, 28, 44, 26},                    // 42
	{43, 62, 47, 64, 26, 42, 29},                    // 43
	{44, 53, 58, 65, 28, 31, 42},                    // 44
	{45, 39, 35, 25, 63, 59, 56},                    // 45
	{46, 60, 56, 68, 27, 40, 35},                    // 46
	{47, 38, 43, 29, 69, 51, 64},                    // 47
	{48, 49, 30, 33, 67, 66, 50},                    // 48
	{49, invalidBaseCell, 61, 66, 33, 48, 41},       // 49
	{50, 48, 32, 30, 70, 67, 52},                    // 50
	{51, 69, 54, 71, 38, 47, 34},                    // 51
	{52, 57, 70, 74, 32, 37, 50},                    // 52
	{53, 61, 65, 75, 31, 41, 44},                    // 53
	{54, 71, 55, 73, 34, 51, 36},                    // 54
	{55, 40, 54, 36, 72, 60, 73},                    // 55
	{56, 68, 63, 77, 35, 46, 45},                    // 56
	{57, 59, 74, 78, 37, 39, 52},                    // 57
	{58, invalidBaseCell, 62, 76, 44, 65, 42},       // 58
	{59, 63, 78, 79, 39, 45, 57},                    // 59
	{60, 72, 68, 80, 40, 55, 46},                    // 60
	{61, 53, 49, 41, 81, 75, 66},                    // 61
	{62, 43, 58, 42, 82, 64, 76},                    // 62
	{63, invalidBaseCell, 56, 45, 79, 59, 77},       // 63
	{64, 47, 62, 43, 84, 69, 82},                    // 64
	{65, 58, 53, 44, 86, 76, 75},                    // 65
	{66, 67, 81, 85, 49, 48, 61},                    // 66
	{67, 66, 50, 48, 87, 85, 70},                    // 67
	{68, 56, 60, 46, 90, 77, 80},                    // 68
	{69, 51, 64, 47, 89, 71, 84},                    // 69
	{70, 67, 52, 50, 83, 87, 74},                    // 70
	{71, 89, 73, 91, 51, 69, 54},                    // 71
	{72, invalidBaseCell, 73, 55, 80, 60, 88},       // 72
	{73, 91, 72, 88, 54, 71, 55},                    // 73
	{74, 78, 83, 92, 52, 57, 70},                    // 74
	{75, 65, 61, 53, 94, 86, 81},                    // 75
	{76, 86, 82, 96, 58, 65, 62},                    // 76
	{77, 63, 68, 56, 93, 79, 90},                    // 77
	{78, 74, 59, 57, 95, 92, 79},                    // 78
	{79, 78, 63, 59, 93, 95, 77},                    // 79
	{80, 68, 72, 60, 99, 90, 88},                    // 80
	{81, 85, 94, 101, 61, 66, 75},                   // 81
	{82, 96, 84, 98, 62, 76, 64},                    // 82
	{83, invalidBaseCell, 74, 70, 100, 87, 92},      // 83
	{84, 69, 82, 64, 97, 89, 98},                    // 84
	{85, 87, 101, 102, 66, 67, 81},                  // 85
	{86, 76, 75, 65, 104, 96, 94},                   // 86
	{87, 83, 102, 100, 67, 70, 85},                  // 87
	{88, 72, 91, 73, 99, 80, 105},                   // 88
	{89, 97, 91, 103, 69, 84, 71},                   // 89
	{90, 77, 80, 68, 106, 93, 99},                   // 90
	{91, 73, 89, 71, 105, 88, 103},                  // 91
	{92, 83, 78, 74, 108, 100, 95},                  // 92
	{93, 79, 90, 77, 109, 95, 106},                  // 93
	{94, 86, 81, 75, 107, 104, 101},                 // 94
	{95, 92, 79, 78, 109, 108, 93},                  // 95
	{96, 104, 98, 110, 76, 86, 82},                  // 96
	{97, invalidBaseCell, 98, 84, 103, 89, 111},     // 97
	{98, 110, 97, 111, 82, 96, 84},                  // 98
	{99, 80, 105, 88, 106, 90, 113},                 // 99
	{100, 102, 83, 87, 108, 114, 92},                // 100
	{101, 102, 107, 112, 81, 85, 94},                // 101
	{102, 101, 87, 85, 114, 112, 100},               // 102
	{103, 91, 97, 89, 116, 105, 111},                // 103
	{104, 107, 110, 115, 86, 94, 96},                // 104
	{105, 88, 103, 91, 113, 99, 116},                // 105
	{106, 93, 99, 90, 117, 109, 113},                // 106
	{107, invalidBaseCell, 101, 94, 115, 104, 112},  // 107
	{108, 100, 95, 92, 118, 114, 109},               // 108
	{109, 108, 93, 95, 117, 118, 106},               // 109
	{110, 98, 104, 96, 119, 111, 115},               // 110
	{111, 97, 110, 98, 116, 103, 119},               // 111
	{112, 107, 102, 101, 120, 115, 114},             // 112
	{113, 99, 116, 105, 117, 106, 121},              // 113
	{114, 112, 100, 102, 118, 120, 108},             // 114
	{115, 110, 107, 104, 120, 119, 112},             // 115
	{116, 103, 119, 111, 113, 105, 121},             // 116
	{117, invalidBaseCell, 109, 118, 113, 121, 106}, // 117
	{118, 120, 108, 114, 117, 121, 109},             // 118
	{119, 111, 115, 110, 121, 116, 120},             // 119
	{120, 115, 114, 112, 121, 119, 118},             // 120
	{121, 116, 120, 119, 117, 113, 118},             // 121
}

var baseCellNeighbor60CCWRots = [numBaseCells][7]int{
	{0, 5, 0, 0, 1, 5, 1},  // 0
	{0, 0, 1, 0, 1, 0, 1},  // 1
	{0, 0, 0, 0, 0, 5, 0},  // 2
	{0, 5, 0, 0, 2, 5, 1},  // 3
	{0, -1, 1, 0, 3, 4, 2}, // 4
	{0, 0, 1, 0, 1, 0, 1},  // 5
	{0, 0, 0, 3, 5, 5, 0},  // 6
	{0, 0, 0, 0, 0, 5, 0},  // 7
	{0, 5, 0, 0, 0, 5, 1},  // 8
	{0, 0, 1, 3, 0, 0, 1},  // 9
	{0, 0, 1, 3, 0, 0, 1},  // 10
	{0, 3, 3, 3, 0, 0, 0},  // 11
	{0, 5, 0, 0, 3, 5, 1},  // 12
	{0, 0, 1, 0, 1, 0, 1},  // 13
	{0, -1, 3, 0, 5, 2, 0}, // 14
	{0, 5, 0, 0, 4, 5, 1},  // 15
	{0, 0, 0, 0, 0, 5, 0},  // 16
	{0, 3, 3, 3, 3, 0, 3},  // 17
	{0, 0, 0, 3, 5, 5, 0},  // 18
	{0, 3, 3, 3, 0, 0, 0},  // 19
	{0, 3, 3, 3, 0, 3, 0},  // 20
	{0, 0, 0, 3, 5, 5, 0},  // 21
	{0, 0, 1, 0, 1, 0, 1},  // 22
	{0, 3, 3, 3, 0, 3, 0},  // 23
	{0, -1, 3, 0, 5, 2, 0}, // 24
	{0, 0, 0, 3, 0, 0, 3},  // 25
	{0, 0, 0, 0, 0, 5, 0},  // 26
	{0, 3, 0, 0, 0, 3, 3},  // 27
	{0, 0, 1, 0, 1, 0, 1},  // 28
	{0, 0, 1, 3, 0, 0, 1},  // 29
	{0, 3, 3, 3, 0, 0, 0},  // 30
	{0, 0, 0, 0, 0, 5, 0},  // 31
	{0, 3, 3, 3, 3, 0, 3},  // 32
	{0, 0, 1, 3, 0, 0, 1},  // 33
	{0, 3, 3, 3, 3, 0, 3},  // 34
	{0, 0, 3, 0, 3, 0, 3},  // 35
	{0, 0, 0, 3, 0, 0, 3},  // 36
	{0, 3, 0, 0, 0, 3, 3},  // 37
	{0, -1, 3, 0, 5, 2, 0}, // 38
	{0, 3, 0, 0, 3, 3, 0},  // 39
	{0, 3, 0, 0, 3, 3, 0},  // 40
	{0, 0, 0, 3, 5, 5, 0},  // 41
	{0, 0, 0, 3, 5, 5, 0},  // 42
	{0, 3, 3, 3, 0, 0, 0},  // 43
	{0, 0, 1, 3, 0, 0, 1},  // 44
	{0, 0, 3, 0, 0, 3, 3},  // 45
	{0, 0, 0, 3, 0, 3, 0},  // 46
	{0, 3, 3, 3, 0, 3, 0},  // 47
	{0, 3, 3, 3, 0, 3, 0},  // 48
	{0, -1, 3, 0, 5, 2, 0}, // 49
	{0, 0, 0, 3, 0, 0, 3},  // 50
	{0, 3, 0, 0, 0, 3, 3},  // 51
	{0, 0, 3, 0, 3, 0, 3},  // 52
	{0, 3, 3, 3, 0, 0, 0},  // 53
	{0, 0, 3, 0, 3, 0, 3},  // 54
	{0, 0, 3, 0, 0, 3, 3},  // 55
	{0, 3, 3, 3, 0, 0, 3},  // 56
	{0, 0, 0, 3, 0, 3, 0},  // 57
	{0, -1, 3, 0, 5, 2, 0}, // 58
	{0, 3, 3, 3, 3, 3, 0},  // 59
	{0, 3, 3, 3, 3, 3, 0},  // 60
	{0, 3, 3, 3, 3, 0, 3},  // 61
	{0, 3, 3, 3, 3, 0, 3},  // 62
	{0, -1, 3, 0, 5, 2, 0}, // 63
	{0, 0, 0, 3, 0, 0, 3},  // 64
	{0, 3, 3, 3, 0, 3, 0},  // 65
	{0, 3, 0, 0, 0, 3, 3},  // 66
	{0, 3, 0, 0, 3, 3, 0},  // 67
	{0, 3, 3, 3, 0, 0, 0},  // 68
	{0, 3, 0, 0, 3, 3, 0},  // 69
	{0, 0, 3, 0, 0, 3, 3},  // 70
	{0, 0, 0, 3, 0, 3, 0},  // 71
	{0, -1, 3, 0, 5, 2, 0}, // 72
	{0, 3, 3, 3, 0, 0, 3},  // 73
	{0, 3, 3, 3, 0, 0, 3},  // 74
	{0, 0, 0, 3, 0, 0, 3},  // 75
	{0, 3, 0, 0, 0, 3, 3},  // 76
	{0, 0, 0, 3, 0, 5, 0},  // 77
	{0, 3, 3, 3, 0, 0, 0},  // 78
	{0, 0, 1, 3, 1, 0, 1},  // 79
	{0, 0, 1, 3, 1, 0, 1},  // 80
	{0, 0, 3, 0, 3, 0, 3},  // 81
	{0, 0, 3, 0, 3, 0, 3},  // 82
	{0, -1, 3, 0, 5, 2, 0}, // 83
	{0, 0, 3, 0, 0, 3, 3},  // 84
	{0, 0, 0, 3, 0, 3, 0},  // 85
	{0, 3, 0, 0, 3, 3, 0},  // 86
	{0, 3, 3, 3, 3, 3, 0},  // 87
	{0, 0, 0, 3, 0, 5, 0},  // 88
	{0, 3, 3, 3, 3, 3, 0},  // 89
	{0, 0, 0, 0, 0, 0, 1},  // 90
	{0, 3, 3, 3, 0, 0, 0},  // 91
	{0, 0, 0, 3, 0, 5, 0},  // 92
	{0, 5, 0, 0, 5, 5, 0},  // 93
	{0, 0, 3, 0, 0, 3, 3},  // 94
	{0, 0, 0, 0, 0, 0, 1},  // 95
	{0, 0, 0, 3, 0, 3, 0},  // 96
	{0, -1, 3, 0, 5, 2, 0}, // 97
	{0, 3, 3, 3, 0, 0, 3},  // 98
	{0, 5, 0, 0, 5, 5, 0},  // 99
	{0, 0, 1, 3, 1, 0, 1},  // 100
	{0, 3, 3, 3, 0, 0, 3},  // 101
	{0, 3, 3, 3, 0, 0, 0},  // 102
	{0, 0, 1, 3, 1, 0, 1},  // 103
	{0, 3, 3, 3, 3, 3, 0},  // 104
	{0, 0, 0, 0, 0, 0, 1},  // 105
	{0, 0, 1, 0, 3, 5, 1},  // 106
	{0, -1, 3, 0, 5, 2, 0}, // 107
	{0, 5, 0, 0, 5, 5, 0},  // 108
	{0, 0, 1, 0, 4, 5, 1},  // 109
	{0, 3, 3, 3, 0, 0, 0},  // 110
	{0, 0, 0, 3, 0, 5, 0},  // 111
	{0, 0, 0, 3, 0, 5, 0},  // 112
	{0, 0, 1, 0, 2, 5, 1},  // 113
	{0, 0, 0, 0, 0, 0, 1},  // 114
	{0, 0, 1, 3, 1, 0, 1},  // 115
	{0, 5, 0, 0, 5, 5, 0},  // 116
	{0, -1, 1, 0, 3, 4, 2}, // 117
	{0, 0, 1, 0, 0, 5, 1},  // 118
	{0, 0, 0, 0, 0, 0, 1},  // 119
	{0, 5, 0, 0, 5, 5, 0},  // 120
	{0, 0, 1, 0, 1, 5, 1},  // 121
}

var faceIjkBaseCells = [numIcosaFaces][3][3][3]baseCellRotation{
	{ // face 0
		{
			{{16, 0}, {18, 0}, {24, 0}},
			{{33, 0}, {30, 0}, {32, 3}},
			{{49, 1}, {48, 3}, {50, 3}},
		},
		{
			{{8, 0}, {5, 5}, {10, 5}},
			{{22, 0}, {16, 0}, {18, 0}},
			{{41, 1}, {33, 0}, {30, 0}},
		},
		{
			{{4, 0}, {0, 5}, {2, 5}},
			{{15, 1}, {8, 0}, {5, 5}},
			{{31, 1}, {22, 0}, {16, 0}},
		},
	},
	{ // face 1
		{
			{{2, 0}, {6, 0}, {14, 0}},
			{{10, 0}, {11, 0}, {17, 3}},
			{{24, 1}, {23, 3}, {25, 3}},
		},
		{
			{{0, 0}, {1, 5}, {9, 5}},
			{{5, 0}, {2, 0}, {6, 0}},
			{{18, 1}, {10, 0}, {11, 0}},
		},
		{
			{{4, 1}, {3, 5}, {7, 5}},
			{{8, 1}, {0, 0}, {1, 5}},
			{{16, 1}, {5, 0}, {2, 0}},
		},
	},
	{ // face 2
		{
			{{7, 0}, {21, 0}, {38, 0}},
			{{9, 0}, {19, 0}, {34, 3}},
			{{14, 1}, {20, 3}, {36, 3}},
		},
		{
			{{3, 0}, {13, 5}, {29, 5}},
			{{1, 0}, {7, 0}, {21, 0}},
			{{6, 1}, {9, 0}, {19, 0}},
		},
		{
			{{4, 2}, {12, 5}, {26, 5}},
			{{0, 1}, {3, 0}, {13, 5}},
			{{2, 1}, {1, 0}, {7, 0}},
		},
	},
	{ // face 3
		{
			{{26, 0}, {42, 0}, {58, 0}},
			{{29, 0}, {43, 0}, {62, 3}},
			{{38, 1}, {47, 3}, {64, 3}},
		},
		{
			{{12, 0}, {28, 5}, {44, 5}},
			{{13, 0}, {26, 0}, {42, 0}},
			{{21, 1}, {29, 0}, {43, 0}},
		},
		{
			{{4, 3}, {15, 5}, {31, 5}},
			{{3, 1}, {12, 0}, {28, 5}},
			{{7, 1}, {13, 0}, {26, 0}},
		},
	},
	{ // face 4
		{
			{{31, 0}, {41, 0}, {49, 0}},
			{{44, 0}, {53, 0}, {61, 3}},
			{{58, 1}, {65, 3}, {75, 3}},
		},
		{
			{{15, 0}, {22, 5}, {33, 5}},
			{{28, 0}, {31, 0}, {41, 0}},
			{{42, 1}, {44, 0}, {53, 0}},
		},
		{
			{{4, 4}, {8, 5}, {16, 5}},
			{{12, 1}, {15, 0}, {22, 5}},
			{{26, 1}, {28, 0}, {31, 0}},
		},
	},
	{ // face 5
		{
			{{50, 0}, {48, 0}, {49, 3}},
			{{32, 0}, {30, 3}, {33, 3}},
			{{24, 3}, {18, 3}, {16, 3}},
		},
		{
			{{70, 0}, {67, 0}, {66, 3}},
			{{52, 3}, {50, 0}, {48, 0}},
			{{37, 3}, {32, 0}, {30, 3}},
		},
		{
			{{83, 0}, {87, 3}, {85, 3}},
			{{74, 3}, {70, 0}, {67, 0}},
			{{57, 1}, {52, 3}, {50, 0}},
		},
	},
	{ // face 6
		{
			{{25, 0}, {23, 0}, {24, 3}},
			{{17, 0}, {11, 3}, {10, 3}},
			{{14, 3}, {6, 3}, {2, 3}},
		},
		{
			{{45, 0}, {39, 0}, {37, 3}},
			{{35, 3}, {25, 0}, {23, 0}},
			{{27, 3}, {17, 0}, {11, 3}},
		},
		{
			{{63, 0}, {59, 3}, {57, 3}},
			{{56, 3}, {45, 0}, {39, 0}},
			{{46, 3}, {35, 3}, {25, 0}},
		},
	},
	{ // face 7
		{
			{{36, 0}, {20, 0}, {14, 3}},
			{{34, 0}, {19, 3}, {9, 3}},
			{{38, 3}, {21, 3}, {7, 3}},
		},
		{
			{{55, 0}, {40, 0}, {27, 3}},
			{{54, 3}, {36, 0}, {20, 0}},
			{{51, 3}, {34, 0}, {19, 3}},
		},
		{
			{{72, 0}, {60, 3}, {46, 3}},
			{{73, 3}, {55, 0}, {40, 0}},
			{{71, 3}, {54, 3}, {36, 0}},
		},
	},
	{ // face 8
		{
			{{64, 0}, {47, 0}, {38, 3}},
			{{62, 0}, {43, 3}, {29, 3}},
			{{58, 3}, {42, 3}, {26, 3}},
		},
		{
			{{84, 0}, {69, 0}, {51, 3}},
			{{82, 3}, {64, 0}, {47, 0}},
			{{76, 3}, {62, 0}, {43, 3}},
		},
		{
			{{97, 0}, {89, 3}, {71, 3}},
			{{98, 3}, {84, 0}, {69, 0}},
			{{96, 3}, {82, 3}, {64, 0}},
		},
	},
	{ // face 9
		{
			{{75, 0}, {65, 0}, {58, 3}},
			{{61, 0}, {53, 3}, {44, 3}},
			{{49, 3}, {41, 3}, {31, 3}},
		},
		{
			{{94, 0}, {86, 0}, {76, 3}},
			{{81, 3}, {75, 0}, {65, 0}},
			{{66, 3}, {61, 0}, {53, 3}},
		},
		{
			{{107, 0}, {104, 3}, {96, 3}},
			{{101, 3}, {94, 0}, {86, 0}},
			{{85, 3}, {81, 3}, {75, 0}},
		},
	},
	{ // face 10
		{
			{{57, 0}, {59, 0}, {63, 3}},
			{{74, 0}, {78, 3}, {79, 3}},
			{{83, 3}, {92, 3}, {95, 3}},
		},
		{
			{{37, 0}, {39, 3}, {45, 3}},
			{{52, 0}, {57, 0}, {59, 0}},
			{{70, 3}, {74, 0}, {78, 3}},
		},
		{
			{{24, 0}, {23, 3}, {25, 3}},
			{{32, 3}, {37, 0}, {39, 3}},
			{{50, 3}, {52, 0}, {57, 0}},
		},
	},
	{ // face 11
		{
			{{46, 0}, {60, 0}, {72, 3}},
			{{56, 0}, {68, 3}, {80, 3}},
			{{63, 3}, {77, 3}, {90, 3}},
		},
		{
			{{27, 0}, {40, 3}, {55, 3}},
			{{35, 0}, {46, 0}, {60, 0}},
			{{45, 3}, {56, 0}, {68, 3}},
		},
		{
			{{14, 0}, {20, 3}, {36, 3}},
			{{17, 3}, {27, 0}, {40, 3}},
			{{25, 3}, {35, 0}, {46, 0}},
		},
	},
	{ // face 12
		{
			{{71, 0}, {89, 0}, {97, 3}},
			{{73, 0}, {91, 3}, {103, 3}},
			{{72, 3}, {88, 3}, {105, 3}},
		},
		{
			{{51, 0}, {69, 3}, {84, 3}},
			{{54, 0}, {71, 0}, {89, 0}},
			{{55, 3}, {73, 0}, {91, 3}},
		},
		{
			{{38, 0}, {47, 3}, {64, 3}},
			{{34, 3}, {51, 0}, {69, 3}},
			{{36, 3}, {54, 0}, {71, 0}},
		},
	},
	{ // face 13
		{
			{{96, 0}, {104, 0}, {107, 3}},
			{{98, 0}, {110, 3}, {115, 3}},
			{{97, 3}, {111, 3}, {119, 3}},
		},
		{
			{{76, 0}, {86, 3}, {94, 3}},
			{{82, 0}, {96, 0}, {104, 0}},
			{{84, 3}, {98, 0}, {110, 3}},
		},
		{
			{{58, 0}, {65, 3}, {75, 3}},
			{{62, 3}, {76, 0}, {86, 3}},
			{{64, 3}, {82, 0}, {96, 0}},
		},
	},
	{ // face 14
		{
			{{85, 0}, {87, 0}, {83, 3}},
			{{101, 0}, {102, 3}, {100, 3}},
			{{107, 3}, {112, 3}, {114, 3}},
		},
		{
			{{66, 0}, {67, 3}, {70, 3}},
			{{81, 0}, {85, 0}, {87, 0}},
			{{94, 3}, {101, 0}, {102, 3}},
		},
		{
			{{49, 0}, {48, 3}, {50, 3}},
			{{61, 3}, {66, 0}, {67, 3}},
			{{75, 3}, {81, 0}, {85, 0}},
		},
	},
	{ // face 15
		{
			{{95, 0}, {92, 0}, {83, 0}},
			{{79, 0}, {78, 0}, {74, 3}},
			{{63, 1}, {59, 3}, {57, 3}},
		},
		{
			{{109, 0}, {108, 0}, {100, 5}},
			{{93, 1}, {95, 0}, {92, 0}},
			{{77, 1}, {79, 0}, {78, 0}},
		},
		{
			{{117, 4}, {118, 5}, {114, 5}},
			{{106, 1}, {109, 0}, {108, 0}},
			{{90, 1}, {93, 1}, {95, 0}},
		},
	},
	{ // face 16
		{
			{{90, 0}, {77, 0}, {63, 0}},
			{{80, 0}, {68, 0}, {56, 3}},
			{{72, 1}, {60, 3}, {46, 3}},
		},
		{
			{{106, 0}, {93, 0}, {79, 5}},
			{{99, 1}, {90, 0}, {77, 0}},
			{{88, 1}, {80, 0}, {68, 0}},
		},
		{
			{{117, 3}, {109, 5}, {95, 5}},
			{{113, 1}, {106, 0}, {93, 0}},
			{{105, 1}, {99, 1}, {90, 0}},
		},
	},
	{ // face 17
		{
			{{105, 0}, {88, 0}, {72, 0}},
			{{103, 0}, {91, 0}, {73, 3}},
			{{97, 1}, {89, 3}, {71, 3}},
		},
		{
			{{113, 0}, {99, 0}, {80, 5}},
			{{116, 1}, {105, 0}, {88, 0}},
			{{111, 1}, {103, 0}, {91, 0}},
		},
		{
			{{117, 2}, {106, 5}, {90, 5}},
			{{121, 1}, {113, 0}, {99, 0}},
			{{119, 1}, {116, 1}, {105, 0}},
		},
	},
	{ // face 18
		{
			{{119, 0}, {111, 0}, {97, 0}},
			{{115, 0}, {110, 0}, {98, 3}},
			{{107, 1}, {104, 3}, {96, 3}},
		},
		{
			{{121, 0}, {116, 0}, {103, 5}},
			{{120, 1}, {119, 0}, {111, 0}},
			{{112, 1}, {115, 0}, {110, 0}},
		},
		{
			{{117, 1}, {113, 5}, {105, 5}},
			{{118, 1}, {121, 0}, {116, 0}},
			{{114, 1}, {120, 1}, {119, 0}},
		},
	},
	{ // face 19
		{
			{{114, 0}, {112, 0}, {107, 0}},
			{{100, 0}, {102, 0}, {101, 3}},
			{{83, 1}, {87, 3}, {85, 3}},
		},
		{
			{{118, 0}, {120, 0}, {115, 5}},
			{{108, 1}, {114, 0}, {112, 0}},
			{{92, 1}, {100, 0}, {102, 0}},
		},
		{
			{{117, 0}, {121, 5}, {119, 5}},
			{{109, 1}, {118, 0}, {120, 0}},
			{{95, 1}, {108, 1}, {114, 0}},
		},
	},
}

var baseCellData = [numBaseCells]baseCellDataEntry{
	{faceIJK{1, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 0
	{faceIJK{2, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},   // 1
	{faceIJK{1, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 2
	{faceIJK{2, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 3
	{faceIJK{0, coordIJK{2, 0, 0}}, true, [2]int{-1, -1}},  // 4
	{faceIJK{1, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},   // 5
	{faceIJK{1, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 6
	{faceIJK{2, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 7
	{faceIJK{0, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 8
	{faceIJK{2, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 9
	{faceIJK{1, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 10
	{faceIJK{1, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},   // 11
	{faceIJK{3, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 12
	{faceIJK{3, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},   // 13
	{faceIJK{11, coordIJK{2, 0, 0}}, true, [2]int{2, 6}},   // 14
	{faceIJK{4, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 15
	{faceIJK{0, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 16
	{faceIJK{6, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 17
	{faceIJK{0, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 18
	{faceIJK{2, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},   // 19
	{faceIJK{7, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 20
	{faceIJK{2, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 21
	{faceIJK{0, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},   // 22
	{faceIJK{6, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 23
	{faceIJK{10, coordIJK{2, 0, 0}}, true, [2]int{1, 5}},   // 24
	{faceIJK{6, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 25
	{faceIJK{3, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 26
	{faceIJK{11, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 27
	{faceIJK{4, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},   // 28
	{faceIJK{3, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 29
	{faceIJK{0, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},   // 30
	{faceIJK{4, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 31
	{faceIJK{5, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 32
	{faceIJK{0, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 33
	{faceIJK{7, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 34
	{faceIJK{11, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},  // 35
	{faceIJK{7, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 36
	{faceIJK{10, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 37
	{faceIJK{12, coordIJK{2, 0, 0}}, true, [2]int{3, 7}},   // 38
	{faceIJK{6, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},   // 39
	{faceIJK{7, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},   // 40
	{faceIJK{4, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 41
	{faceIJK{3, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 42
	{faceIJK{3, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},   // 43
	{faceIJK{4, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 44
	{faceIJK{6, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 45
	{faceIJK{11, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 46
	{faceIJK{8, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 47
	{faceIJK{5, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 48
	{faceIJK{14, coordIJK{2, 0, 0}}, true, [2]int{0, 9}},   // 49
	{faceIJK{5, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 50
	{faceIJK{12, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 51
	{faceIJK{10, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},  // 52
	{faceIJK{4, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},   // 53
	{faceIJK{12, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},  // 54
	{faceIJK{7, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 55
	{faceIJK{11, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 56
	{faceIJK{10, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 57
	{faceIJK{13, coordIJK{2, 0, 0}}, true, [2]int{4, 8}},   // 58
	{faceIJK{10, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 59
	{faceIJK{11, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 60
	{faceIJK{9, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 61
	{faceIJK{8, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},   // 62
	{faceIJK{6, coordIJK{2, 0, 0}}, true, [2]int{11, 15}},  // 63
	{faceIJK{8, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 64
	{faceIJK{9, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},   // 65
	{faceIJK{14, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 66
	{faceIJK{5, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},   // 67
	{faceIJK{16, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},  // 68
	{faceIJK{8, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},   // 69
	{faceIJK{5, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 70
	{faceIJK{12, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 71
	{faceIJK{7, coordIJK{2, 0, 0}}, true, [2]int{12, 16}},  // 72
	{faceIJK{12, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 73
	{faceIJK{10, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 74
	{faceIJK{9, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},   // 75
	{faceIJK{13, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 76
	{faceIJK{16, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 77
	{faceIJK{15, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},  // 78
	{faceIJK{15, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 79
	{faceIJK{16, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 80
	{faceIJK{14, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},  // 81
	{faceIJK{13, coordIJK{1, 1, 0}}, false, [2]int{0, 0}},  // 82
	{faceIJK{5, coordIJK{2, 0, 0}}, true, [2]int{10, 19}},  // 83
	{faceIJK{8, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 84
	{faceIJK{14, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 85
	{faceIJK{9, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},   // 86
	{faceIJK{14, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 87
	{faceIJK{17, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 88
	{faceIJK{12, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 89
	{faceIJK{16, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 90
	{faceIJK{17, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},  // 91
	{faceIJK{15, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 92
	{faceIJK{16, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},  // 93
	{faceIJK{9, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},   // 94
	{faceIJK{15, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 95
	{faceIJK{13, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 96
	{faceIJK{8, coordIJK{2, 0, 0}}, true, [2]int{13, 17}},  // 97
	{faceIJK{13, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 98
	{faceIJK{17, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},  // 99
	{faceIJK{19, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 100
	{faceIJK{14, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 101
	{faceIJK{19, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},  // 102
	{faceIJK{17, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 103
	{faceIJK{13, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 104
	{faceIJK{17, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 105
	{faceIJK{16, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 106
	{faceIJK{9, coordIJK{2, 0, 0}}, true, [2]int{14, 18}},  // 107
	{faceIJK{15, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},  // 108
	{faceIJK{15, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 109
	{faceIJK{18, coordIJK{0, 1, 1}}, false, [2]int{0, 0}},  // 110
	{faceIJK{18, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 111
	{faceIJK{19, coordIJK{0, 0, 1}}, false, [2]int{0, 0}},  // 112
	{faceIJK{17, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 113
	{faceIJK{19, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 114
	{faceIJK{18, coordIJK{0, 1, 0}}, false, [2]int{0, 0}},  // 115
	{faceIJK{18, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},  // 116
	{faceIJK{19, coordIJK{2, 0, 0}}, true, [2]int{-1, -1}}, // 117
	{faceIJK{19, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 118
	{faceIJK{18, coordIJK{0, 0, 0}}, false, [2]int{0, 0}},  // 119
	{faceIJK{19, coordIJK{1, 0, 1}}, false, [2]int{0, 0}},  // 120
	{faceIJK{18, coordIJK{1, 0, 0}}, false, [2]int{0, 0}},  // 121
}
