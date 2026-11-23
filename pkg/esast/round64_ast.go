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

package esast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// CartesianBoundsAggSpec aliases GeoBoundsAggSpec for `cartesian_bounds` metric aggregations.
type CartesianBoundsAggSpec = GeoBoundsAggSpec

// CartesianCentroidAggSpec aliases MetricAggSpec for `cartesian_centroid` metric aggregations.
type CartesianCentroidAggSpec = MetricAggSpec

// GeoHexGridAggSpec aliases GeoGridAggSpec for `geohex_grid` bucket aggregations.
type GeoHexGridAggSpec = GeoGridAggSpec

// GeoGridQuery models an Elasticsearch `geo_grid` spatial cell query (`geohash`, `geotile`, `geohex`).
type GeoGridQuery struct {
	Field          string   `json:"-"`
	Geohash        string   `json:"geohash,omitempty"`
	Geotile        string   `json:"geotile,omitempty"`
	Geohex         string   `json:"geohex,omitempty"`
	IgnoreUnmapped bool     `json:"ignore_unmapped,omitempty"`
	Boost          *float64 `json:"boost,omitempty"`
	Name           string   `json:"_name,omitempty"`
}

// GridType returns which cell grid kind ("geohash", "geotile", or "geohex") is set on gg.
func (gg *GeoGridQuery) GridType() string {
	if gg == nil {
		return ""
	}
	if gg.Geohash != "" {
		return "geohash"
	}
	if gg.Geotile != "" {
		return "geotile"
	}
	if gg.Geohex != "" {
		return "geohex"
	}
	return ""
}

// GridValue returns the cell identifier string set on gg.
func (gg *GeoGridQuery) GridValue() string {
	if gg == nil {
		return ""
	}
	if gg.Geohash != "" {
		return gg.Geohash
	}
	if gg.Geotile != "" {
		return gg.Geotile
	}
	return gg.Geohex
}

func (gg GeoGridQuery) MarshalJSON() ([]byte, error) {
	m := map[string]any{}
	if gg.Field != "" {
		cell := map[string]any{}
		if gg.Geohash != "" {
			cell["geohash"] = gg.Geohash
		}
		if gg.Geotile != "" {
			cell["geotile"] = gg.Geotile
		}
		if gg.Geohex != "" {
			cell["geohex"] = gg.Geohex
		}
		m[gg.Field] = cell
	}
	if gg.IgnoreUnmapped {
		m["ignore_unmapped"] = true
	}
	if gg.Boost != nil {
		m["boost"] = *gg.Boost
	}
	if gg.Name != "" {
		m["_name"] = gg.Name
	}
	return json.Marshal(m)
}

func (gg *GeoGridQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	var out GeoGridQuery
	if rawBoost, ok := rawMap["boost"]; ok {
		b, err := parseOptionalNonNegativeBoost(rawBoost)
		if err != nil {
			return err
		}
		out.Boost = b
	}
	if rawName, ok := rawMap["_name"]; ok {
		var n string
		if err := json.Unmarshal(rawName, &n); err != nil {
			return fmt.Errorf("parsing_exception: [geo_grid] invalid [_name]")
		}
		out.Name = n
	}
	if rawIU, ok := rawMap["ignore_unmapped"]; ok {
		var iu any
		if err := json.Unmarshal(rawIU, &iu); err != nil {
			return fmt.Errorf("parsing_exception: [geo_grid] invalid [ignore_unmapped]")
		}
		b, err := parseFlexibleBool(iu)
		if err != nil {
			return err
		}
		out.IgnoreUnmapped = b
	}
	var fieldKeys []string
	for k := range rawMap {
		switch k {
		case "boost", "_name", "ignore_unmapped":
		default:
			fieldKeys = append(fieldKeys, k)
		}
	}
	if len(fieldKeys) != 1 {
		return fmt.Errorf("parsing_exception: [geo_grid] must specify exactly one field, got %d", len(fieldKeys))
	}
	out.Field = fieldKeys[0]

	var specMap map[string]json.RawMessage
	if err := json.Unmarshal(rawMap[out.Field], &specMap); err != nil {
		return fmt.Errorf("parsing_exception: [geo_grid] field [%s] must be an object", out.Field)
	}
	for k := range specMap {
		switch k {
		case "geohash", "geotile", "geohex", "ignore_unmapped", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [geo_grid] unknown field [%s]", k)
		}
	}
	var spec struct {
		Geohash        string          `json:"geohash"`
		Geotile        string          `json:"geotile"`
		Geohex         string          `json:"geohex"`
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		Boost          json.RawMessage `json:"boost"`
		Name           string          `json:"_name"`
	}
	if err := json.Unmarshal(rawMap[out.Field], &spec); err != nil {
		return fmt.Errorf("parsing_exception: [geo_grid] field [%s] invalid: %w", out.Field, err)
	}
	out.Geohash = strings.TrimSpace(spec.Geohash)
	out.Geotile = strings.TrimSpace(spec.Geotile)
	out.Geohex = strings.TrimSpace(spec.Geohex)
	gridCount := 0
	if out.Geohash != "" {
		gridCount++
	}
	if out.Geotile != "" {
		gridCount++
	}
	if out.Geohex != "" {
		gridCount++
	}
	if gridCount != 1 {
		return fmt.Errorf("parsing_exception: [geo_grid] requires exactly one of [geohash], [geotile], or [geohex]")
	}
	if spec.IgnoreUnmapped != nil {
		b, err := parseFlexibleBool(spec.IgnoreUnmapped)
		if err != nil {
			return err
		}
		out.IgnoreUnmapped = b
	}
	if len(spec.Boost) > 0 && out.Boost == nil {
		b, err := parseOptionalNonNegativeBoost(spec.Boost)
		if err != nil {
			return err
		}
		out.Boost = b
	}
	if spec.Name != "" && out.Name == "" {
		out.Name = spec.Name
	}
	*gg = out
	return nil
}
