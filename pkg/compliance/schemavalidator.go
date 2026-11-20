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

package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

const maxSchemaTypeExpansionDepth = 96

type specTypeKey struct {
	Namespace string
	Name      string
}

func (k specTypeKey) String() string {
	if k.Namespace == "" {
		return k.Name
	}
	return k.Namespace + "." + k.Name
}

type specTypeName struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (n specTypeName) key() specTypeKey {
	return specTypeKey{Namespace: n.Namespace, Name: n.Name}
}

type specSchemaFile struct {
	Endpoints []specEndpointDef `json:"endpoints"`
	Types     []specTypeDef     `json:"types"`
}

type specURLTemplate struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

type specExceptionDef struct {
	StatusCodes []int            `json:"statusCodes"`
	Body        specResponseBody `json:"body"`
}

type specEndpointDef struct {
	Name              string            `json:"name"`
	URLs              []specURLTemplate `json:"urls"`
	Request           *specTypeName     `json:"request"`
	Response          *specTypeName     `json:"response"`
	ResponseMediaType []string          `json:"responseMediaType"`
}

type specTypeDef struct {
	Kind       string             `json:"kind"`
	Name       specTypeName       `json:"name"`
	Generics   []specTypeName     `json:"generics"`
	Inherits   *specInheritsSpec  `json:"inherits"`
	Properties []specPropertyDef  `json:"properties"`
	Body       *specResponseBody  `json:"body"`
	Exceptions []specExceptionDef `json:"exceptions"`
	Type       *specTypeExpr      `json:"type"`
	Members    []specEnumMember   `json:"members"`
	IsOpen     bool               `json:"isOpen"`
	Behaviors  []specBehaviorDef  `json:"behaviors"`
}

type specInheritsSpec struct {
	Type     specTypeName   `json:"type"`
	Generics []specTypeExpr `json:"generics"`
}

type specResponseBody struct {
	Kind       string            `json:"kind"`
	Properties []specPropertyDef `json:"properties"`
	Value      *specTypeExpr     `json:"value"`
}

type specPropertyDef struct {
	Name     string       `json:"name"`
	Aliases  []string     `json:"aliases"`
	Required bool         `json:"required"`
	Type     specTypeExpr `json:"type"`
}

type specEnumMember struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

type specBehaviorDef struct {
	Type     specTypeName   `json:"type"`
	Generics []specTypeExpr `json:"generics"`
}

type specTypeExpr struct {
	Kind      string          `json:"kind"`
	Type      *specTypeName   `json:"type"`
	Generics  []specTypeExpr  `json:"generics"`
	Value     json.RawMessage `json:"value"`
	Key       *specTypeExpr   `json:"key"`
	SingleKey bool            `json:"singleKey"`
	Items     []specTypeExpr  `json:"items"`

	// Decoded form of Value depending on Kind ("array_of"/"dictionary_of" vs "literal_value").
	elemExpr   *specTypeExpr
	literalVal any
}

func (e *specTypeExpr) UnmarshalJSON(data []byte) error {
	type rawExpr struct {
		Kind      string          `json:"kind"`
		Type      *specTypeName   `json:"type"`
		Generics  []specTypeExpr  `json:"generics"`
		Value     json.RawMessage `json:"value"`
		Key       *specTypeExpr   `json:"key"`
		SingleKey bool            `json:"singleKey"`
		Items     []specTypeExpr  `json:"items"`
	}
	var r rawExpr
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	e.Kind = r.Kind
	e.Type = r.Type
	e.Generics = r.Generics
	e.Value = r.Value
	e.Key = r.Key
	e.SingleKey = r.SingleKey
	e.Items = r.Items

	switch r.Kind {
	case "array_of", "dictionary_of":
		if len(r.Value) > 0 && string(r.Value) != "null" {
			var sub specTypeExpr
			if err := json.Unmarshal(r.Value, &sub); err != nil {
				return fmt.Errorf("decoding %s value type expression: %w", r.Kind, err)
			}
			e.elemExpr = &sub
		}
	case "literal_value":
		if len(r.Value) > 0 {
			dec := json.NewDecoder(bytes.NewReader(r.Value))
			dec.UseNumber()
			var lit any
			if err := dec.Decode(&lit); err != nil {
				return fmt.Errorf("decoding literal_value: %w", err)
			}
			e.literalVal = lit
		}
	}
	return nil
}

// SpecSchemaValidator validates HTTP response payloads against the compiled
// elastic/elasticsearch-specification output/schema/schema.json model.
type SpecSchemaValidator struct {
	endpoints     map[string]specEndpointDef
	endpointNames []string
	types         map[specTypeKey]specTypeDef
	endpointCount int
	typeCount     int
}

// LoadSpecSchemaValidator reads and compiles an elasticsearch-specification schema.json file.
func LoadSpecSchemaValidator(path string) (*SpecSchemaValidator, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- trusted local specification schema path
	if err != nil {
		return nil, fmt.Errorf("reading specification schema %q: %w", path, err)
	}
	return ParseSpecSchemaValidator(raw)
}

// ParseSpecSchemaValidator compiles raw schema.json bytes into a SpecSchemaValidator.
func ParseSpecSchemaValidator(raw []byte) (*SpecSchemaValidator, error) {
	var parsed specSchemaFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parsing specification schema JSON: %w", err)
	}

	endpoints := make(map[string]specEndpointDef, len(parsed.Endpoints))
	endpointNames := make([]string, 0, len(parsed.Endpoints))
	for _, ep := range parsed.Endpoints {
		if ep.Name == "" {
			continue
		}
		if _, exists := endpoints[ep.Name]; !exists {
			endpointNames = append(endpointNames, ep.Name)
		}
		endpoints[ep.Name] = ep
	}
	sort.Strings(endpointNames)

	types := make(map[specTypeKey]specTypeDef, len(parsed.Types))
	for _, td := range parsed.Types {
		if td.Name.Name == "" {
			continue
		}
		types[td.Name.key()] = td
	}

	return &SpecSchemaValidator{
		endpoints:     endpoints,
		endpointNames: endpointNames,
		types:         types,
		endpointCount: len(parsed.Endpoints),
		typeCount:     len(parsed.Types),
	}, nil
}

// EndpointCount returns the total number of REST endpoints loaded from schema.json.
func (v *SpecSchemaValidator) EndpointCount() int {
	if v == nil {
		return 0
	}
	return v.endpointCount
}

// TypeCount returns the total number of compiled types loaded from schema.json.
func (v *SpecSchemaValidator) TypeCount() int {
	if v == nil {
		return 0
	}
	return v.typeCount
}

// HasEndpoint reports whether the named REST endpoint exists in schema.json.
func (v *SpecSchemaValidator) HasEndpoint(endpoint string) bool {
	if v == nil {
		return false
	}
	_, ok := v.endpoints[strings.TrimSpace(endpoint)]
	return ok
}

func isSpecWildcardTargetSegment(seg string) bool {
	switch seg {
	case "_all", "_local", "_master":
		return true
	default:
		return false
	}
}

func matchSpecURLTemplate(method, cleanPath string, tmpl specURLTemplate) (bool, int) {
	methodOK := false
	for _, m := range tmpl.Methods {
		if strings.EqualFold(m, method) {
			methodOK = true
			break
		}
	}
	if !methodOK {
		return false, 0
	}
	if tmpl.Path == "/" && cleanPath == "/" {
		return true, 100
	}
	tSegs := strings.Split(strings.Trim(tmpl.Path, "/"), "/")
	pSegs := strings.Split(strings.Trim(cleanPath, "/"), "/")
	if tmpl.Path == "/" || cleanPath == "/" || len(tSegs) != len(pSegs) {
		return false, 0
	}
	literalScore := 0
	for i := range tSegs {
		if strings.HasPrefix(tSegs[i], "{") && strings.HasSuffix(tSegs[i], "}") {
			if pSegs[i] == "" || (strings.HasPrefix(pSegs[i], "_") && !isSpecWildcardTargetSegment(pSegs[i])) {
				return false, 0
			}
			literalScore += 1
			continue
		}
		if tSegs[i] != pSegs[i] {
			return false, 0
		}
		literalScore += 10
	}
	return true, literalScore
}

// MatchEndpoint matches an HTTP method and URL path against endpoint URL templates in schema.json.
// If candidates are provided, only those endpoint names are considered; otherwise all endpoints are searched.
func (v *SpecSchemaValidator) MatchEndpoint(method, urlPath string, candidates ...string) string {
	if v == nil {
		return ""
	}
	cleanPath := urlPath
	if cleanPath == "" {
		cleanPath = "/"
	}
	names := candidates
	if len(names) == 0 {
		names = v.endpointNames
	}
	bestName := ""
	bestScore := -1
	for _, epName := range names {
		ep, ok := v.endpoints[epName]
		if !ok {
			continue
		}
		for _, u := range ep.URLs {
			if matched, score := matchSpecURLTemplate(method, cleanPath, u); matched && score > bestScore {
				bestScore = score
				bestName = epName
			}
		}
	}
	return bestName
}

// ValidateHTTPResponse validates an HTTP response payload given its HTTP status code and endpoint name.
// For 2xx/3xx responses it delegates to ValidateEndpointResponse. For 4xx/5xx responses it validates
// against declared endpoint exception schemas (e.g. get 404, cluster.health 408) or the standard
// Elasticsearch structured {"error": ...} response envelope.
func (v *SpecSchemaValidator) ValidateHTTPResponse(endpoint string, statusCode int, payload []byte) error {
	if v == nil {
		return fmt.Errorf("nil SpecSchemaValidator")
	}
	epName := strings.TrimSpace(endpoint)
	ep, ok := v.endpoints[epName]
	if !ok {
		return fmt.Errorf("unknown specification endpoint %q", endpoint)
	}
	if statusCode < 400 {
		return v.ValidateEndpointResponse(epName, payload)
	}

	trimmedPayload := bytes.TrimSpace(payload)
	if len(trimmedPayload) == 0 {
		if ep.Response != nil {
			if respDef, exists := v.types[ep.Response.key()]; exists {
				if statusCode == 404 && respDef.Body != nil && respDef.Body.Kind == "no_body" {
					return nil
				}
				for _, exc := range respDef.Exceptions {
					for _, code := range exc.StatusCodes {
						if code == statusCode && exc.Body.Kind == "no_body" {
							return nil
						}
					}
				}
			}
		}
		return fmt.Errorf("endpoint %q ($): empty error payload on HTTP %d", epName, statusCode)
	}

	root, err := decodeStrictJSONPayload(trimmedPayload)
	if err != nil {
		return fmt.Errorf("endpoint %q ($): invalid JSON error response on HTTP %d: %w", epName, statusCode, err)
	}

	if ep.Response != nil {
		if respDef, exists := v.types[ep.Response.key()]; exists {
			bindings := unboundGenericBindings(respDef.Generics)
			for _, exc := range respDef.Exceptions {
				for _, code := range exc.StatusCodes {
					if code == statusCode {
						excDef := specTypeDef{
							Kind: "response",
							Name: specTypeName{
								Namespace: respDef.Name.Namespace,
								Name:      respDef.Name.Name + ".Exception",
							},
							Body: &exc.Body,
						}
						if err := v.validateNamedType("$", root, excDef, bindings, 0); err != nil {
							return fmt.Errorf("endpoint %q (HTTP %d): %w", epName, statusCode, err)
						}
						return nil
					}
				}
			}
		}
	}

	obj, ok := root.(map[string]any)
	if !ok {
		return fmt.Errorf("endpoint %q ($): expected JSON object error envelope on HTTP %d, got %s", epName, statusCode, describeJSONKind(root))
	}
	errVal, hasErr := obj["error"]
	if !hasErr {
		return fmt.Errorf("endpoint %q ($): expected \"error\" field in HTTP %d response", epName, statusCode)
	}
	if errBaseDef, hasErrBase := v.types[specTypeKey{Namespace: "_types", Name: "ErrorResponseBase"}]; hasErrBase {
		if _, isLegacyStr := errVal.(string); !isLegacyStr {
			if err := v.validateNamedType("$", root, errBaseDef, nil, 0); err != nil {
				return fmt.Errorf("endpoint %q (HTTP %d): %w", epName, statusCode, err)
			}
			if statusField, hasStatus := obj["status"]; hasStatus {
				if sf, sOk := toNumericFloat64(statusField); sOk && int(sf) != statusCode {
					return fmt.Errorf("endpoint %q ($): HTTP %d error payload status=%d mismatch", epName, statusCode, int(sf))
				}
			}
		}
	}
	return nil
}

// ValidateEndpointResponse validates a serialized JSON response payload against the
// compiled response schema of the given Elasticsearch specification endpoint name
// (for example, "info", "search", "count", "get", "indices.create", "cluster.health").
func (v *SpecSchemaValidator) ValidateEndpointResponse(endpoint string, payload []byte) error {
	if v == nil {
		return fmt.Errorf("nil SpecSchemaValidator")
	}
	epName := strings.TrimSpace(endpoint)
	ep, ok := v.endpoints[epName]
	if !ok {
		return fmt.Errorf("unknown specification endpoint %q", endpoint)
	}

	trimmedPayload := bytes.TrimSpace(payload)
	if ep.Response == nil {
		if len(trimmedPayload) == 0 {
			return nil
		}
		if acceptsNonJSONMedia(ep.ResponseMediaType) && trimmedPayload[0] != '{' && trimmedPayload[0] != '[' {
			return nil
		}
		_, err := decodeStrictJSONPayload(trimmedPayload)
		if err != nil {
			return fmt.Errorf("endpoint %q: invalid JSON payload: %w", epName, err)
		}
		return nil
	}

	respKey := ep.Response.key()
	respDef, ok := v.types[respKey]
	if !ok {
		return fmt.Errorf("endpoint %q: response type %q not found in specification schema", epName, respKey.String())
	}

	if respDef.Kind == "response" && respDef.Body != nil && respDef.Body.Kind == "no_body" {
		if len(trimmedPayload) != 0 {
			return fmt.Errorf("endpoint %q ($): expected empty response body (no_body), got %d bytes", epName, len(trimmedPayload))
		}
		return nil
	}

	if len(trimmedPayload) == 0 {
		if acceptsNonJSONMedia(ep.ResponseMediaType) {
			return nil
		}
		return fmt.Errorf("endpoint %q ($): empty response payload for typed response %s", epName, respKey.String())
	}

	if acceptsNonJSONMedia(ep.ResponseMediaType) && (!acceptsJSONMedia(ep.ResponseMediaType) ||
		((trimmedPayload[0] != '{' && trimmedPayload[0] != '[') && respDef.Body != nil && respDef.Body.Value != nil && respDef.Body.Value.Kind == "array_of")) {
		return nil
	}

	root, err := decodeStrictJSONPayload(trimmedPayload)
	if err != nil {
		// Some endpoints (e.g. cat.*) support both text/plain and application/json;
		// if payload is non-JSON and text media is permitted, validate as string when applicable.
		if acceptsNonJSONMedia(ep.ResponseMediaType) {
			bindings := unboundGenericBindings(respDef.Generics)
			if textErr := v.validateNamedType("$", string(payload), respDef, bindings, 0); textErr == nil {
				return nil
			}
		}
		return fmt.Errorf("endpoint %q ($): invalid JSON response: %w", epName, err)
	}

	bindings := unboundGenericBindings(respDef.Generics)
	if err := v.validateNamedType("$", root, respDef, bindings, 0); err != nil {
		return fmt.Errorf("endpoint %q: %w", epName, err)
	}
	return nil
}

func acceptsJSONMedia(mediaTypes []string) bool {
	if len(mediaTypes) == 0 {
		return true
	}
	for _, mt := range mediaTypes {
		if strings.Contains(strings.ToLower(mt), "json") {
			return true
		}
	}
	return false
}

func acceptsNonJSONMedia(mediaTypes []string) bool {
	for _, mt := range mediaTypes {
		lower := strings.ToLower(mt)
		if !strings.Contains(lower, "json") {
			return true
		}
	}
	return false
}

func decodeStrictJSONPayload(trimmed []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON token %v", extra)
		}
		return nil, fmt.Errorf("invalid trailing data after JSON root: %w", err)
	}
	return val, nil
}

func unboundGenericBindings(generics []specTypeName) map[specTypeKey]specTypeExpr {
	if len(generics) == 0 {
		return nil
	}
	out := make(map[specTypeKey]specTypeExpr, len(generics))
	for _, g := range generics {
		out[g.key()] = specTypeExpr{Kind: "user_defined_value"}
	}
	return out
}

func substituteTypeExpr(expr specTypeExpr, bindings map[specTypeKey]specTypeExpr) specTypeExpr {
	if len(bindings) == 0 {
		return expr
	}
	switch expr.Kind {
	case "instance_of":
		if expr.Type != nil {
			if bound, ok := bindings[expr.Type.key()]; ok {
				return bound
			}
		}
		if len(expr.Generics) == 0 {
			return expr
		}
		cp := expr
		cp.Generics = make([]specTypeExpr, len(expr.Generics))
		for i, g := range expr.Generics {
			cp.Generics[i] = substituteTypeExpr(g, bindings)
		}
		return cp
	case "array_of":
		if expr.elemExpr == nil {
			return expr
		}
		cp := expr
		sub := substituteTypeExpr(*expr.elemExpr, bindings)
		cp.elemExpr = &sub
		return cp
	case "dictionary_of":
		cp := expr
		if expr.Key != nil {
			kSub := substituteTypeExpr(*expr.Key, bindings)
			cp.Key = &kSub
		}
		if expr.elemExpr != nil {
			vSub := substituteTypeExpr(*expr.elemExpr, bindings)
			cp.elemExpr = &vSub
		}
		return cp
	case "union_of":
		if len(expr.Items) == 0 {
			return expr
		}
		cp := expr
		cp.Items = make([]specTypeExpr, len(expr.Items))
		for i, item := range expr.Items {
			cp.Items[i] = substituteTypeExpr(item, bindings)
		}
		return cp
	default:
		return expr
	}
}

func bindTypeArguments(params []specTypeName, args []specTypeExpr, callerBindings map[specTypeKey]specTypeExpr) map[specTypeKey]specTypeExpr {
	if len(params) == 0 {
		return nil
	}
	callee := make(map[specTypeKey]specTypeExpr, len(params))
	for i, p := range params {
		if i < len(args) {
			callee[p.key()] = substituteTypeExpr(args[i], callerBindings)
		} else {
			callee[p.key()] = specTypeExpr{Kind: "user_defined_value"}
		}
	}
	return callee
}

func (v *SpecSchemaValidator) validateTypeExpr(path string, val any, expr specTypeExpr, bindings map[specTypeKey]specTypeExpr, depth int) error {
	if depth > maxSchemaTypeExpansionDepth {
		return nil
	}
	switch expr.Kind {
	case "user_defined_value", "":
		return nil

	case "literal_value":
		if !schemaLiteralEquals(val, expr.literalVal) {
			return fmt.Errorf("%s: expected literal %v (%T), got %v (%T)", path, expr.literalVal, expr.literalVal, val, val)
		}
		return nil

	case "array_of":
		arr, ok := val.([]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON array, got %s", path, describeJSONKind(val))
		}
		if expr.elemExpr == nil {
			return nil
		}
		elemExpr := substituteTypeExpr(*expr.elemExpr, bindings)
		for i, item := range arr {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := v.validateTypeExpr(itemPath, item, elemExpr, nil, 0); err != nil {
				return err
			}
		}
		return nil

	case "dictionary_of":
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON object (dictionary), got %s", path, describeJSONKind(val))
		}
		if expr.SingleKey && len(obj) != 1 {
			return fmt.Errorf("%s: expected single-key dictionary object, got %d keys", path, len(obj))
		}
		var keyExpr *specTypeExpr
		if expr.Key != nil {
			ke := substituteTypeExpr(*expr.Key, bindings)
			keyExpr = &ke
		}
		var valExpr *specTypeExpr
		if expr.elemExpr != nil {
			ve := substituteTypeExpr(*expr.elemExpr, bindings)
			valExpr = &ve
		}

		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			entryPath := path + "." + k
			if keyExpr != nil {
				if err := v.validateDictionaryKey(entryPath, k, *keyExpr, 0); err != nil {
					return err
				}
			}
			if valExpr != nil {
				entryVal := obj[k]
				if entryVal == nil {
					// Dictionary entries in ES responses (e.g., field values or dynamic metadata)
					// allow null only if value type allows null or user_defined_value; check directly.
					if err := v.validateTypeExpr(entryPath, entryVal, *valExpr, nil, 0); err != nil {
						return err
					}
					continue
				}
				if err := v.validateTypeExpr(entryPath, entryVal, *valExpr, nil, 0); err != nil {
					return err
				}
			}
		}
		return nil

	case "union_of":
		if len(expr.Items) == 0 {
			return nil
		}
		var firstErr error
		for _, item := range expr.Items {
			sub := substituteTypeExpr(item, bindings)
			err := v.validateTypeExpr(path, val, sub, nil, depth+1)
			if err == nil {
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		return fmt.Errorf("%s: value %s did not match any of %d union variants (first mismatch: %v)", path, describeJSONKind(val), len(expr.Items), firstErr)

	case "instance_of":
		if expr.Type == nil {
			return nil
		}
		tKey := expr.Type.key()
		if bound, ok := bindings[tKey]; ok {
			return v.validateTypeExpr(path, val, bound, nil, depth+1)
		}
		if expr.Type.Namespace == "_builtins" {
			return validateBuiltinType(path, val, expr.Type.Name)
		}
		if expr.Type.Namespace == "_types" && expr.Type.Name == "EsqlColumns" {
			if obj, isObj := val.(map[string]any); isObj {
				return validateEsqlColumnsJSON(path, obj)
			}
		}
		if expr.Type.Namespace == "_types" {
			if err := validateIntegralConstraint(path, val, expr.Type.Name); err != nil {
				return err
			}
		}
		def, ok := v.types[tKey]
		if !ok {
			return fmt.Errorf("%s: referenced schema type %q not found", path, tKey.String())
		}
		calleeBindings := bindTypeArguments(def.Generics, expr.Generics, bindings)
		return v.validateNamedType(path, val, def, calleeBindings, depth+1)

	default:
		return fmt.Errorf("%s: unsupported type expression kind %q", path, expr.Kind)
	}
}

func (v *SpecSchemaValidator) validateDictionaryKey(path string, key string, keyExpr specTypeExpr, depth int) error {
	if depth > maxSchemaTypeExpansionDepth {
		return nil
	}
	// JSON object keys are always serialized strings; numeric/boolean key aliases in ES
	// (such as shard numbers or status codes) serialize as string representations of those scalars.
	if err := v.validateTypeExpr(path+"(key)", key, keyExpr, nil, depth+1); err == nil {
		return nil
	}
	if num := json.Number(key); isValidJSONNumber(key) {
		if err := v.validateTypeExpr(path+"(key)", num, keyExpr, nil, depth+1); err == nil {
			return nil
		}
	}
	if key == "true" || key == "false" {
		if err := v.validateTypeExpr(path+"(key)", key == "true", keyExpr, nil, depth+1); err == nil {
			return nil
		}
	}
	return v.validateTypeExpr(path+"(key)", key, keyExpr, nil, depth+1)
}

func (v *SpecSchemaValidator) validateNamedType(path string, val any, def specTypeDef, bindings map[specTypeKey]specTypeExpr, depth int) error {
	if depth > maxSchemaTypeExpansionDepth {
		return nil
	}
	switch def.Kind {
	case "type_alias":
		if def.Type == nil {
			return nil
		}
		sub := substituteTypeExpr(*def.Type, bindings)
		return v.validateTypeExpr(path, val, sub, nil, depth+1)

	case "enum":
		return validateEnumType(path, val, def)

	case "interface":
		return v.validateObjectShape(path, val, def, def.Properties, bindings, depth)

	case "response":
		if def.Body == nil {
			if def.Inherits != nil {
				return v.validateObjectShape(path, val, def, nil, bindings, depth)
			}
			return nil
		}
		switch def.Body.Kind {
		case "no_body":
			if val != nil {
				return fmt.Errorf("%s: expected empty body, got %s", path, describeJSONKind(val))
			}
			return nil
		case "value":
			if def.Body.Value == nil {
				return nil
			}
			sub := substituteTypeExpr(*def.Body.Value, bindings)
			return v.validateTypeExpr(path, val, sub, nil, depth+1)
		case "properties":
			return v.validateObjectShape(path, val, def, def.Body.Properties, bindings, depth)
		default:
			return fmt.Errorf("%s: unsupported response body kind %q", path, def.Body.Kind)
		}

	default:
		return nil
	}
}

type resolvedProperty struct {
	Name     string
	Aliases  []string
	Required bool
	Type     specTypeExpr
}

type resolvedAddlProps struct {
	Key   specTypeExpr
	Value specTypeExpr
}

func (v *SpecSchemaValidator) collectObjectHierarchy(
	def specTypeDef,
	ownProps []specPropertyDef,
	bindings map[specTypeKey]specTypeExpr,
	visited map[specTypeKey]bool,
) ([]resolvedProperty, *resolvedAddlProps, error) {
	tKey := def.Name.key()
	if visited[tKey] {
		return nil, nil, nil
	}
	visited[tKey] = true

	var props []resolvedProperty
	var addl *resolvedAddlProps

	if def.Inherits != nil {
		parentKey := def.Inherits.Type.key()
		parentDef, ok := v.types[parentKey]
		if !ok {
			return nil, nil, fmt.Errorf("inherited schema type %q not found (from %s)", parentKey.String(), tKey.String())
		}
		parentBindings := bindTypeArguments(parentDef.Generics, def.Inherits.Generics, bindings)
		var parentBodyProps []specPropertyDef
		if parentDef.Kind == "response" && parentDef.Body != nil && parentDef.Body.Kind == "properties" {
			parentBodyProps = parentDef.Body.Properties
		} else {
			parentBodyProps = parentDef.Properties
		}
		inheritedProps, inheritedAddl, err := v.collectObjectHierarchy(parentDef, parentBodyProps, parentBindings, visited)
		if err != nil {
			return nil, nil, err
		}
		props = append(props, inheritedProps...)
		if inheritedAddl != nil {
			addl = inheritedAddl
		}
	}

	indexByName := make(map[string]int, len(props))
	for i, p := range props {
		indexByName[p.Name] = i
	}
	for _, p := range ownProps {
		rp := resolvedProperty{
			Name:     p.Name,
			Aliases:  p.Aliases,
			Required: p.Required,
			Type:     substituteTypeExpr(p.Type, bindings),
		}
		if idx, exists := indexByName[p.Name]; exists {
			props[idx] = rp
		} else {
			indexByName[p.Name] = len(props)
			props = append(props, rp)
		}
	}

	for _, b := range def.Behaviors {
		if (b.Type.Name == "AdditionalProperties" || b.Type.Name == "AdditionalProperty") && len(b.Generics) >= 2 {
			addl = &resolvedAddlProps{
				Key:   substituteTypeExpr(b.Generics[0], bindings),
				Value: substituteTypeExpr(b.Generics[1], bindings),
			}
		}
	}

	return props, addl, nil
}

func (v *SpecSchemaValidator) validateObjectShape(
	path string,
	val any,
	def specTypeDef,
	ownProps []specPropertyDef,
	bindings map[specTypeKey]specTypeExpr,
	depth int,
) error {
	obj, ok := val.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: expected JSON object for %s, got %s", path, def.Name.key().String(), describeJSONKind(val))
	}

	props, addl, err := v.collectObjectHierarchy(def, ownProps, bindings, make(map[specTypeKey]bool))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	knownKeys := make(map[string]resolvedProperty, len(props)*2)
	for _, prop := range props {
		knownKeys[prop.Name] = prop
		for _, alias := range prop.Aliases {
			if _, exists := knownKeys[alias]; !exists {
				knownKeys[alias] = prop
			}
		}
	}

	// 1. Verify all required properties are present (under canonical name or a declared alias).
	defKey := def.Name.key()
	for _, prop := range props {
		if !prop.Required || isConditionallyOmittedSpecProperty(defKey, prop.Name) {
			continue
		}
		matchedKey := ""
		if _, present := obj[prop.Name]; present {
			matchedKey = prop.Name
		} else {
			for _, alias := range prop.Aliases {
				if _, present := obj[alias]; present {
					matchedKey = alias
					break
				}
			}
		}
		if matchedKey == "" {
			return fmt.Errorf("%s: missing required property %q on %s", path, prop.Name, def.Name.key().String())
		}
	}

	// 2. Deterministically validate all present properties (and AdditionalProperties if declared).
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	matchedDeclared := 0
	for _, k := range keys {
		propVal := obj[k]
		propPath := path + "." + k
		if prop, declared := knownKeys[k]; declared {
			matchedDeclared++
			if propVal == nil && !prop.Required {
				// Optional properties in elasticsearch-specification omit `| null` even when
				// wire JSON serializes absent values as explicit null (e.g. max_score: null).
				continue
			}
			if err := v.validateTypeExpr(propPath, propVal, prop.Type, nil, 0); err != nil {
				return err
			}
			continue
		}
		if addl != nil {
			if err := v.validateDictionaryKey(propPath, k, addl.Key, 0); err != nil {
				return err
			}
			if propVal != nil {
				if err := v.validateTypeExpr(propPath, propVal, addl.Value, nil, 0); err != nil {
					return err
				}
			}
		}
	}

	// When validating inside a union (depth > 1), prevent a non-empty object with zero matching
	// declared keys from spuriously matching an unrelated all-optional interface variant.
	if depth > 1 && addl == nil && len(obj) > 0 && len(props) > 0 && matchedDeclared == 0 {
		return fmt.Errorf("%s: object keys do not match any declared properties of %s", path, def.Name.key().String())
	}

	return nil
}

func validateEsqlColumnsJSON(path string, obj map[string]any) error {
	colsRaw, hasCols := obj["columns"]
	if !hasCols {
		return fmt.Errorf("%s: missing required property \"columns\" on EsqlColumns JSON payload", path)
	}
	cols, ok := colsRaw.([]any)
	if !ok {
		return fmt.Errorf("%s.columns: expected JSON array, got %s", path, describeJSONKind(colsRaw))
	}
	for i, c := range cols {
		cm, ok := c.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.columns[%d]: expected JSON object, got %s", path, i, describeJSONKind(c))
		}
		if _, okName := cm["name"].(string); !okName {
			return fmt.Errorf("%s.columns[%d].name: expected string", path, i)
		}
		if _, okType := cm["type"].(string); !okType {
			return fmt.Errorf("%s.columns[%d].type: expected string", path, i)
		}
	}
	valsRaw, hasVals := obj["values"]
	if !hasVals {
		return fmt.Errorf("%s: missing required property \"values\" on EsqlColumns JSON payload", path)
	}
	vals, ok := valsRaw.([]any)
	if !ok {
		return fmt.Errorf("%s.values: expected JSON array, got %s", path, describeJSONKind(valsRaw))
	}
	for i, row := range vals {
		if _, okRow := row.([]any); !okRow {
			return fmt.Errorf("%s.values[%d]: expected JSON row array, got %s", path, i, describeJSONKind(row))
		}
	}
	return nil
}

// isConditionallyOmittedSpecProperty identifies telemetry/metadata fields that
// elastic/elasticsearch-specification 8.15 marks required even when omitted by default
// (such as segment file_sizes when include_segment_file_sizes=false, non-tiered node role counts,
// ILM/DLM transition fields on plain data streams, or unscored rank_eval hits).
func isConditionallyOmittedSpecProperty(tKey specTypeKey, propName string) bool {
	switch tKey {
	case specTypeKey{Namespace: "_types", Name: "SegmentsStats"}:
		return propName == "file_sizes"
	case specTypeKey{Namespace: "cluster.stats", Name: "ClusterNodes"}:
		return propName == "indexing_pressure"
	case specTypeKey{Namespace: "cluster.stats", Name: "ClusterNodeCount"}:
		switch propName {
		case "data_cold", "data_content", "data_hot", "data_warm", "ml", "transform", "voting_only":
			return true
		}
	case specTypeKey{Namespace: "cluster.stats", Name: "ClusterOperatingSystem"}:
		return propName == "pretty_names"
	case specTypeKey{Namespace: "indices._types", Name: "DataStream"}:
		switch propName {
		case "next_generation_managed_by", "prefer_ilm", "template":
			return true
		}
	case specTypeKey{Namespace: "indices._types", Name: "DataStreamIndex"}:
		return propName == "managed_by" || propName == "prefer_ilm"
	case specTypeKey{Namespace: "_global.rank_eval", Name: "RankEvalHit"}:
		return propName == "_score"
	}
	return false
}

func validateBuiltinType(path string, val any, builtinName string) error {
	switch builtinName {
	case "string":
		if _, ok := val.(string); !ok {
			return fmt.Errorf("%s: expected string, got %s", path, describeJSONKind(val))
		}
		return nil
	case "boolean":
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("%s: expected boolean, got %s", path, describeJSONKind(val))
		}
		return nil
	case "number":
		if !isSchemaJSONNumber(val) {
			return fmt.Errorf("%s: expected number, got %s", path, describeJSONKind(val))
		}
		return nil
	case "null":
		if val != nil {
			return fmt.Errorf("%s: expected null, got %s", path, describeJSONKind(val))
		}
		return nil
	case "binary":
		switch val.(type) {
		case string, []any:
			return nil
		default:
			return fmt.Errorf("%s: expected binary (base64 string or byte array), got %s", path, describeJSONKind(val))
		}
	case "void":
		if val != nil {
			if m, ok := val.(map[string]any); ok && len(m) == 0 {
				return nil
			}
			return fmt.Errorf("%s: expected void/empty, got %s", path, describeJSONKind(val))
		}
		return nil
	default:
		return fmt.Errorf("%s: unknown builtin type %q", path, builtinName)
	}
}

func validateIntegralConstraint(path string, val any, typeName string) error {
	switch typeName {
	case "integer", "long", "short", "byte", "uint", "ulong", "unsigned_long":
		if !isSchemaJSONNumber(val) {
			return fmt.Errorf("%s: expected integer (%s), got %s", path, typeName, describeJSONKind(val))
		}
		okInt, nonNeg := isIntegralNumber(val)
		if !okInt {
			return fmt.Errorf("%s: expected integral %s value, got %v", path, typeName, val)
		}
		if (typeName == "uint" || typeName == "ulong" || typeName == "unsigned_long") && !nonNeg {
			return fmt.Errorf("%s: expected non-negative %s value, got %v", path, typeName, val)
		}
	}
	return nil
}

func validateEnumType(path string, val any, def specTypeDef) error {
	var strVal string
	switch tv := val.(type) {
	case string:
		strVal = tv
	case bool:
		strVal = strconv.FormatBool(tv)
	default:
		return fmt.Errorf("%s: expected enum string for %s, got %s", path, def.Name.key().String(), describeJSONKind(val))
	}

	if def.IsOpen {
		if _, isStr := val.(string); !isStr {
			return fmt.Errorf("%s: expected string for open enum %s, got %s", path, def.Name.key().String(), describeJSONKind(val))
		}
		return nil
	}

	for _, m := range def.Members {
		if m.Name == strVal {
			if _, isBool := val.(bool); isBool && m.Name != "true" && m.Name != "false" {
				continue
			}
			return nil
		}
		for _, alias := range m.Aliases {
			if alias == strVal {
				return nil
			}
		}
	}
	return fmt.Errorf("%s: value %q is not a valid member of enum %s", path, strVal, def.Name.key().String())
}

func isSchemaJSONNumber(val any) bool {
	switch tv := val.(type) {
	case json.Number:
		return isValidJSONNumber(string(tv))
	case float64:
		return !math.IsNaN(tv) && !math.IsInf(tv, 0)
	case int, int64, uint, uint64:
		return true
	default:
		return false
	}
}

func isValidJSONNumber(s string) bool {
	if s == "" {
		return false
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		return true
	}
	f, err := strconv.ParseFloat(s, 64)
	return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func isIntegralNumber(val any) (integral bool, nonNegative bool) {
	switch tv := val.(type) {
	case json.Number:
		s := string(tv)
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return true, i >= 0
		}
		if _, err := strconv.ParseUint(s, 10, 64); err == nil {
			return true, true
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return false, false
		}
		return math.Trunc(f) == f, f >= 0
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return false, false
		}
		return math.Trunc(tv) == tv, tv >= 0
	case int:
		return true, tv >= 0
	case int64:
		return true, tv >= 0
	case uint, uint64:
		return true, true
	default:
		return false, false
	}
}

func schemaLiteralEquals(actual any, expected any) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	switch ev := expected.(type) {
	case string:
		av, ok := actual.(string)
		return ok && av == ev
	case bool:
		av, ok := actual.(bool)
		return ok && av == ev
	case json.Number:
		if !isSchemaJSONNumber(actual) {
			return false
		}
		af, aok := toNumericFloat64(actual)
		ef, eok := toNumericFloat64(ev)
		return aok && eok && af == ef
	case float64:
		if !isSchemaJSONNumber(actual) {
			return false
		}
		af, aok := toNumericFloat64(actual)
		return aok && af == ev
	default:
		return actual == expected
	}
}

func describeJSONKind(val any) string {
	switch tv := val.(type) {
	case nil:
		return "null"
	case bool:
		return fmt.Sprintf("boolean(%v)", tv)
	case string:
		if len(tv) > 40 {
			return fmt.Sprintf("string(%q...)", tv[:40])
		}
		return fmt.Sprintf("string(%q)", tv)
	case json.Number:
		return fmt.Sprintf("number(%s)", string(tv))
	case float64:
		return fmt.Sprintf("number(%v)", tv)
	case []any:
		return fmt.Sprintf("array(len=%d)", len(tv))
	case map[string]any:
		return fmt.Sprintf("object(keys=%d)", len(tv))
	default:
		return fmt.Sprintf("%T", val)
	}
}
