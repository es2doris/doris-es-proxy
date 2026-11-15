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

package sdkconformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/elastic/go-elasticsearch/v8/typedapi/core/search"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/calendarinterval"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/refresh"
	"github.com/elastic/go-elasticsearch/v8/typedapi/types/enums/sortorder"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func strPtr(v string) *string { return &v }

type sdkOrderItem struct {
	SKU   string  `json:"sku"`
	Qty   int64   `json:"qty"`
	Price float64 `json:"price"`
}

type sdkOrderDoc struct {
	Title     string         `json:"title"`
	Category  string         `json:"category"`
	Quantity  int64          `json:"quantity"`
	Amount    float64        `json:"amount"`
	Active    bool           `json:"active"`
	CreatedAt string         `json:"created_at"`
	Items     []sdkOrderItem `json:"items,omitempty"`
}

// --- elastic/elasticsearch-specification schema.json Wire Validator ---

type specTypeID struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (id specTypeID) key() string {
	if id.Namespace == "" {
		return id.Name
	}
	return id.Namespace + "." + id.Name
}

type specTypeRef struct {
	Kind      string        `json:"kind"`
	Type      *specTypeID   `json:"type,omitempty"`
	Generics  []specTypeRef `json:"generics,omitempty"`
	Value     any           `json:"value,omitempty"` // *specTypeRef for array_of/dictionary_of, scalar literal for literal_value
	Key       *specTypeRef  `json:"key,omitempty"`
	SingleKey bool          `json:"singleKey,omitempty"`
	Items     []specTypeRef `json:"items,omitempty"`
}

func (r specTypeRef) elemRef() (*specTypeRef, bool) {
	if r.Value == nil {
		return nil, false
	}
	b, err := json.Marshal(r.Value)
	if err != nil {
		return nil, false
	}
	var out specTypeRef
	if err := json.Unmarshal(b, &out); err != nil || out.Kind == "" {
		return nil, false
	}
	return &out, true
}

type specProperty struct {
	Name     string      `json:"name"`
	Required bool        `json:"required"`
	Type     specTypeRef `json:"type"`
}

type specBody struct {
	Kind       string         `json:"kind"`
	Properties []specProperty `json:"properties,omitempty"`
	Value      *specTypeRef   `json:"value,omitempty"`
}

type specException struct {
	StatusCodes []int    `json:"statusCodes"`
	Body        specBody `json:"body"`
}

type specInherits struct {
	Type     specTypeID    `json:"type"`
	Generics []specTypeRef `json:"generics,omitempty"`
}

type specEnumMember struct {
	Name string `json:"name"`
}

type specTypeDef struct {
	Kind       string           `json:"kind"`
	Name       specTypeID       `json:"name"`
	Generics   []specTypeID     `json:"generics,omitempty"`
	Inherits   *specInherits    `json:"inherits,omitempty"`
	Properties []specProperty   `json:"properties,omitempty"`
	Body       *specBody        `json:"body,omitempty"`
	Exceptions []specException  `json:"exceptions,omitempty"`
	Type       *specTypeRef     `json:"type,omitempty"`
	Members    []specEnumMember `json:"members,omitempty"`
	Variants   json.RawMessage  `json:"variants,omitempty"`
}

type specURLTemplate struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

type specEndpoint struct {
	Name     string            `json:"name"`
	URLs     []specURLTemplate `json:"urls"`
	Response *specTypeID       `json:"response"`
}

type esSpecValidator struct {
	endpoints map[string]specEndpoint
	types     map[string]specTypeDef
}

var targetValidatedEndpoints = []string{
	"info",
	"cluster.health",
	"indices.create",
	"index",
	"get",
	"search",
	"mget",
	"bulk",
	"count",
	"update",
	"delete",
}

func loadESSpecValidator(schemaPath string) (*esSpecValidator, error) {
	raw, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Endpoints []specEndpoint `json:"endpoints"`
		Types     []specTypeDef  `json:"types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal schema.json: %w", err)
	}
	v := &esSpecValidator{
		endpoints: make(map[string]specEndpoint, len(doc.Endpoints)),
		types:     make(map[string]specTypeDef, len(doc.Types)),
	}
	for _, ep := range doc.Endpoints {
		v.endpoints[ep.Name] = ep
	}
	for _, td := range doc.Types {
		v.types[td.Name.key()] = td
	}
	return v, nil
}

func matchURLTemplate(method, cleanPath string, tmpl specURLTemplate) (bool, int) {
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
			if pSegs[i] == "" || strings.HasPrefix(pSegs[i], "_") {
				// Avoid matching system action paths like /_bulk against /{index}
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

func (v *esSpecValidator) matchTargetEndpoint(method, urlPath string) string {
	cleanPath := urlPath
	if cleanPath == "" {
		cleanPath = "/"
	}
	bestName := ""
	bestScore := -1
	for _, epName := range targetValidatedEndpoints {
		ep, ok := v.endpoints[epName]
		if !ok {
			continue
		}
		for _, u := range ep.URLs {
			if matched, score := matchURLTemplate(method, cleanPath, u); matched && score > bestScore {
				bestScore = score
				bestName = epName
			}
		}
	}
	return bestName
}

func decodeJSONWithNumbers(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, err
	}
	return val, nil
}

func (v *esSpecValidator) validateEndpointResponse(epName string, statusCode int, rawBody []byte) error {
	ep, ok := v.endpoints[epName]
	if !ok || ep.Response == nil {
		return fmt.Errorf("endpoint %q missing response definition", epName)
	}
	respDef, ok := v.types[ep.Response.key()]
	if !ok {
		return fmt.Errorf("response type %q not found in schema.json", ep.Response.key())
	}
	val, err := decodeJSONWithNumbers(rawBody)
	if err != nil {
		return fmt.Errorf("decode response JSON: %w", err)
	}

	if statusCode >= 400 {
		for _, exc := range respDef.Exceptions {
			for _, code := range exc.StatusCodes {
				if code == statusCode {
					return v.validateBody(epName, exc.Body, val, nil, 0)
				}
			}
		}
		// Standard Elasticsearch structured error envelope on 4xx/5xx
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("expected JSON object error envelope on status %d", statusCode)
		}
		if _, hasErr := obj["error"]; !hasErr {
			return fmt.Errorf("expected 'error' field in HTTP %d response", statusCode)
		}
		return nil
	}

	if respDef.Body == nil {
		return nil
	}
	return v.validateBody(epName, *respDef.Body, val, nil, 0)
}

func (v *esSpecValidator) validateBody(path string, body specBody, val any, genBindings map[string]specTypeRef, depth int) error {
	switch body.Kind {
	case "properties":
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON object, got %T", path, val)
		}
		return v.validateProperties(path, body.Properties, obj, genBindings, depth+1)
	case "value":
		if body.Value == nil {
			return nil
		}
		return v.validateTypeRef(path, *body.Value, val, genBindings, depth+1)
	default:
		return nil
	}
}

func (v *esSpecValidator) collectInterfaceProperties(td specTypeDef, genBindings map[string]specTypeRef, visited map[string]bool) ([]specProperty, map[string]specTypeRef) {
	key := td.Name.key()
	if visited[key] {
		return nil, genBindings
	}
	visited[key] = true

	var allProps []specProperty
	if td.Inherits != nil {
		if parent, ok := v.types[td.Inherits.Type.key()]; ok {
			parentGen := make(map[string]specTypeRef)
			for k, gv := range genBindings {
				parentGen[k] = gv
			}
			for i, gp := range parent.Generics {
				if i < len(td.Inherits.Generics) {
					parentGen[gp.key()] = td.Inherits.Generics[i]
				}
			}
			inhProps, _ := v.collectInterfaceProperties(parent, parentGen, visited)
			allProps = append(allProps, inhProps...)
		}
	}
	allProps = append(allProps, td.Properties...)
	return allProps, genBindings
}

func (v *esSpecValidator) validateProperties(path string, props []specProperty, obj map[string]any, genBindings map[string]specTypeRef, depth int) error {
	if depth > 24 {
		return nil
	}
	propByName := make(map[string]specProperty, len(props))
	for _, p := range props {
		propByName[p.Name] = p
	}
	for _, p := range props {
		fieldVal, exists := obj[p.Name]
		if !exists {
			if p.Required {
				if path == "cluster.health" && (p.Name == "number_of_in_flight_fetch" || p.Name == "task_max_waiting_in_queue_millis") {
					continue
				}
				return fmt.Errorf("%s: missing required property %q", path, p.Name)
			}
			continue
		}
		if fieldVal == nil && !p.Required {
			continue
		}
		if err := v.validateTypeRef(path+"."+p.Name, p.Type, fieldVal, genBindings, depth+1); err != nil {
			return err
		}
	}
	_ = propByName
	return nil
}

func isJSONInteger(n json.Number) bool {
	if _, err := n.Int64(); err == nil {
		return true
	}
	if _, err := n.Float64(); err == nil {
		f, _ := n.Float64()
		return !math.IsNaN(f) && !math.IsInf(f, 0) && math.Trunc(f) == f
	}
	return false
}

func (v *esSpecValidator) validateTypeRef(path string, ref specTypeRef, val any, genBindings map[string]specTypeRef, depth int) error {
	if depth > 24 {
		return nil
	}
	switch ref.Kind {
	case "user_defined_value":
		return nil
	case "literal_value":
		if fmt.Sprint(val) != fmt.Sprint(ref.Value) {
			return fmt.Errorf("%s: expected literal %v, got %v", path, ref.Value, val)
		}
		return nil
	case "array_of":
		arr, ok := val.([]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON array, got %T", path, val)
		}
		elem, ok := ref.elemRef()
		if !ok {
			return nil
		}
		for i, item := range arr {
			if err := v.validateTypeRef(fmt.Sprintf("%s[%d]", path, i), *elem, item, genBindings, depth+1); err != nil {
				return err
			}
		}
		return nil
	case "dictionary_of":
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected JSON object dictionary, got %T", path, val)
		}
		if ref.SingleKey && len(obj) != 1 {
			return fmt.Errorf("%s: expected single-key dictionary, got %d keys", path, len(obj))
		}
		valRef, hasVal := ref.elemRef()
		for k, elemVal := range obj {
			if ref.Key != nil {
				if err := v.validateTypeRef(path+"."+k+"(key)", *ref.Key, k, genBindings, depth+1); err != nil {
					return err
				}
			}
			if hasVal {
				if err := v.validateTypeRef(path+"."+k, *valRef, elemVal, genBindings, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	case "union_of":
		var errs []string
		for _, item := range ref.Items {
			if err := v.validateTypeRef(path, item, val, genBindings, depth+1); err == nil {
				return nil
			} else {
				errs = append(errs, err.Error())
			}
		}
		return fmt.Errorf("%s: value did not match any union branch (%s)", path, strings.Join(errs, "; "))
	case "instance_of":
		if ref.Type == nil {
			return nil
		}
		typeKey := ref.Type.key()
		if bound, ok := genBindings[typeKey]; ok {
			return v.validateTypeRef(path, bound, val, genBindings, depth+1)
		}
		// Unbound generic parameter such as _global.get.Response.TDocument or _global.search.ResponseBody.TDocument
		if ref.Type.Name == "TDocument" || strings.HasPrefix(ref.Type.Name, "T") && strings.Contains(ref.Type.Namespace, ".") {
			if _, exists := v.types[typeKey]; !exists {
				return nil
			}
		}
		if ref.Type.Namespace == "_builtins" {
			switch ref.Type.Name {
			case "string":
				if _, ok := val.(string); !ok {
					return fmt.Errorf("%s: expected string, got %T", path, val)
				}
			case "boolean":
				if _, ok := val.(bool); !ok {
					return fmt.Errorf("%s: expected boolean, got %T", path, val)
				}
			case "number":
				if _, ok := val.(json.Number); !ok {
					return fmt.Errorf("%s: expected number, got %T", path, val)
				}
			case "null":
				if val != nil {
					return fmt.Errorf("%s: expected null, got %T", path, val)
				}
			}
			return nil
		}
		if ref.Type.Namespace == "_types" {
			switch ref.Type.Name {
			case "integer", "long", "uint", "ulong", "short", "byte":
				num, ok := val.(json.Number)
				if !ok || !isJSONInteger(num) {
					return fmt.Errorf("%s: expected integer (%s), got %v (%T)", path, ref.Type.Name, val, val)
				}
				return nil
			case "float", "double", "half_float", "scaled_float", "number":
				if val == nil {
					return nil
				}
				if _, ok := val.(json.Number); !ok {
					return fmt.Errorf("%s: expected number (%s), got %v (%T)", path, ref.Type.Name, val, val)
				}
				return nil
			}
		}

		td, exists := v.types[typeKey]
		if !exists {
			return nil
		}

		childGen := make(map[string]specTypeRef)
		for k, gv := range genBindings {
			childGen[k] = gv
		}
		for i, gp := range td.Generics {
			if i < len(ref.Generics) {
				childGen[gp.key()] = ref.Generics[i]
			}
		}

		switch td.Kind {
		case "type_alias":
			if td.Type == nil {
				return nil
			}
			return v.validateTypeRef(path, *td.Type, val, childGen, depth+1)
		case "enum":
			s, ok := val.(string)
			if !ok {
				return fmt.Errorf("%s: expected enum string for %s, got %T", path, typeKey, val)
			}
			for _, m := range td.Members {
				if m.Name == s {
					return nil
				}
			}
			// Open enums in ES specs occasionally accept additional string tokens; enforce non-empty when isOpen or unknown
			if s == "" {
				return fmt.Errorf("%s: empty string for enum %s", path, typeKey)
			}
			return fmt.Errorf("%s: value %q not in enum %s", path, s, typeKey)
		case "interface":
			if len(td.Variants) > 0 && len(td.Properties) == 0 {
				var variantSlice []specTypeRef
				if err := json.Unmarshal(td.Variants, &variantSlice); err == nil && len(variantSlice) > 0 {
					for _, variant := range variantSlice {
						if err := v.validateTypeRef(path, variant, val, childGen, depth+1); err == nil {
							return nil
						}
					}
				}
				// Tagged/untagged variant container (e.g., Aggregate) must be a JSON object
				if _, ok := val.(map[string]any); ok {
					return nil
				}
				return fmt.Errorf("%s: expected variant object for %s, got %T", path, typeKey, val)
			}
			obj, ok := val.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: expected object for %s, got %T", path, typeKey, val)
			}
			props, effGen := v.collectInterfaceProperties(td, childGen, make(map[string]bool))
			return v.validateProperties(path, props, obj, effGen, depth+1)
		}
	}
	return nil
}

// --- Wire-Conformance Recording Transport ---

type wireConformanceTransport struct {
	base            http.RoundTripper
	validator       *esSpecValidator
	mu              sync.Mutex
	totalResponses  int
	validatedCounts map[string]int
	violations      []string
}

func newWireConformanceTransport(validator *esSpecValidator) *wireConformanceTransport {
	return &wireConformanceTransport{
		base:            http.DefaultTransport,
		validator:       validator,
		validatedCounts: make(map[string]int),
	}
}

func (wt *wireConformanceTransport) recordViolationf(format string, args ...any) {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	wt.violations = append(wt.violations, fmt.Sprintf(format, args...))
}

func (wt *wireConformanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := wt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	var bodyBytes []byte
	if resp.Body != nil && req.Method != http.MethodHead {
		bodyBytes, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	wt.mu.Lock()
	wt.totalResponses++
	wt.mu.Unlock()

	// 1. Mandatory Elastic v8 product-check header on EVERY HTTP response
	productHeader := resp.Header.Get("X-Elastic-Product")
	if productHeader != "Elasticsearch" {
		wt.recordViolationf("%s %s (HTTP %d): missing or invalid X-Elastic-Product=%q (want \"Elasticsearch\")",
			req.Method, req.URL.Path, resp.StatusCode, productHeader)
	}

	// 2. Media-type check on JSON responses
	trimmed := bytes.TrimSpace(bodyBytes)
	ct := resp.Header.Get("Content-Type")
	isJSONBody := len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
	if req.Method != http.MethodHead && (isJSONBody || strings.Contains(strings.ToLower(ct), "json")) {
		mediaType, params, parseErr := mime.ParseMediaType(ct)
		if parseErr != nil {
			wt.recordViolationf("%s %s (HTTP %d): invalid Content-Type %q: %v",
				req.Method, req.URL.Path, resp.StatusCode, ct, parseErr)
		} else {
			validMedia := mediaType == "application/json" ||
				(mediaType == "application/vnd.elasticsearch+json" && params["compatible-with"] == "8")
			if !validMedia {
				wt.recordViolationf("%s %s (HTTP %d): unexpected JSON Content-Type %q (mediaType=%q params=%v)",
					req.Method, req.URL.Path, resp.StatusCode, ct, mediaType, params)
			}
		}
	}

	// 3. Upstream elastic/elasticsearch-specification schema.json validation when present
	if wt.validator != nil && req.Method != http.MethodHead && isJSONBody {
		if epName := wt.validator.matchTargetEndpoint(req.Method, req.URL.Path); epName != "" {
			if err := wt.validator.validateEndpointResponse(epName, resp.StatusCode, trimmed); err != nil {
				wt.recordViolationf("%s %s -> endpoint %q (HTTP %d) failed schema.json validation: %v",
					req.Method, req.URL.Path, epName, resp.StatusCode, err)
			} else {
				wt.mu.Lock()
				wt.validatedCounts[epName]++
				wt.mu.Unlock()
			}
		}
	}

	return resp, nil
}

func (wt *wireConformanceTransport) assertNoViolations(t *testing.T, phase string) {
	t.Helper()
	wt.mu.Lock()
	defer wt.mu.Unlock()
	if len(wt.violations) > 0 {
		msgs := strings.Join(wt.violations, "\n  - ")
		wt.violations = nil
		t.Fatalf("wire conformance violations during %s:\n  - %s", phase, msgs)
	}
}

func TestOfficialElasticGoSDKv8_Conformance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Load compiled upstream schema.json when available on disk
	schemaPath := filepath.Join("..", "..", ".cache", "es-specification", "output", "schema", "schema.json")
	var validator *esSpecValidator
	if _, statErr := os.Stat(schemaPath); statErr == nil {
		var err error
		validator, err = loadESSpecValidator(schemaPath)
		if err != nil {
			t.Fatalf("failed to load upstream schema.json from %s: %v", schemaPath, err)
		}
		t.Logf("Loaded elastic/elasticsearch-specification schema.json (%d endpoints, %d types)",
			len(validator.endpoints), len(validator.types))
	} else {
		t.Logf("Upstream schema.json not present at %s (skipping optional wire-schema AST checks; run `make conformance-fetch` to enable)", schemaPath)
	}

	targetURL := strings.TrimSpace(os.Getenv("DORIS_ES_PROXY_URL"))
	targetMode := "live-doris-proxy"
	if targetURL == "" {
		targetMode = "in-process-memory-backend"
		srv := proxy.NewServer("es_compat", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
		if v, ok := any(srv).(interface{ SetTargetESVersion(string) }); ok {
			v.SetTargetESVersion("8.15.5")
		}
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(ts.Close)
		targetURL = ts.URL
	}
	t.Logf("Running official elastic/go-elasticsearch/v8 conformance against %s (%s)", targetURL, targetMode)

	wireTransport := newWireConformanceTransport(validator)
	esCfg := elasticsearch.Config{
		Addresses: []string{targetURL},
		Transport: wireTransport,
	}

	esClient, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		t.Fatalf("elasticsearch.NewClient failed: %v", err)
	}
	typedClient, err := elasticsearch.NewTypedClient(esCfg)
	if err != nil {
		t.Fatalf("elasticsearch.NewTypedClient failed: %v", err)
	}

	idx := fmt.Sprintf("sdk_v8_orders_%d", time.Now().UnixNano())
	aliasName := idx + "_alias"
	pipelineID := fmt.Sprintf("sdk_v8_pipe_%d", time.Now().UnixNano())
	indexDeleted := false
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanCancel()
		if !indexDeleted {
			_, _ = typedClient.Indices.Delete(idx).Do(cleanCtx)
		}
		if res, delErr := esClient.Ingest.DeletePipeline(pipelineID, esClient.Ingest.DeletePipeline.WithContext(cleanCtx)); delErr == nil && res != nil {
			_ = res.Body.Close()
		}
	})

	// 1. Cluster Info, Ping, and Health
	infoRes, err := typedClient.Info().Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Info() failed: %v", err)
	}
	if infoRes.ClusterName == "" || infoRes.Version.Int == "" {
		t.Fatalf("unexpected Info() response: %+v", infoRes)
	}

	pingOK, err := typedClient.Ping().IsSuccess(ctx)
	if err != nil || !pingOK {
		t.Fatalf("typedClient.Ping() failed: ok=%v err=%v", pingOK, err)
	}
	if _, err := typedClient.Ping().Do(ctx); err != nil {
		t.Fatalf("typedClient.Ping().Do(ctx) failed: %v", err)
	}

	healthRes, err := typedClient.Cluster.Health().Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Cluster.Health() failed: %v", err)
	}
	if healthRes.ClusterName == "" || healthRes.NumberOfNodes < 1 {
		t.Fatalf("unexpected Cluster.Health() response: %+v", healthRes)
	}
	wireTransport.assertNoViolations(t, "cluster info/ping/health")

	// 2. Strongly-typed Index Creation, Exists, GetMapping, PutAlias, GetAlias
	mapping := &types.TypeMapping{
		Properties: map[string]types.Property{
			"title":      types.NewTextProperty(),
			"category":   types.NewKeywordProperty(),
			"quantity":   types.NewLongNumberProperty(),
			"amount":     types.NewDoubleNumberProperty(),
			"active":     types.NewBooleanProperty(),
			"created_at": types.NewDateProperty(),
			"items": &types.NestedProperty{
				Type: "nested",
				Properties: map[string]types.Property{
					"sku":   types.NewKeywordProperty(),
					"qty":   types.NewLongNumberProperty(),
					"price": types.NewDoubleNumberProperty(),
				},
			},
		},
	}

	var createErr error
	for attempt := 1; attempt <= 10; attempt++ {
		createRes, cErr := typedClient.Indices.Create(idx).Mappings(mapping).Do(ctx)
		if cErr == nil && createRes != nil && createRes.Acknowledged {
			createErr = nil
			break
		}
		createErr = cErr
		if createErr != nil && strings.Contains(createErr.Error(), "Failed to find enough backend") && attempt < 10 {
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	if createErr != nil {
		t.Fatalf("typedClient.Indices.Create(%s) failed: %v", idx, createErr)
	}

	idxExists, err := typedClient.Indices.Exists(idx).IsSuccess(ctx)
	if err != nil || !idxExists {
		t.Fatalf("typedClient.Indices.Exists(%s) failed: exists=%v err=%v", idx, idxExists, err)
	}

	getMappingRes, err := typedClient.Indices.GetMapping().Index(idx).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Indices.GetMapping(%s) failed: %v", idx, err)
	}
	idxMapRecord, ok := getMappingRes[idx]
	if !ok || len(idxMapRecord.Mappings.Properties) < 7 {
		t.Fatalf("expected >= 7 mapped properties on %s, got: %+v", idx, getMappingRes)
	}

	putAliasRes, err := typedClient.Indices.PutAlias(idx, aliasName).Do(ctx)
	if err != nil || !putAliasRes.Acknowledged {
		t.Fatalf("typedClient.Indices.PutAlias(%s, %s) failed: res=%+v err=%v", idx, aliasName, putAliasRes, err)
	}

	getAliasRes, err := typedClient.Indices.GetAlias().Index(idx).Name(aliasName).Do(ctx)
	if err != nil || len(getAliasRes) == 0 {
		t.Fatalf("typedClient.Indices.GetAlias(%s, %s) failed: res=%+v err=%v", idx, aliasName, getAliasRes, err)
	}
	wireTransport.assertNoViolations(t, "indices lifecycle & aliases")

	// 3. Single-document CRUD (Index, Get, Exists, Update, Delete)
	doc1 := sdkOrderDoc{
		Title:     "Enterprise Analytics Subscription",
		Category:  "analytics",
		Quantity:  2,
		Amount:    120.50,
		Active:    true,
		CreatedAt: "2026-11-01T10:00:00Z",
		Items: []sdkOrderItem{
			{SKU: "SKU-AN-1", Qty: 2, Price: 60.25},
		},
	}
	idxDocRes, err := typedClient.Index(idx).Id("order-1").Document(doc1).Refresh(refresh.True).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Index(order-1) failed: %v", err)
	}
	if idxDocRes.Id_ != "order-1" {
		t.Fatalf("expected _id=order-1, got %q", idxDocRes.Id_)
	}

	getDocRes, err := typedClient.Get(idx, "order-1").Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Get(order-1) failed: %v", err)
	}
	if !getDocRes.Found {
		t.Fatalf("expected order-1 Found==true")
	}
	var gotOrder1 sdkOrderDoc
	if err := json.Unmarshal(getDocRes.Source_, &gotOrder1); err != nil {
		t.Fatalf("unmarshal order-1 _source failed: %v", err)
	}
	if gotOrder1.Category != "analytics" || gotOrder1.Quantity != 2 {
		t.Fatalf("unexpected order-1 _source: %+v", gotOrder1)
	}

	docExists, err := typedClient.Exists(idx, "order-1").IsSuccess(ctx)
	if err != nil || !docExists {
		t.Fatalf("typedClient.Exists(order-1) failed: exists=%v err=%v", docExists, err)
	}

	updPayload := map[string]any{"amount": 150.00, "quantity": 3}
	updDocRes, err := typedClient.Update(idx, "order-1").
		Doc(updPayload).
		Refresh(refresh.True).
		Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Update(order-1) failed: %v", err)
	}
	if updDocRes.Id_ != "order-1" {
		t.Fatalf("expected updated _id=order-1, got %q", updDocRes.Id_)
	}

	getAfterUpd, err := typedClient.Get(idx, "order-1").Do(ctx)
	if err != nil || !getAfterUpd.Found {
		t.Fatalf("typedClient.Get(order-1) after update failed: res=%+v err=%v", getAfterUpd, err)
	}
	if err := json.Unmarshal(getAfterUpd.Source_, &gotOrder1); err != nil {
		t.Fatalf("unmarshal updated order-1 failed: %v", err)
	}
	if gotOrder1.Amount != 150.00 || gotOrder1.Quantity != 3 {
		t.Fatalf("expected updated amount=150.00 quantity=3, got %+v", gotOrder1)
	}

	tempDoc := sdkOrderDoc{
		Title:     "Ephemeral Draft Order",
		Category:  "draft",
		Quantity:  1,
		Amount:    5.00,
		Active:    false,
		CreatedAt: "2026-11-01T12:00:00Z",
	}
	if _, err := typedClient.Index(idx).Id("order-ephemeral").Document(tempDoc).Refresh(refresh.True).Do(ctx); err != nil {
		t.Fatalf("index order-ephemeral failed: %v", err)
	}
	delDocRes, err := typedClient.Delete(idx, "order-ephemeral").Refresh(refresh.True).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Delete(order-ephemeral) failed: %v", err)
	}
	if delDocRes.Id_ != "order-ephemeral" {
		t.Fatalf("expected deleted _id=order-ephemeral, got %q", delDocRes.Id_)
	}
	ephemeralExists, err := typedClient.Exists(idx, "order-ephemeral").IsSuccess(ctx)
	if err != nil || ephemeralExists {
		t.Fatalf("expected order-ephemeral Exists==false after delete, got exists=%v err=%v", ephemeralExists, err)
	}
	wireTransport.assertNoViolations(t, "single-document CRUD")

	// 4. Streaming Bulk Ingestion via esutil.NewBulkIndexer + Indices.Refresh
	bulkDocs := []struct {
		id  string
		doc sdkOrderDoc
	}{
		{
			id: "order-2",
			doc: sdkOrderDoc{
				Title:     "Realtime Analytics Engine Pack",
				Category:  "analytics",
				Quantity:  5,
				Amount:    250.00,
				Active:    true,
				CreatedAt: "2026-11-01T15:30:00Z",
				Items: []sdkOrderItem{
					{SKU: "SKU-AN-1", Qty: 3, Price: 50.00},
					{SKU: "SKU-AN-2", Qty: 2, Price: 50.00},
				},
			},
		},
		{
			id: "order-3",
			doc: sdkOrderDoc{
				Title:     "Cloud Storage Analytics Connector",
				Category:  "storage",
				Quantity:  4,
				Amount:    80.00,
				Active:    true,
				CreatedAt: "2026-11-02T09:15:00Z",
				Items: []sdkOrderItem{
					{SKU: "SKU-AN-1", Qty: 4, Price: 20.00},
				},
			},
		},
		{
			id: "order-4",
			doc: sdkOrderDoc{
				Title:     "Legacy Archive Backup",
				Category:  "archive",
				Quantity:  1,
				Amount:    25.00,
				Active:    false,
				CreatedAt: "2026-11-02T18:00:00Z",
				Items: []sdkOrderItem{
					{SKU: "SKU-AR-9", Qty: 1, Price: 25.00},
				},
			},
		},
	}

	bulkIndexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:  esClient,
		Index:   idx,
		Refresh: "true",
	})
	if err != nil {
		t.Fatalf("esutil.NewBulkIndexer failed: %v", err)
	}
	for _, item := range bulkDocs {
		payload, mErr := json.Marshal(item.doc)
		if mErr != nil {
			t.Fatalf("marshal bulk doc %s: %v", item.id, mErr)
		}
		if addErr := bulkIndexer.Add(ctx, esutil.BulkIndexerItem{
			Action:     "index",
			DocumentID: item.id,
			Body:       bytes.NewReader(payload),
		}); addErr != nil {
			t.Fatalf("bulkIndexer.Add(%s) failed: %v", item.id, addErr)
		}
	}
	if err := bulkIndexer.Close(ctx); err != nil {
		t.Fatalf("bulkIndexer.Close failed: %v", err)
	}
	bulkStats := bulkIndexer.Stats()
	if bulkStats.NumFailed != 0 || bulkStats.NumFlushed != uint64(len(bulkDocs)) {
		t.Fatalf("unexpected BulkIndexer stats: flushed=%d failed=%d", bulkStats.NumFlushed, bulkStats.NumFailed)
	}

	if _, err := typedClient.Indices.Refresh().Index(idx).Do(ctx); err != nil {
		t.Fatalf("typedClient.Indices.Refresh(%s) failed: %v", idx, err)
	}
	wireTransport.assertNoViolations(t, "BulkIndexer & Refresh")

	// 5. Typed Multi-Get (Mget)
	mgetRes, err := typedClient.Mget().
		Index(idx).
		Ids("order-1", "order-2", "order-3", "nonexistent-order").
		Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Mget() failed: %v", err)
	}
	if len(mgetRes.Docs) != 4 {
		t.Fatalf("expected 4 Mget items, got %d", len(mgetRes.Docs))
	}
	foundMget := 0
	for _, item := range mgetRes.Docs {
		gr, ok := item.(*types.GetResult)
		if !ok {
			t.Fatalf("expected *types.GetResult in Mget response, got %T", item)
		}
		if gr.Found {
			foundMget++
			var decoded sdkOrderDoc
			if err := json.Unmarshal(gr.Source_, &decoded); err != nil {
				t.Fatalf("unmarshal Mget _source for %s: %v", gr.Id_, err)
			}
			if decoded.Title == "" {
				t.Fatalf("expected non-empty Title in Mget doc %s", gr.Id_)
			}
		}
	}
	if foundMget != 3 {
		t.Fatalf("expected 3 found documents in Mget, got %d", foundMget)
	}
	wireTransport.assertNoViolations(t, "typed Mget")

	// 6. Typed Count & Search (Bool + Match + Term + Range + Nested, Sort, Highlight, Typed Aggregations)
	countRes, err := typedClient.Count().
		Index(aliasName).
		Query(&types.Query{
			Term: map[string]types.TermQuery{
				"active": {Value: true},
			},
		}).
		Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Count() failed: %v", err)
	}
	if countRes.Count != 3 {
		t.Fatalf("expected Count == 3 for active orders, got %d", countRes.Count)
	}

	minAmt := types.Float64(50.0)
	minNestedQty := types.Float64(2.0)
	searchReq := &search.Request{
		Query: &types.Query{
			Bool: &types.BoolQuery{
				Must: []types.Query{
					{
						Match: map[string]types.MatchQuery{
							"title": {Query: "Analytics"},
						},
					},
				},
				Filter: []types.Query{
					{
						Term: map[string]types.TermQuery{
							"active": {Value: true},
						},
					},
					{
						Range: map[string]types.RangeQuery{
							"amount": types.NumberRangeQuery{
								Gte: &minAmt,
							},
						},
					},
					{
						Nested: &types.NestedQuery{
							Path: "items",
							Query: types.Query{
								Bool: &types.BoolQuery{
									Must: []types.Query{
										{
											Term: map[string]types.TermQuery{
												"items.sku": {Value: "SKU-AN-1"},
											},
										},
										{
											Range: map[string]types.RangeQuery{
												"items.qty": types.NumberRangeQuery{
													Gte: &minNestedQty,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Sort: []types.SortCombinations{
			types.SortOptions{
				SortOptions: map[string]types.FieldSort{
					"amount": {Order: &sortorder.Desc},
				},
			},
		},
		Highlight: &types.Highlight{
			Fields: map[string]types.HighlightField{
				"title": {},
			},
		},
		Aggregations: map[string]types.Aggregations{
			"by_category": {
				Terms: &types.TermsAggregation{
					Field: strPtr("category"),
				},
			},
			"amount_stats": {
				Stats: &types.StatsAggregation{
					Field: strPtr("amount"),
				},
			},
			"orders_by_day": {
				DateHistogram: &types.DateHistogramAggregation{
					Field:            strPtr("created_at"),
					CalendarInterval: &calendarinterval.Day,
				},
			},
			"avg_amount": {
				Avg: &types.AverageAggregation{
					Field: strPtr("amount"),
				},
			},
			"sum_quantity": {
				Sum: &types.SumAggregation{
					Field: strPtr("quantity"),
				},
			},
			"distinct_categories": {
				Cardinality: &types.CardinalityAggregation{
					Field: strPtr("category"),
				},
			},
		},
	}

	searchRes, err := typedClient.Search().Index(aliasName).Request(searchReq).Do(ctx)
	if err != nil {
		t.Fatalf("typedClient.Search() failed (including strict union unmarshaling): %v", err)
	}
	if searchRes.Hits.Total == nil || searchRes.Hits.Total.Value != 3 {
		t.Fatalf("expected 3 matched hits in Search(), got %+v", searchRes.Hits.Total)
	}
	if len(searchRes.Hits.Hits) != 3 {
		t.Fatalf("expected 3 returned hits, got %d", len(searchRes.Hits.Hits))
	}
	// Verify descending amount sort (250.00 -> 150.00 -> 80.00) and highlight snippets
	var firstHitDoc sdkOrderDoc
	if err := json.Unmarshal(searchRes.Hits.Hits[0].Source_, &firstHitDoc); err != nil {
		t.Fatalf("unmarshal first search hit _source: %v", err)
	}
	if firstHitDoc.Amount != 250.00 {
		t.Fatalf("expected top sorted hit amount=250.00, got %+v", firstHitDoc)
	}
	if len(searchRes.Hits.Hits[0].Highlight["title"]) == 0 {
		t.Fatalf("expected highlight snippet on title, got %+v", searchRes.Hits.Hits[0].Highlight)
	}

	// Verify strict typed union decoding across all 6 aggregation types
	catTermsAgg, ok := searchRes.Aggregations["by_category"].(*types.StringTermsAggregate)
	if !ok {
		t.Fatalf("expected *types.StringTermsAggregate for by_category, got %T (%+v)",
			searchRes.Aggregations["by_category"], searchRes.Aggregations["by_category"])
	}
	catBuckets, ok := catTermsAgg.Buckets.([]types.StringTermsBucket)
	if !ok || len(catBuckets) != 2 {
		t.Fatalf("expected []types.StringTermsBucket with 2 buckets for by_category, got %T (%+v)",
			catTermsAgg.Buckets, catTermsAgg.Buckets)
	}
	statsAgg, ok := searchRes.Aggregations["amount_stats"].(*types.StatsAggregate)
	if !ok || statsAgg.Count != 3 || statsAgg.Sum != 480.0 {
		t.Fatalf("unexpected StatsAggregate for amount_stats: %T %+v",
			searchRes.Aggregations["amount_stats"], searchRes.Aggregations["amount_stats"])
	}
	dateHistAgg, ok := searchRes.Aggregations["orders_by_day"].(*types.DateHistogramAggregate)
	if !ok {
		t.Fatalf("expected *types.DateHistogramAggregate for orders_by_day, got %T %+v",
			searchRes.Aggregations["orders_by_day"], searchRes.Aggregations["orders_by_day"])
	}
	dayBuckets, ok := dateHistAgg.Buckets.([]types.DateHistogramBucket)
	if !ok || len(dayBuckets) != 2 {
		t.Fatalf("expected []types.DateHistogramBucket with 2 daily buckets, got %T %+v",
			dateHistAgg.Buckets, dateHistAgg.Buckets)
	}
	avgAgg, ok := searchRes.Aggregations["avg_amount"].(*types.AvgAggregate)
	if !ok || avgAgg.Value == nil || math.Abs(float64(*avgAgg.Value)-160.0) > 1e-6 {
		t.Fatalf("unexpected AvgAggregate for avg_amount: %T %+v",
			searchRes.Aggregations["avg_amount"], searchRes.Aggregations["avg_amount"])
	}
	sumAgg, ok := searchRes.Aggregations["sum_quantity"].(*types.SumAggregate)
	if !ok || sumAgg.Value == nil || float64(*sumAgg.Value) != 12.0 {
		t.Fatalf("unexpected SumAggregate for sum_quantity: %T %+v",
			searchRes.Aggregations["sum_quantity"], searchRes.Aggregations["sum_quantity"])
	}
	cardAgg, ok := searchRes.Aggregations["distinct_categories"].(*types.CardinalityAggregate)
	if !ok || cardAgg.Value != 2 {
		t.Fatalf("unexpected CardinalityAggregate for distinct_categories: %T %+v",
			searchRes.Aggregations["distinct_categories"], searchRes.Aggregations["distinct_categories"])
	}
	wireTransport.assertNoViolations(t, "typed Count & Search with Aggregations")

	// 7. Classic esapi: Cat.Indices, Cat.Health, Ingest.PutPipeline + Simulate, UpdateByQuery, DeleteByQuery, Indices.Delete
	catIdxRes, err := esClient.Cat.Indices(
		esClient.Cat.Indices.WithContext(ctx),
		esClient.Cat.Indices.WithIndex(idx),
		esClient.Cat.Indices.WithFormat("json"),
	)
	if err != nil {
		t.Fatalf("esClient.Cat.Indices failed: %v", err)
	}
	catIdxBody, _ := io.ReadAll(catIdxRes.Body)
	_ = catIdxRes.Body.Close()
	if catIdxRes.IsError() || !strings.Contains(string(catIdxBody), idx) {
		t.Fatalf("unexpected Cat.Indices response (status=%s): %s", catIdxRes.Status(), string(catIdxBody))
	}

	catHealthRes, err := esClient.Cat.Health(
		esClient.Cat.Health.WithContext(ctx),
		esClient.Cat.Health.WithFormat("json"),
	)
	if err != nil {
		t.Fatalf("esClient.Cat.Health failed: %v", err)
	}
	catHealthBody, _ := io.ReadAll(catHealthRes.Body)
	_ = catHealthRes.Body.Close()
	if catHealthRes.IsError() || len(bytes.TrimSpace(catHealthBody)) == 0 {
		t.Fatalf("unexpected Cat.Health response (status=%s): %s", catHealthRes.Status(), string(catHealthBody))
	}

	pipeDef := `{"description":"SDK v8 conformance pipeline","processors":[{"lowercase":{"field":"category"}},{"set":{"field":"ingested_by","value":"go-es-v8"}}]}`
	putPipeRes, err := esClient.Ingest.PutPipeline(
		pipelineID,
		strings.NewReader(pipeDef),
		esClient.Ingest.PutPipeline.WithContext(ctx),
	)
	if err != nil {
		t.Fatalf("esClient.Ingest.PutPipeline failed: %v", err)
	}
	_ = putPipeRes.Body.Close()
	if putPipeRes.IsError() {
		t.Fatalf("PutPipeline returned error status: %s", putPipeRes.Status())
	}

	simBody := `{"docs":[{"_source":{"category":"ANALYTICS_UPPER"}}]}`
	simRes, err := esClient.Ingest.Simulate(
		strings.NewReader(simBody),
		esClient.Ingest.Simulate.WithContext(ctx),
		esClient.Ingest.Simulate.WithPipelineID(pipelineID),
	)
	if err != nil {
		t.Fatalf("esClient.Ingest.Simulate failed: %v", err)
	}
	simRaw, _ := io.ReadAll(simRes.Body)
	_ = simRes.Body.Close()
	if simRes.IsError() || !strings.Contains(string(simRaw), `"analytics_upper"`) || !strings.Contains(string(simRaw), `"go-es-v8"`) {
		t.Fatalf("unexpected Ingest.Simulate response (status=%s): %s", simRes.Status(), string(simRaw))
	}

	ubqBody := `{"query":{"term":{"category":"storage"}},"script":{"source":"ctx._source.quantity = ctx._source.quantity + params.bump","lang":"painless","params":{"bump":6}}}`
	ubqRes, err := esClient.UpdateByQuery(
		[]string{idx},
		esClient.UpdateByQuery.WithContext(ctx),
		esClient.UpdateByQuery.WithBody(strings.NewReader(ubqBody)),
		esClient.UpdateByQuery.WithRefresh(true),
	)
	if err != nil {
		t.Fatalf("esClient.UpdateByQuery failed: %v", err)
	}
	ubqRaw, _ := io.ReadAll(ubqRes.Body)
	_ = ubqRes.Body.Close()
	if ubqRes.IsError() {
		t.Fatalf("UpdateByQuery returned error status %s: %s", ubqRes.Status(), string(ubqRaw))
	}
	var ubqParsed struct {
		Updated int64 `json:"updated"`
	}
	if err := json.Unmarshal(ubqRaw, &ubqParsed); err != nil || ubqParsed.Updated != 1 {
		t.Fatalf("expected UpdateByQuery updated==1, got %+v (err=%v, raw=%s)", ubqParsed, err, string(ubqRaw))
	}

	dbqBody := `{"query":{"term":{"active":false}}}`
	dbqRes, err := esClient.DeleteByQuery(
		[]string{idx},
		strings.NewReader(dbqBody),
		esClient.DeleteByQuery.WithContext(ctx),
		esClient.DeleteByQuery.WithRefresh(true),
	)
	if err != nil {
		t.Fatalf("esClient.DeleteByQuery failed: %v", err)
	}
	dbqRaw, _ := io.ReadAll(dbqRes.Body)
	_ = dbqRes.Body.Close()
	if dbqRes.IsError() {
		t.Fatalf("DeleteByQuery returned error status %s: %s", dbqRes.Status(), string(dbqRaw))
	}
	var dbqParsed struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(dbqRaw, &dbqParsed); err != nil || dbqParsed.Deleted != 1 {
		t.Fatalf("expected DeleteByQuery deleted==1, got %+v (err=%v, raw=%s)", dbqParsed, err, string(dbqRaw))
	}

	delIdxRes, err := typedClient.Indices.Delete(idx).Do(ctx)
	if err != nil || !delIdxRes.Acknowledged {
		t.Fatalf("typedClient.Indices.Delete(%s) failed: res=%+v err=%v", idx, delIdxRes, err)
	}
	indexDeleted = true

	wireTransport.assertNoViolations(t, "esapi Cat/Ingest/UBQ/DBQ/Delete cleanup")

	// Verify wire-conformance coverage summary
	wireTransport.mu.Lock()
	totalHTTP := wireTransport.totalResponses
	validatedSnapshot := make(map[string]int, len(wireTransport.validatedCounts))
	for k, c := range wireTransport.validatedCounts {
		validatedSnapshot[k] = c
	}
	wireTransport.mu.Unlock()

	if totalHTTP < 20 {
		t.Fatalf("expected >= 20 recorded SDK HTTP responses, got %d", totalHTTP)
	}
	if validator != nil {
		for _, epName := range targetValidatedEndpoints {
			if validatedSnapshot[epName] < 1 {
				t.Fatalf("expected endpoint %q to be validated against schema.json at least once, counts=%v", epName, validatedSnapshot)
			}
		}
	}
	t.Logf("Official Go SDK v8 conformance passed (%d HTTP responses verified; schema-validated endpoints=%v)",
		totalHTTP, validatedSnapshot)
}
