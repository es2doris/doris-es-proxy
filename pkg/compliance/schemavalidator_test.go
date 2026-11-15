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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestSpecSchemaValidatorSyntheticConstructs(t *testing.T) {
	t.Parallel()

	const syntheticSchema = `{
  "endpoints": [
    {
      "name": "test.item",
      "response": { "name": "ItemResponse", "namespace": "test" },
      "responseMediaType": ["application/json"]
    },
    {
      "name": "test.dict",
      "response": { "name": "SingleDictResponse", "namespace": "test" },
      "responseMediaType": ["application/json"]
    },
    {
      "name": "test.nobody",
      "response": { "name": "EmptyResponse", "namespace": "test" },
      "responseMediaType": []
    },
    {
      "name": "test.untyped",
      "response": null,
      "responseMediaType": ["application/json"]
    }
  ],
  "types": [
    {
      "kind": "enum",
      "name": { "name": "StatusEnum", "namespace": "test" },
      "isOpen": false,
      "members": [
        { "name": "green", "aliases": ["ok"] },
        { "name": "yellow" },
        { "name": "red" }
      ]
    },
    {
      "kind": "enum",
      "name": { "name": "OpenTagEnum", "namespace": "test" },
      "isOpen": true,
      "members": [
        { "name": "alpha" }
      ]
    },
    {
      "kind": "interface",
      "name": { "name": "BaseEnvelope", "namespace": "test" },
      "generics": [
        { "name": "TPayload", "namespace": "test.BaseEnvelope" }
      ],
      "properties": [
        {
          "name": "acknowledged",
          "required": true,
          "type": { "kind": "instance_of", "type": { "name": "boolean", "namespace": "_builtins" } }
        },
        {
          "name": "status",
          "aliases": ["health_status"],
          "required": true,
          "type": { "kind": "instance_of", "type": { "name": "StatusEnum", "namespace": "test" } }
        },
        {
          "name": "data",
          "required": true,
          "type": { "kind": "instance_of", "type": { "name": "TPayload", "namespace": "test.BaseEnvelope" } }
        }
      ]
    },
    {
      "kind": "type_alias",
      "name": { "name": "MetricOrLabel", "namespace": "test" },
      "type": {
        "kind": "union_of",
        "items": [
          { "kind": "instance_of", "type": { "name": "uint", "namespace": "_types" } },
          { "kind": "literal_value", "value": "n/a" }
        ]
      }
    },
    {
      "kind": "interface",
      "name": { "name": "PayloadBody", "namespace": "test" },
      "generics": [
        { "name": "TDoc", "namespace": "test.PayloadBody" }
      ],
      "behaviors": [
        {
          "type": { "name": "AdditionalProperties", "namespace": "_spec_utils" },
          "generics": [
            { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } },
            { "kind": "instance_of", "type": { "name": "MetricOrLabel", "namespace": "test" } }
          ]
        }
      ],
      "properties": [
        {
          "name": "count",
          "required": true,
          "type": { "kind": "instance_of", "type": { "name": "long", "namespace": "_types" } }
        },
        {
          "name": "tag",
          "required": false,
          "type": { "kind": "instance_of", "type": { "name": "OpenTagEnum", "namespace": "test" } }
        },
        {
          "name": "items",
          "required": true,
          "type": {
            "kind": "array_of",
            "value": { "kind": "instance_of", "type": { "name": "TDoc", "namespace": "test.PayloadBody" } }
          }
        }
      ]
    },
    {
      "kind": "response",
      "name": { "name": "ItemResponse", "namespace": "test" },
      "generics": [
        { "name": "TDocument", "namespace": "test.ItemResponse" }
      ],
      "inherits": {
        "type": { "name": "BaseEnvelope", "namespace": "test" },
        "generics": [
          {
            "kind": "instance_of",
            "type": { "name": "PayloadBody", "namespace": "test" },
            "generics": [
              { "kind": "instance_of", "type": { "name": "TDocument", "namespace": "test.ItemResponse" } }
            ]
          }
        ]
      },
      "body": {
        "kind": "properties",
        "properties": [
          {
            "name": "version_lit",
            "required": false,
            "type": { "kind": "literal_value", "value": 8 }
          }
        ]
      }
    },
    {
      "kind": "response",
      "name": { "name": "SingleDictResponse", "namespace": "test" },
      "body": {
        "kind": "value",
        "value": {
          "kind": "dictionary_of",
          "singleKey": true,
          "key": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } },
          "value": { "kind": "instance_of", "type": { "name": "MetricOrLabel", "namespace": "test" } }
        }
      }
    },
    {
      "kind": "response",
      "name": { "name": "EmptyResponse", "namespace": "test" },
      "body": { "kind": "no_body" }
    },
    {
      "kind": "type_alias",
      "name": { "name": "long", "namespace": "_types" },
      "type": { "kind": "instance_of", "type": { "name": "number", "namespace": "_builtins" } }
    },
    {
      "kind": "type_alias",
      "name": { "name": "uint", "namespace": "_types" },
      "type": { "kind": "instance_of", "type": { "name": "number", "namespace": "_builtins" } }
    }
  ]
}`

	v, err := ParseSpecSchemaValidator([]byte(syntheticSchema))
	if err != nil {
		t.Fatalf("ParseSpecSchemaValidator failed: %v", err)
	}
	if v.EndpointCount() != 4 {
		t.Fatalf("EndpointCount() = %d, want 4", v.EndpointCount())
	}
	if v.TypeCount() != 10 {
		t.Fatalf("TypeCount() = %d, want 10", v.TypeCount())
	}
	if !v.HasEndpoint("test.item") || v.HasEndpoint("nonexistent") {
		t.Fatalf("HasEndpoint check failed")
	}

	// Nil safety
	var nilValidator *SpecSchemaValidator
	if nilValidator.EndpointCount() != 0 || nilValidator.TypeCount() != 0 || nilValidator.HasEndpoint("test.item") {
		t.Fatalf("nil SpecSchemaValidator getters should return zero values")
	}
	if err := nilValidator.ValidateEndpointResponse("test.item", []byte(`{}`)); err == nil {
		t.Fatalf("expected error on nil SpecSchemaValidator")
	}

	// Valid payload using canonical + alias + open enum + union AdditionalProperties + unbound TDocument
	validItem := `{
		"acknowledged": true,
		"health_status": "ok",
		"version_lit": 8,
		"data": {
			"count": 42,
			"tag": "custom_open_value",
			"items": [{"user": "alice"}, {"user": "bob"}],
			"extra_metric": 10,
			"extra_na": "n/a"
		}
	}`
	if err := v.ValidateEndpointResponse("test.item", []byte(validItem)); err != nil {
		t.Fatalf("expected validItem to pass, got: %v", err)
	}

	// Negative cases on test.item
	badPayloads := []struct {
		name    string
		payload string
	}{
		{"missing required status", `{"acknowledged":true,"data":{"count":1,"items":[]}}`},
		{"wrong boolean type", `{"acknowledged":"yes","status":"green","data":{"count":1,"items":[]}}`},
		{"closed enum violation", `{"acknowledged":true,"status":"purple","data":{"count":1,"items":[]}}`},
		{"open enum non-string", `{"acknowledged":true,"status":"green","data":{"count":1,"tag":123,"items":[]}}`},
		{"non-integral long", `{"acknowledged":true,"status":"green","data":{"count":1.5,"items":[]}}`},
		{"array_of non-array", `{"acknowledged":true,"status":"green","data":{"count":1,"items":"not_arr"}}`},
		{"literal mismatch", `{"acknowledged":true,"status":"green","version_lit":7,"data":{"count":1,"items":[]}}`},
		{"additional prop negative uint", `{"acknowledged":true,"status":"green","data":{"count":1,"items":[],"bad_extra":-5}}`},
		{"additional prop union mismatch", `{"acknowledged":true,"status":"green","data":{"count":1,"items":[],"bad_extra":"wrong"}}`},
		{"malformed json", `{"acknowledged":true`},
		{"trailing json garbage", `{"acknowledged":true,"status":"green","data":{"count":1,"items":[]}} {}`},
		{"empty body", ``},
	}
	for _, tc := range badPayloads {
		if err := v.ValidateEndpointResponse("test.item", []byte(tc.payload)); err == nil {
			t.Errorf("case %q: expected validation error, got nil", tc.name)
		}
	}

	// dictionary_of singleKey
	if err := v.ValidateEndpointResponse("test.dict", []byte(`{"only_one": 7}`)); err != nil {
		t.Fatalf("singleKey dictionary with 1 key failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.dict", []byte(`{"only_one": "n/a"}`)); err != nil {
		t.Fatalf("singleKey dictionary with literal union variant failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.dict", []byte(`{"k1": 1, "k2": 2}`)); err == nil {
		t.Fatalf("expected singleKey dictionary with 2 keys to fail")
	}
	if err := v.ValidateEndpointResponse("test.dict", []byte(`{}`)); err == nil {
		t.Fatalf("expected singleKey dictionary with 0 keys to fail")
	}

	// no_body and untyped endpoints
	if err := v.ValidateEndpointResponse("test.nobody", nil); err != nil {
		t.Fatalf("expected empty payload on no_body endpoint to pass: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.nobody", []byte(`{"unexpected":1}`)); err == nil {
		t.Fatalf("expected non-empty payload on no_body endpoint to fail")
	}
	if err := v.ValidateEndpointResponse("test.untyped", []byte(`{"any":123}`)); err != nil {
		t.Fatalf("expected valid JSON on untyped endpoint to pass: %v", err)
	}
	if err := v.ValidateEndpointResponse("unknown.endpoint", []byte(`{}`)); err == nil {
		t.Fatalf("expected unknown endpoint error")
	}
}

func TestSpecSchemaValidatorLiveUpstreamSchema(t *testing.T) {
	schemaPath := filepath.Join(conformanceCacheBaseDir(), "es-specification", "output", "schema", "schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		if os.Getenv("CONFORMANCE_REQUIRE_UPSTREAM") == "1" {
			t.Fatalf("required upstream specification schema missing at %s: %v", schemaPath, err)
		}
		t.Skipf("skipping live specification schema test (.cache not populated at %s)", schemaPath)
	}

	v, err := LoadSpecSchemaValidator(schemaPath)
	if err != nil {
		t.Fatalf("LoadSpecSchemaValidator(%s) failed: %v", schemaPath, err)
	}
	if v.EndpointCount() != 518 {
		t.Fatalf("EndpointCount() = %d, want 518", v.EndpointCount())
	}
	if v.TypeCount() != 3025 {
		t.Fatalf("TypeCount() = %d, want 3025", v.TypeCount())
	}

	// Validate live doris-es-proxy responses against compiled upstream Elasticsearch wire schemas.
	srv := proxy.NewServer("es_compat", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
	if cfg, ok := any(srv).(interface{ SetTargetESVersion(string) }); ok {
		cfg.SetTargetESVersion("8.15.5")
	}
	handler := withDefaultES8AcceptHeader(srv.Handler())

	doReq := func(method, target, body string) []byte {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, "http://es.local"+target, rdr)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()
		raw, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("%s %s read body failed: %v", method, target, readErr)
		}
		if resp.StatusCode >= 300 {
			t.Fatalf("%s %s returned status %d: %s", method, target, resp.StatusCode, string(raw))
		}
		return raw
	}

	infoBytes := doReq(http.MethodGet, "/", "")
	if err := v.ValidateEndpointResponse("info", infoBytes); err != nil {
		t.Fatalf("live info response failed upstream schema validation: %v\npayload: %s", err, string(infoBytes))
	}

	healthBytes := doReq(http.MethodGet, "/_cluster/health", "")
	if err := v.ValidateEndpointResponse("cluster.health", healthBytes); err != nil {
		t.Fatalf("live cluster.health response failed upstream schema validation: %v\npayload: %s", err, string(healthBytes))
	}

	createBytes := doReq(http.MethodPut, "/orders", `{"mappings":{"properties":{"amount":{"type":"integer"},"category":{"type":"keyword"}}}}`)
	if err := v.ValidateEndpointResponse("indices.create", createBytes); err != nil {
		t.Fatalf("live indices.create response failed upstream schema validation: %v\npayload: %s", err, string(createBytes))
	}

	indexBytes := doReq(http.MethodPut, "/orders/_doc/1?refresh=true", `{"amount":120,"category":"books"}`)
	if err := v.ValidateEndpointResponse("index", indexBytes); err != nil {
		t.Fatalf("live index response failed upstream schema validation: %v\npayload: %s", err, string(indexBytes))
	}

	getBytes := doReq(http.MethodGet, "/orders/_doc/1", "")
	if err := v.ValidateEndpointResponse("get", getBytes); err != nil {
		t.Fatalf("live get response failed upstream schema validation: %v\npayload: %s", err, string(getBytes))
	}

	countBytes := doReq(http.MethodPost, "/orders/_count", `{"query":{"match_all":{}}}`)
	if err := v.ValidateEndpointResponse("count", countBytes); err != nil {
		t.Fatalf("live count response failed upstream schema validation: %v\npayload: %s", err, string(countBytes))
	}

	searchBytes := doReq(http.MethodPost, "/orders/_search", `{"query":{"match_all":{}},"aggs":{"by_cat":{"terms":{"field":"category"}}}}`)
	if err := v.ValidateEndpointResponse("search", searchBytes); err != nil {
		t.Fatalf("live search response failed upstream schema validation: %v\npayload: %s", err, string(searchBytes))
	}

	// Negative wire-schema mutations against live upstream schema.json
	negativeCases := []struct {
		endpoint string
		payload  string
	}{
		{"search", `{"timed_out":false,"_shards":{"total":1,"successful":1,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`}, // missing required took
		{"search", `{"took":1,"timed_out":"false","_shards":{"total":1,"successful":1,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`},
		{"search", `{"took":1,"timed_out":false,"_shards":{"total":-1,"successful":1,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`},
		{"index", `{"_index":"orders","_id":"1","_version":1,"result":"not_a_real_result","_shards":{"total":1,"successful":1,"failed":0},"_seq_no":0,"_primary_term":1}`},
	}
	for _, nc := range negativeCases {
		if err := v.ValidateEndpointResponse(nc.endpoint, []byte(nc.payload)); err == nil {
			t.Errorf("expected upstream schema validation error for %s payload %s", nc.endpoint, nc.payload)
		}
	}
}
