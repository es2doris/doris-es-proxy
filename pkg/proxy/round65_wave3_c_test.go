package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRound65Wave3C_PatternReplaceNormalizerSearch(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	createBody := `{
		"settings": {
			"analysis": {
				"normalizer": {
					"my_normalizer": {
						"type": "custom",
						"filter": ["replace_zeros"]
					}
				},
				"filter": {
					"replace_zeros": {
						"type": "pattern_replace",
						"pattern": "0+",
						"replacement": "",
						"all": true
					}
				}
			}
		},
		"mappings": {
			"properties": {
				"pagerank": {
					"type": "keyword",
					"normalizer": "my_normalizer"
				}
			}
		}
	}`
	rec := doRound63Req(t, h, http.MethodPut, "/test", []byte(createBody), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}

	// Regression guard: handlePutDoc calls syncCatalogFromBackend, which resets s.indices[name]
	// without re-applying CustomSettings. validateAndEvolveExistingIndexR61CRUD must restore
	// AnalysisConfig before ShredDocument runs so pattern_replace normalizer strips zeros.
	rec = doRound63Req(t, h, http.MethodPut, "/test/_doc/1", []byte(`{"pagerank":"000000111"}`), nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("index failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPost, "/test/_refresh", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", rec.Code, rec.Body.String())
	}
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		t.Fatalf("syncCatalogFromBackend failed: %v", err)
	}
	rec = doRound63Req(t, h, http.MethodPut, "/test/_doc/2", []byte(`{"pagerank":"000022200"}`), nil)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("second index after catalog sync failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPost, "/test/_refresh", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("second refresh failed: %d %s", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		query string
		want  string
	}{
		{"pagerank:111", `"total":{"relation":"eq","value":1}`},
		{"pagerank:222", `"total":{"relation":"eq","value":1}`},
	} {
		rec = doRound63Req(t, h, http.MethodGet, "/test/_search?q="+tc.query, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("search %s failed: %d %s", tc.query, rec.Code, rec.Body.String())
		}
		var sr map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
			t.Fatalf("invalid search response JSON: %v", err)
		}
		totalVal := sr["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)
		if totalVal != 1 {
			t.Fatalf("expected 1 hit for %s, got %v body=%s", tc.query, totalVal, rec.Body.String())
		}
	}
}

func TestRound65Wave3C_FieldCapsTSIDAndConflicts(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")

	tsdbBody := `{
		"settings": {
			"index": {
				"mode": "time_series",
				"routing_path": ["metricset"],
				"time_series": {
					"start_time": "2021-04-28T00:00:00Z",
					"end_time": "2021-04-29T00:00:00Z"
				}
			}
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"metricset": {"type": "keyword", "time_series_dimension": true},
				"rx": {"type": "long", "time_series_metric": "gauge"}
			}
		}
	}`
	stdBody := `{
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"metricset": {"type": "keyword"},
				"rx": {"type": "long"}
			}
		}
	}`
	if rec := doRound63Req(t, h, http.MethodPut, "/idx_tsdb", []byte(tsdbBody), nil); rec.Code != http.StatusOK {
		t.Fatalf("create idx_tsdb failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRound63Req(t, h, http.MethodPut, "/idx_std", []byte(stdBody), nil); rec.Code != http.StatusOK {
		t.Fatalf("create idx_std failed: %d %s", rec.Code, rec.Body.String())
	}

	// TSDB-only _field_caps exposes _tsid metadata_field and omits non_dimension_indices conflict.
	rec := doRound63Req(t, h, http.MethodGet, "/idx_tsdb/_field_caps?fields=*", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("tsdb _field_caps failed: %d %s", rec.Code, rec.Body.String())
	}
	var tsResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tsResp); err != nil {
		t.Fatalf("decode tsdb field_caps: %v", err)
	}
	fieldsMap := tsResp["fields"].(map[string]any)
	tsidMap, _ := fieldsMap["_tsid"].(map[string]any)["_tsid"].(map[string]any)
	if metadataField, _ := tsidMap["metadata_field"].(bool); !metadataField {
		t.Fatalf("expected _tsid._tsid.metadata_field=true on TSDB index, got %+v", fieldsMap["_tsid"])
	}

	// Mixed TSDB + standard index sets non_dimension_indices and clears time_series_dimension.
	rec = doRound63Req(t, h, http.MethodGet, "/idx_tsdb,idx_std/_field_caps?fields=*", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mixed _field_caps failed: %d %s", rec.Code, rec.Body.String())
	}
	var mixResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &mixResp); err != nil {
		t.Fatalf("decode mixed field_caps: %v", err)
	}
	mixFields := mixResp["fields"].(map[string]any)
	metricsetKw := mixFields["metricset"].(map[string]any)["keyword"].(map[string]any)
	if _, hasDim := metricsetKw["time_series_dimension"]; hasDim {
		t.Fatalf("expected time_series_dimension omitted when non_dimension_indices present, got %+v", metricsetKw)
	}
	if _, hasConflict := metricsetKw["non_dimension_indices"]; !hasConflict {
		t.Fatalf("expected non_dimension_indices on mixed metricset, got %+v", metricsetKw)
	}
}

func TestRound65Wave3C_ES8QueryValidationAndKNN(t *testing.T) {
	_, h8 := newRound61AdminTestServer(t, "8.15.5")
	if rec := doRound63Req(t, h8, http.MethodPut, "/qtest", []byte(`{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"loc": {"type": "geo_point"},
				"vec": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"}
			}
		}
	}`), nil); rec.Code != http.StatusOK {
		t.Fatalf("create qtest failed: %d %s", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "match_cutoff_frequency",
			body: `{"query":{"match":{"title":{"query":"hello","cutoff_frequency":0.01,"type":"boolean"}}}}`,
			want: "cutoff_freqency is not supported",
		},
		{
			name: "common_query",
			body: `{"query":{"common":{"title":{"query":"hello","cutoff_frequency":0.01}}}}`,
			want: "Common Terms Query usage is not supported",
		},
		{
			name: "type_query",
			body: `{"query":{"type":{"value":"_doc"}}}`,
			want: "[types removal] Type queries are deprecated",
		},
		{
			name: "geo_bounding_box_type",
			body: `{"query":{"geo_bounding_box":{"type":"memory","loc":{"top_left":{"lat":1,"lon":-1},"bottom_right":{"lat":-1,"lon":1}}}}}`,
			want: "failed to parse [geo_bounding_box] query. unexpected field [type]",
		},
		{
			name: "knn_invalid_k",
			body: `{"knn":{"field":"vec","query_vector":[1,0],"k":5,"num_candidates":2}}`,
			want: `"caused_by":{"reason":"[num_candidates] cannot be less than [k]","type":"illegal_argument_exception"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRound63Req(t, h8, http.MethodPost, "/qtest/_search", []byte(tc.body), nil)
			if rec.Code < 400 || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("%s: expected 4xx containing %q, got %d %s", tc.name, tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRound65Wave3C_TSDBPassthroughAndDynamicTemplates(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")
	tpl := `{
		"index_patterns": ["k9s*"],
		"data_stream": {},
		"template": {
			"settings": {
				"index": {
					"number_of_shards": 1,
					"mode": "time_series",
					"time_series": {"start_time": "2023-08-31T13:03:08.138Z"}
				}
			},
			"mappings": {
				"properties": {
					"attributes": {
						"type": "passthrough",
						"dynamic": true,
						"time_series_dimension": true,
						"priority": 0
					}
				},
				"dynamic_templates": [
					{"counter_metric": {"mapping": {"type": "integer", "time_series_metric": "counter"}}}
				]
			}
		}
	}`
	if rec := doRound63Req(t, h, http.MethodPut, "/_index_template/my-dynamic-template", []byte(tpl), nil); rec.Code != http.StatusOK {
		t.Fatalf("tpl failed: %d %s", rec.Code, rec.Body.String())
	}
	bulkBody := `{ "create": { "dynamic_templates": { "data": "counter_metric" } } }
{ "@timestamp": "2023-09-01T13:03:08.138Z", "data": "10", "attributes.dim1": "A", "attributes.dim2": "1", "attributes.another.dim1": "C", "attributes.another.dim2": "10.5" }
{ "create": { "dynamic_templates": { "data": "counter_metric" } } }
{ "@timestamp": "2023-09-01T13:03:09.138Z", "data": "20", "attributes.dim1": "A", "attributes.dim2": "1", "attributes.another.dim1": "C", "attributes.another.dim2": "10.5" }
`
	rec := doRound63Req(t, h, http.MethodPost, "/k9s/_bulk?refresh=true", []byte(bulkBody), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"errors":false`) {
		t.Fatalf("k9s bulk failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRound63Req(t, h, http.MethodPost, "/k9s/_search", []byte(`{
		"size": 0,
		"aggs": {
			"filterA": {
				"filter": {"term": {"dim1": "A"}},
				"aggs": {"tsids": {"terms": {"field": "_tsid"}}}
			}
		}
	}`), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"MD2HE8yse1ZklY-p0-bRcC8gYpiKqVppKhfZ18WLDvTuNPo7EnyZdkhvafL006Xf2Q"`) {
		t.Fatalf("k9s passthrough alias search failed: %d %s", rec.Code, rec.Body.String())
	}

	otelTpl := `{
		"index_patterns": ["otel"],
		"data_stream": {},
		"template": {
			"settings": {"index": {"number_of_shards": 1, "mode": "time_series", "time_series": {"start_time": "2023-08-31T13:03:08.138Z"}}},
			"mappings": {
				"properties": {
					"body": {"type": "match_only_text"},
					"attributes": {"type": "passthrough", "dynamic": true, "time_series_dimension": true, "priority": 1},
					"scope": {"properties": {"attributes": {"type": "passthrough", "dynamic": true, "time_series_dimension": true, "priority": 2}}},
					"resource": {"properties": {"attributes": {"type": "passthrough", "dynamic": true, "time_series_dimension": true, "priority": 3}}},
					"metrics": {"type": "passthrough", "dynamic": true, "priority": 0}
				},
				"dynamic_templates": [
					{"counter_metric": {"mapping": {"type": "integer", "time_series_metric": "counter", "ignore_malformed": true}}},
					{"strings_as_keyword": {"mapping": {"type": "keyword", "ignore_above": 1024, "match_mapping_type": "string", "path_match": "*attributes.*"}}}
				]
			}
		}
	}`
	if rec2 := doRound63Req(t, h, http.MethodPut, "/_index_template/otel-tpl", []byte(otelTpl), nil); rec2.Code != http.StatusOK {
		t.Fatalf("otel tpl failed: %d %s", rec2.Code, rec2.Body.String())
	}
	otelBulk := `{ "create": { "dynamic_templates": { "metrics.data": "counter_metric" } } }
{ "@timestamp": "2023-09-01T13:03:08.138Z", "metrics": {"data": "10"}, "body": "top-level", "attributes": {"body": "attribute"}, "scope": {"attributes": {"body": "scope" }}, "resource": {"attributes": {"body": "resource" }}}
`
	rec2 := doRound63Req(t, h, http.MethodPost, "/otel/_bulk?refresh=true", []byte(otelBulk), nil)
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"errors":false`) {
		t.Fatalf("otel bulk failed: %d %s", rec2.Code, rec2.Body.String())
	}
	rec2 = doRound63Req(t, h, http.MethodPost, "/otel/_search", []byte(`{"size": 1, "fields": ["*"]}`), nil)
	if rec2.Code != http.StatusOK ||
		!strings.Contains(rec2.Body.String(), `"body":["top-level"]`) ||
		!strings.Contains(rec2.Body.String(), `"attributes.body":["attribute"]`) ||
		!strings.Contains(rec2.Body.String(), `"scope.attributes.body":["scope"]`) ||
		!strings.Contains(rec2.Body.String(), `"resource.attributes.body":["resource"]`) {
		t.Fatalf("otel conflicting alias top-level search unexpected: %d %s", rec2.Code, rec2.Body.String())
	}
}
