package schema

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func shredRound39ToMap(t *testing.T, s *IndexSchema, id string, raw string) map[string]any {
	t.Helper()
	rowBytes, err := ShredDocument(s, id, 1, false, json.RawMessage(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(rowBytes, &m); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	return m
}

func TestRound39_F1_EnabledFalseAndIndexFalse(t *testing.T) {
	f := false
	raw := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title": {Type: "text"},
			"secret_code": {
				Type:  "keyword",
				Index: &f,
			},
			"payload": {
				Type:    "object",
				Enabled: &f,
				Properties: map[string]esast.FieldProperty{
					"inner": {Type: "keyword"},
				},
			},
		},
	}
	s := CompileIndexSchema("es_db", "idx_r39_f1", raw)

	// 1. secret_code is NotIndexed
	sc := s.ResolveField("secret_code")
	if !sc.NotIndexed || sc.EnabledFalse {
		t.Fatalf("expected secret_code NotIndexed=true, got binding=%+v", sc)
	}

	// 2. payload and payload.inner resolve with EnabledFalse=true, NotIndexed=true
	pl := s.ResolveField("payload")
	if !pl.EnabledFalse || !pl.NotIndexed {
		t.Fatalf("expected payload EnabledFalse=true, got binding=%+v", pl)
	}
	plInner := s.ResolveField("payload.inner")
	if !plInner.EnabledFalse || !plInner.NotIndexed {
		t.Fatalf("expected payload.inner EnabledFalse=true, got binding=%+v", plInner)
	}

	// 3. ExpandFieldPattern("*") excludes secret_code and payload*
	expanded := s.ExpandFieldPattern("*")
	for _, b := range expanded {
		if b.Field == "secret_code" || strings.HasPrefix(b.Field, "payload") {
			t.Fatalf("unexpected non-searchable field %q in ExpandFieldPattern(*)", b.Field)
		}
	}

	// 4. ShredDocument keeps secret_code in column, omits secret_code and payload from _all_text and _doc
	row := shredRound39ToMap(t, s, "1", `{"title":"hello","secret_code":"xyz987","payload":{"inner":"deep_secret"}}`)
	if row["f__secret_code"] != "xyz987" {
		t.Fatalf("expected f__secret_code column to be populated, got %v", row["f__secret_code"])
	}
	allText, _ := row["_all_text"].(string)
	if strings.Contains(allText, "xyz987") || strings.Contains(allText, "deep_secret") {
		t.Fatalf("expected _all_text to exclude index:false and enabled:false values, got %q", allText)
	}
	docBytes, _ := json.Marshal(row["_doc"])
	docStr := string(docBytes)
	if strings.Contains(docStr, "deep_secret") {
		t.Fatalf("expected _doc variant to exclude enabled:false values, got %q", docStr)
	}

	// 5. MergeMappingSpecs preserves Enabled and Index
	merged := MergeMappingSpecs(raw, &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"extra": {Type: "keyword"},
		},
	})
	if merged.Properties["secret_code"].Index == nil || *merged.Properties["secret_code"].Index {
		t.Fatalf("expected MergeMappingSpecs to preserve Index=false")
	}
	if merged.Properties["payload"].Enabled == nil || *merged.Properties["payload"].Enabled {
		t.Fatalf("expected MergeMappingSpecs to preserve Enabled=false")
	}
}

func TestRound39_F2_LeafFieldRejectsJSONObject(t *testing.T) {
	tr := true
	raw := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":   {Type: "text"},
			"tags":    {Type: "keyword"},
			"lenient": {Type: "keyword", IgnoreMalformed: &tr},
			"user": {
				Type: "text",
				Properties: map[string]esast.FieldProperty{
					"name": {Type: "keyword"},
				},
			},
		},
	}
	s := CompileIndexSchema("es_db", "idx_r39_f2", raw)

	// 1. Direct JSON object on text field -> mapper_parsing_exception
	if _, err := ShredDocument(s, "1", 1, false, json.RawMessage(`{"title":{"sub":"bad"}}`)); err == nil {
		t.Fatalf("expected error when indexing JSON object into text leaf field")
	}

	// 2. JSON object inside array on keyword field -> mapper_parsing_exception
	if _, err := ShredDocument(s, "2", 1, false, json.RawMessage(`{"tags":["valid",{"sub":"bad"}]}`)); err == nil {
		t.Fatalf("expected error when indexing array containing JSON object into keyword leaf field")
	}

	// 3. ignore_malformed: true records field in _ignored and succeeds
	row := shredRound39ToMap(t, s, "3", `{"lenient":{"sub":"ignored_obj"},"title":"ok"}`)
	ignored, _ := row["_ignored"].([]any)
	if len(ignored) != 1 || ignored[0] != "lenient" {
		t.Fatalf("expected _ignored=[lenient], got %v", row["_ignored"])
	}

	// 4. Hybrid field with explicit sub-properties still accepts object
	row4 := shredRound39ToMap(t, s, "4", `{"user":{"name":"alice"}}`)
	if row4["f__user__name"] != "alice" {
		t.Fatalf("expected f__user__name=alice, got %v", row4["f__user__name"])
	}
}

func TestRound39_F3_CopyToCustomMultiFieldsAndNestedCoerce(t *testing.T) {
	f := false
	raw := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"first": {Type: "text", CopyTo: "full"},
			"last":  {Type: "text", CopyTo: "full"},
			"full": {
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"raw": {Type: "keyword"},
					"len": {Type: "token_count"},
				},
			},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"name": {
						Type: "text",
						Fields: map[string]esast.FieldProperty{
							"raw": {Type: "keyword"},
						},
					},
					"active": {
						Type:   "boolean",
						Coerce: &f,
					},
				},
			},
		},
	}
	s := CompileIndexSchema("es_db", "idx_r39_f3", raw)

	fullRaw := s.ResolveField("full.raw")
	if fullRaw.Kind != StoragePromotedArray {
		t.Fatalf("expected full.raw to be upgraded to StoragePromotedArray by copy_to, got binding=%+v", fullRaw)
	}

	row := shredRound39ToMap(t, s, "1", `{"first":"Ada","last":"Lovelace","items":[{"name":"math","active":true}]}`)
	rawVals, ok := row["f__full__raw"].([]any)
	if !ok || len(rawVals) != 2 || rawVals[0] != "Ada" || rawVals[1] != "Lovelace" {
		t.Fatalf("expected f__full__raw=[Ada Lovelace], got %T %v", row["f__full__raw"], row["f__full__raw"])
	}
	itemsBytes, _ := json.Marshal(row["n__items"])
	if strings.Contains(string(itemsBytes), `"raw"`) {
		t.Fatalf("expected nested storage not to leak synthetic multi-field key 'raw', got %s", string(itemsBytes))
	}

	// Nested boolean with coerce: false rejects string "true"
	if _, err := ShredDocument(s, "2", 1, false, json.RawMessage(`{"items":[{"name":"math","active":"true"}]}`)); err == nil {
		t.Fatalf("expected nested boolean with coerce:false to reject string 'true'")
	}
}
