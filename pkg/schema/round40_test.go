package schema

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound40_F3_ShredScalarOrObjectUnderArrayPath(t *testing.T) {
	raw := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"tags": {
				Type:        "keyword",
				MultiValued: true,
				Properties: map[string]esast.FieldProperty{
					"tagFQN": {Type: "keyword", MultiValued: true},
				},
			},
		},
	}
	s := CompileIndexSchema("es_db", "idx_r40_f3", raw)

	// Sub-object at a promoted array path with subproperties ("tags": {"tagFQN": "tier.gold"}) must not stringify the map into f__tags as ["map[tagFQN:tier.gold]"]
	rowBytes, err := ShredDocument(s, "1", 1, false, json.RawMessage(`{"tags": {"tagFQN": "tier.gold"}}`))
	if err != nil {
		t.Fatalf("unexpected shred error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(rowBytes, &m); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if m["f__tags"] != nil {
		t.Fatalf("expected f__tags to be omitted when document has map at path, got %v (%T)", m["f__tags"], m["f__tags"])
	}
	if arr, ok := m["f__tags__tagFQN"].([]any); !ok || len(arr) != 1 || arr[0] != "tier.gold" {
		t.Fatalf("expected f__tags__tagFQN to be [\"tier.gold\"], got %v (%T)", m["f__tags__tagFQN"], m["f__tags__tagFQN"])
	}
}

func TestRound40_F4_EnabledFalseWithDottedDocumentKeys(t *testing.T) {
	f := false
	raw := &esast.MappingSpec{
		Dynamic: "strict",
		Properties: map[string]esast.FieldProperty{
			"title": {Type: "text"},
			"payload": {
				Type:    "object",
				Enabled: &f,
			},
		},
	}
	s := CompileIndexSchema("es_db", "idx_r40_f4", raw)

	// Document uses flat dotted key "payload.secret" under enabled:false object "payload"
	docJSON := `{"title": "visible_word", "payload.secret": "top_secret_token", "payload.deep.key": "hidden_value"}`
	rowBytes, err := ShredDocument(s, "1", 1, false, json.RawMessage(docJSON))
	if err != nil {
		t.Fatalf("expected strict dynamic mapping to allow dotted key under enabled:false object, got error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(rowBytes, &m); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	// _all_text must not contain values from payload.secret or payload.deep.key
	allText, _ := m["_all_text"].(string)
	if strings.Contains(allText, "top_secret_token") || strings.Contains(allText, "hidden_value") {
		t.Fatalf("expected _all_text to exclude enabled:false dotted keys, got %q", allText)
	}
	if !strings.Contains(allText, "visible_word") {
		t.Fatalf("expected _all_text to contain visible_word, got %q", allText)
	}
	// _doc VARIANT must not contain payload.secret or payload.deep.key
	var docVariant map[string]any
	if docStr, ok := m["_doc"].(string); ok {
		_ = json.Unmarshal([]byte(docStr), &docVariant)
	}
	if _, exists := docVariant["payload.secret"]; exists {
		t.Fatalf("expected _doc variant to strip payload.secret, got %+v", docVariant)
	}
	if _, exists := docVariant["payload.deep.key"]; exists {
		t.Fatalf("expected _doc variant to strip payload.deep.key, got %+v", docVariant)
	}
}

func TestRound40_F5_AliasToEnabledFalseAndChainedAliases(t *testing.T) {
	f := false
	raw := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title": {
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"keyword": {Type: "keyword"},
				},
			},
			"alias1":   {Type: "alias", Path: "title"},
			"alias2":   {Type: "alias", Path: "alias1"},
			"alias_kw": {Type: "alias", Path: "alias1.keyword"},
			"payload": {
				Type:    "object",
				Enabled: &f,
			},
			"payload_alias": {
				Type: "alias",
				Path: "payload",
			},
			"payload_sub_alias": {
				Type: "alias",
				Path: "payload.inner",
			},
		},
	}
	s := CompileIndexSchema("es_db", "idx_r40_f5", raw)

	// 1. Chained alias alias2 -> alias1 -> title
	b2 := s.ResolveField("alias2")
	if b2.ColumnName != "f__title" || b2.KeywordCompanion != "f__title__keyword" {
		t.Fatalf("expected chained alias2 to resolve to f__title with companion f__title__keyword, got %+v", b2)
	}
	bKw := s.ResolveField("alias_kw")
	if bKw.ColumnName != "f__title__keyword" {
		t.Fatalf("expected alias_kw to resolve to f__title__keyword, got %+v", bKw)
	}

	// 2. Alias to enabled: false object or subpath preserves EnabledFalse=true and NotIndexed=true
	pa := s.ResolveField("payload_alias")
	if !pa.EnabledFalse || !pa.NotIndexed {
		t.Fatalf("expected payload_alias to preserve EnabledFalse=true and NotIndexed=true, got %+v", pa)
	}
	psa := s.ResolveField("payload_sub_alias")
	if !psa.EnabledFalse || !psa.NotIndexed {
		t.Fatalf("expected payload_sub_alias to preserve EnabledFalse=true and NotIndexed=true, got %+v", psa)
	}
}

func TestRound40_F6_GenerateAlterTableDDLUpdatesAliasesToWidenedArrays(t *testing.T) {
	rawOld := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"tag":       {Type: "keyword"},
			"tag_alias": {Type: "alias", Path: "tag"},
		},
	}
	oldSchema := CompileIndexSchema("es_db", "idx_r40_f6", rawOld)

	rawNew := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"tag":       {Type: "keyword", MultiValued: true, UpgradedArray: true},
			"tag_alias": {Type: "alias", Path: "tag"},
		},
	}
	newSchema := CompileIndexSchema("es_db", "idx_r40_f6", rawNew)

	stmts := GenerateAlterTableDDL(oldSchema, newSchema)
	if len(stmts) == 0 {
		t.Fatalf("expected ALTER TABLE statements when tag is widened to array")
	}
	aliasBinding := newSchema.ResolveField("tag_alias")
	if aliasBinding.Kind != StoragePromotedArray || aliasBinding.ColumnName != "f__arr__tag" {
		t.Fatalf("expected tag_alias to be updated to StoragePromotedArray f__arr__tag, got %+v", aliasBinding)
	}
}
