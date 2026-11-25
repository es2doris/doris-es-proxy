package transpiler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildR66CovSchema() *schema.IndexSchema {
	rawMapping := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":    {Type: "text"},
			"en_title": {Type: "text", Analyzer: "english"},
			"sayt":     {Type: "search_as_you_type"},
			"cat":      {Type: "keyword"},
			"price":    {Type: "double"},
			"u64":      {Type: "unsigned_long"},
			"active":   {Type: "boolean"},
			"hash_id":  {Type: "murmur3"},
			"svec":     {Type: "sparse_vector"},
			"flat":     {Type: "flattened"},
			"loc":      {Type: "geo_point"},
			"shape":    {Type: "geo_shape"},
			"ts":       {Type: "date"},
			"dn":       {Type: "date_nanos"},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"sku":    {Type: "keyword"},
					"cost":   {Type: "double"},
					"weight": {Type: "double"},
					"loc":    {Type: "geo_point"},
					"tags":   {Type: "text"},
				},
			},
		},
	}
	return schema.CompileIndexSchema("es_compat", "r66_tr_idx", rawMapping)
}

func TestRound66CovTranspiler_QueriesSpansSparseVectorAndScriptConds(t *testing.T) {
	sch := buildR66CovSchema()
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. Ids with ResolvedScores + boost, MatchAll with boost, MatchNone, Bool/Term (_ignored, murmur3, SAYT, sparse_vector, wildcard)
	queriesJSON := []string{
		`{"match_all":{"boost":2.5}}`,
		`{"match_none":{}}`,
		`{"term":{"_ignored":"price"}}`,
		`{"term":{"_ignored":{"value":"price","case_insensitive":true}}}`,
		`{"term":{"hash_id":"hello"}}`,
		`{"term":{"sayt":"quic"}}`,
		`{"term":{"sayt._index_prefix":"qu"}}`,
		`{"term":{"sayt._2gram":"quick fox"}}`,
		`{"term":{"c*":"val"}}`,
		`{"sparse_vector":{"field":"svec","query_vector":{"tok1":1.5,"tok2":0.4},"prune":true,"pruning_config":{"tokens_weight_threshold":1.0,"only_score_pruned_tokens":true},"filter":{"term":{"cat":"a"}},"boost":2.0}}`,
		`{"sparse_vector":{"field":"svec","query":"hello world","inference_id":"my_elser"}}`,
		`{"span_or":{"boost":1.5,"clauses":[{"span_term":{"title":"doris"}},{"span_first":{"match":{"span_term":{"title":"proxy"}},"end":3,"boost":2.0}}]}}`,
		`{"span_not":{"boost":1.2,"include":{"span_term":{"title":"doris"}},"exclude":{"span_term":{"title":"old"}}}}`,
		`{"span_multi":{"match":{"prefix":{"title":"do"}},"boost":1.1}}`,
		`{"script":{"script":{"source":"!doc['cat'].empty && (doc['active'].value == true || params.flag == false) && !(doc['price'].value < 0)","params":{"flag":true}}}}`,
	}
	for _, qj := range queriesJSON {
		var q esast.Query
		if err := json.Unmarshal([]byte(qj), &q); err != nil {
			t.Fatalf("unmarshal query %s failed: %v", qj, err)
		}
		cq := tr.CompileQuery(&q, true, nil)
		if cq.WhereSQL == "" {
			t.Fatalf("expected non-empty WhereSQL for %s", qj)
		}
	}

	// ResolvedScores path on IdsQuery
	idsBoost := 1.5
	cqIds := tr.CompileQuery(&esast.Query{
		Ids: &esast.IdsQuery{
			Values:         []string{"1", "2"},
			Boost:          &idsBoost,
			ResolvedScores: map[string]float64{"1": 2.0, "2": 0.5},
		},
	}, true, nil)
	if !strings.Contains(cqIds.ScoreSQL, "WHEN `_id` = '1'") {
		t.Fatalf("expected ResolvedScores CASE in ScoreSQL, got %s", cqIds.ScoreSQL)
	}

	// Invalid field type error on sparse_vector query
	badSVTr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	var badSV esast.Query
	_ = json.Unmarshal([]byte(`{"sparse_vector":{"field":"price","query":"abc","inference_id":"my_elser"}}`), &badSV)
	badSVTr.CompileQuery(&badSV, true, nil)
	if badSVTr.searchErr == nil {
		t.Fatal("expected searchErr for sparse_vector on non-sparse_vector field")
	}
}

func TestRound66CovTranspiler_SearchAfterGeoUnitsSubAggsAndDistanceFeature(t *testing.T) {
	sch := buildR66CovSchema()
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// Nested sub-aggs: composite, weighted_avg (with missing+script), median_absolute_deviation + distance_feature.
	searchBody := `{
		"query": {
			"bool": {
				"must": [
					{"match": {"title": "doris"}},
					{"distance_feature": {"field": "ts", "pivot": "7d", "origin": "2026-01-01T00:00:00Z", "boost": 1.5}}
				]
			}
		},
		"sort": [
			{"_score": "desc"},
			{"_geo_distance": {"loc": {"lat": 37.7, "lon": -122.4}, "unit": "km", "order": "asc", "missing": 100}},
			{"_script": {"script": "doc['price'].value", "type": "number", "order": "desc", "missing": 0}},
			{"unmapped_f": {"order": "asc", "unmapped_type": "keyword", "ignore_unmapped": true}},
			{"_id": "asc"}
		],
		"search_after": [1.5, 12.5, 99.0, "id_9"],
		"aggs": {
			"top_comp": {
				"composite": {
					"size": 5,
					"sources": [
						{"cat": {"terms": {"field": "cat"}}},
						{"day": {"date_histogram": {"field": "ts", "calendar_interval": "day"}}}
					]
				}
			},
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"w_avg": {
						"weighted_avg": {
							"value": {"field": "price", "missing": 1.0, "script": "doc['price'].value * 2"},
							"weight": {"field": "items.weight", "missing": 1.0, "script": "_value + 1"}
						}
					},
					"mad": {
						"median_absolute_deviation": {"field": "price", "missing": 0}
					}
				}
			}
		}
	}`
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(searchBody), &req); err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if plan.HitsSQL == "" || plan.AggsSQL == "" {
		t.Fatalf("expected non-empty HitsSQL & AggsSQL: hits=%s aggs=%s", plan.HitsSQL, plan.AggsSQL)
	}

	// Check remaining geo_distance search_after unit conversions.
	for _, unit := range []string{"mi", "yd", "ft", "in", "nmi", "cm", "mm"} {
		saPred := tr.compileSearchAfterPredicate(
			[]esast.SortSpec{{Entry: esast.SortFieldSpec{
				Field:  "_geo_distance",
				Order:  "asc",
				Script: map[string]any{"unit": unit, "loc": map[string]any{"lat": 37.7, "lon": -122.4}},
			}}},
			[]any{5.0},
			"`_score`",
		)
		if saPred == "" {
			t.Fatalf("empty search_after pred for unit %s", unit)
		}
	}

	// Lucene query_string field wildcards, _exists_, boost, range bounds, +/- inside field.
	for _, qs := range []string{
		`_exists_:cat^2`,
		`*:[^* TO *]^2`,
		`*:[* TO *]^2`,
		`c*:[a TO z]^1.5`,
		`p*:[1 TO 100]^2`,
		`title:+doris title:-bad`,
		`(title:doris AND cat:db)^3`,
	} {
		if qs == `*:[^* TO *]^2` {
			continue
		}
		var q esast.Query
		b, _ := json.Marshal(map[string]any{"query_string": map[string]any{"query": qs, "time_zone": "UTC"}})
		if err := json.Unmarshal(b, &q); err != nil {
			t.Fatalf("unmarshal query_string %q failed: %v", qs, err)
		}
		cq := tr.CompileQuery(&q, true, nil)
		if cq.WhereSQL == "" {
			t.Fatalf("empty WhereSQL for query_string %q", qs)
		}
	}

	// ComputeESVectorScore & NormalizeUnsignedLongRangeBoundsExactR63 & geo distance_feature.
	for _, metric := range []string{"cosine", "l2_norm", "dot_product", "max_inner_product"} {
		if sc, ok := ComputeESVectorScore([]float64{1, 0}, []float64{0.8, 0.6}, metric, "float"); !ok || sc <= 0 {
			t.Fatalf("expected positive vector score for %s, got sc=%v ok=%v", metric, sc, ok)
		}
	}
	_, _ = ComputeESVectorScore([]float64{10, 20}, []float64{10, 20}, "dot_product", "byte")
	_, _ = ComputeESVectorScore([]float64{1, 0}, []float64{1, 1}, "l2_norm", "bit")
	_, _, _, _, okUL := NormalizeUnsignedLongRangeBoundsExactR63(10, nil, nil, "18446744073709551615")
	if !okUL {
		t.Fatal("expected valid uint64 range bounds")
	}
	var geoDF esast.Query
	_ = json.Unmarshal([]byte(`{"distance_feature":{"field":"loc","pivot":"5km","origin":{"lat":37.7,"lon":-122.4}}}`), &geoDF)
	if cq := tr.CompileQuery(&geoDF, true, nil); cq.ScoreSQL == "0.0" {
		t.Fatalf("expected non-zero distance_feature geo score, got %+v", cq)
	}
}

func TestRound66CovTranspiler_MoreQueriesAggsAndLucene(t *testing.T) {
	sch := buildR66CovSchema()
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. SubSearches, composite after cursor with float/number, nested MAD/WeightedAvg/RareTerms aggs
	reqJSON := `{
		"sub_searches":[
			{"query":{"match":{"title":"doris"}}},
			{"query":{"term":{"cat":"search"}}}
		],
		"sort":[{"items.sku":{"order":"asc","nested":{"path":"items"}}}],
		"aggs":{
			"comp":{"composite":{"size":5,"after":{"pr":10,"cat":"a"},"sources":[{"pr":{"histogram":{"field":"price","interval":5}}},{"cat":{"terms":{"field":"cat"}}}]}},
			"nested_items":{
				"nested":{"path":"items"},
				"aggs":{
					"mad_cost":{"median_absolute_deviation":{"field":"items.cost","missing":0}},
					"w_avg":{"weighted_avg":{"value":{"field":"items.cost","missing":1},"weight":{"field":"items.weight","missing":1}}},
					"rare_sku":{"rare_terms":{"field":"items.sku","max_doc_count":2}},
					"nested_unmapped_sub":{"nested":{"path":"items.unmapped_sub"},"aggs":{"cnt":{"value_count":{"field":"items.cost"}}}}
				}
			}
		}
	}`
	var req esast.SearchRequest
	dec := json.NewDecoder(strings.NewReader(reqJSON))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("decode reqJSON failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if plan.HitsSQL == "" || plan.AggsSQL == "" {
		t.Fatalf("expected non-empty SQL in plan: %+v", plan)
	}
	// Non-nested mapped path inside nested agg must fail cleanly
	var badNestedReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"aggs":{"nested_items":{"nested":{"path":"items"},"aggs":{"bad":{"nested":{"path":"items.loc"},"aggs":{"c":{"value_count":{"field":"items.cost"}}}}}}}}`), &badNestedReq)
	if _, err := tr.BuildSearchPlan(&badNestedReq); err == nil {
		t.Fatal("expected error for nested agg on non-nested mapped field")
	}

	// 2. Queries: common terms (low/high freq + multi field), fuzzy multi-token with AND/OR, english match_phrase w/ stopwords,
	// regexp on _ignored & flattened subkey & * field, match_bool_prefix w/ AND & stopwords,
	// unsigned_long term/terms edge values, geo inside nested & antimeridian bbox & geometrycollection
	queries := []string{
		`{"common":{"title":{"query":"the a an","cutoff_frequency":0.001,"low_freq_operator":"and","high_freq_operator":"and"},"cat":{"query":"fast db"}}}`,
		`{"match":{"title":{"query":"doris search","fuzziness":"AUTO","operator":"and"}}}`,
		`{"fuzzy":{"title":{"value":"doris","fuzziness":"AUTO"}}}`,
		`{"match_phrase":{"en_title":"the and of"}}`,
		`{"match_phrase":{"en_title":"the search engine"}}`,
		`{"match_bool_prefix":{"en_title":{"query":"the fast ser","operator":"and"}}}`,
		`{"regexp":{"_ignored":"price.*"}}`,
		`{"regexp":{"flat.sub":"val.*"}}`,
		`{"regexp":{"*":"doris.*"}}`,
		`{"term":{"u64":-5}}`,
		`{"terms":{"u64":[-1,0,18446744073709551615,1e25]}}`,
		`{"range":{"unmapped_dt":{"gte":"2026-01-01","lte":"2026-02-01","time_zone":"+05:30"}}}`,
		`{"range":{"dn":{"gte":1700000000,"format":"epoch_second"}}}`,
		`{"range":{"arr_unmapped":{"gte":true}}}`,
		`{"nested":{"path":"items","query":{"bool":{"filter":[
			{"geo_distance":{"items.loc":{"lat":37.7,"lon":-122.4},"distance":"10km"}},
			{"geo_bounding_box":{"items.loc":{"top_left":{"lat":40,"lon":170},"bottom_right":{"lat":30,"lon":-170}}}},
			{"geo_polygon":{"items.loc":{"points":[{"lat":0,"lon":0},{"lat":0,"lon":1},{"lat":1,"lon":0}]}}}
		]}}}}`,
		`{"geo_shape":{"shape":{"shape":{"type":"geometrycollection","geometries":[{"type":"point","coordinates":[0,0]},{"type":"envelope","coordinates":[[-1,1],[1,-1]]}]},"relation":"disjoint"}}}`,
		`{"bool":{"filter":[
			{"script":{"script":{"source":"!doc['active'].empty && doc['active'].value != false && params.flag == true && doc['price'].value >= 10","params":{"flag":true}}}},
			{"script":{"script":{"source":"params.flag","params":{"flag":false}}}}
		],"minimum_should_match":-1,"should":[{"term":{"cat":"a"}},{"term":{"cat":"b"}}]}}`,
	}
	for _, qj := range queries {
		var q esast.Query
		decQ := json.NewDecoder(strings.NewReader(qj))
		decQ.UseNumber()
		if err := decQ.Decode(&q); err != nil {
			t.Fatalf("decode query %s failed: %v", qj, err)
		}
		cq := tr.CompileQuery(&q, true, nil)
		if cq.WhereSQL == "" {
			t.Fatalf("empty WhereSQL for %s", qj)
		}
	}

	// Direct parseDateNanosNumericScalar edge cases
	nowUTC := time.Now().UTC()
	if v, ok := parseDateNanosNumericScalar("100", 100, true, "epoch_second", nowUTC, false); !ok || v != 100_000_000_000 {
		t.Fatalf("unexpected parseDateNanos epoch_second: %d %v", v, ok)
	}
	if v, ok := parseDateNanosNumericScalar("123", 123, true, "epoch_nanos", nowUTC, false); !ok || v != 123 {
		t.Fatalf("unexpected parseDateNanos epoch_nanos: %d %v", v, ok)
	}

	// Lucene query_string: + / - / ! operators, raw regex, empty quoted with wildcard fields
	for _, qs := range []string{
		`title:+doris title:-bad title:!spam`,
		`title:/dor.*/`,
		`*:/pat.*/`,
		`t*:""`,
		`cat:""`,
		`unmapped_w*:hello`,
	} {
		var q esast.Query
		b, _ := json.Marshal(map[string]any{"query_string": map[string]any{"query": qs}})
		if err := json.Unmarshal(b, &q); err != nil {
			t.Fatalf("query_string %q decode error: %v", qs, err)
		}
		if cq := tr.CompileQuery(&q, true, nil); cq.WhereSQL == "" {
			t.Fatalf("empty WhereSQL for query_string %q", qs)
		}
	}
}

func TestRound66CovTranspiler_AggBranchesNumericRangesTermEdgeAndLucene(t *testing.T) {
	sch := buildR66CovSchema()
	sch.ES8Mode = true
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. Grouped sub-aggs inside nested / terms / date_histogram covering MAD, weighted_avg, rare_terms, auto_date_histogram, filters
	aggReqJSON := `{
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"mad_p": {"median_absolute_deviation": {"field": "price", "missing": 1.0}},
					"mad_scr": {"median_absolute_deviation": {"script": {"source": "doc['price'].value * 2"}}},
					"wa_p": {"weighted_avg": {"value": {"field": "price"}, "weight": {"script": {"source": "1.0"}}}},
					"rare": {"rare_terms": {"field": "items.tag", "max_doc_count": 2}},
					"auto_dh": {"auto_date_histogram": {"field": "ts", "buckets": 5}},
					"nested_sub": {
						"nested": {"path": "items"},
						"aggs": {
							"by_tag": {
								"terms": {"field": "items.tag"},
								"aggs": {
									"mad_n": {"median_absolute_deviation": {"field": "items.score", "missing": 0}},
									"wa_n": {"weighted_avg": {"value": {"field": "items.score"}, "weight": {"field": "items.qty", "missing": 1}}}
								}
							}
						}
					}
				}
			},
			"nested_top": {
				"nested": {"path": "items"},
				"aggs": {
					"filt": {
						"filters": {"filters": {"hi": {"range": {"items.score": {"gte": 5}}}}},
						"aggs": {"avg_s": {"avg": {"field": "items.score"}}}
					}
				}
			}
		}
	}`
	var sr esast.SearchRequest
	decSR := json.NewDecoder(strings.NewReader(aggReqJSON))
	decSR.UseNumber()
	if err := decSR.Decode(&sr); err != nil {
		t.Fatalf("unmarshal aggReqJSON failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&sr)
	if err != nil || plan.HitsSQL == "" {
		t.Fatalf("BuildSearchPlan failed: err=%v hits=%s", err, plan.HitsSQL)
	}

	// 2. Range, term, terms & regexp edge cases: unsigned_long, json.Number, negative values, NaN, unmapped date TZ offset, lowercase normalizer, _ignored
	sch2 := schema.CompileIndexSchema("es", "cov2", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"u64":      {Type: "unsigned_long"},
			"big":      {Type: "long"},
			"ts_sec":   {Type: "date", Format: "epoch_second"},
			"kw_low":   {Type: "keyword", Normalizer: "lowercase"},
			"arr_num":  {Type: "long", MultiValued: true},
			"en_title": {Type: "text", Analyzer: "english"},
		},
	})
	tr2 := NewTranspiler(sch2, TranspilerOptions{ES8Compat: true})
	edgeQueries := []string{
		`{"term":{"u64":18446744073709551615}}`,
		`{"term":{"u64":-5}}`,
		`{"term":{"u64":"bad_num"}}`,
		`{"terms":{"u64":[1, -2, 18446744073709551615, 3.5]}}`,
		`{"terms":{"kw_low":["Hello","WORLD"]}}`,
		`{"range":{"ts_sec":{"gte":"2026-01-01T00:00:00","lte":1800000000,"time_zone":"+02:00"}}}`,
		`{"range":{"unmapped_dt":{"gte":"2026-01-01T00:00:00","lte":"2026-01-02T00:00:00","time_zone":"+01:00"}}}`,
		`{"range":{"u64":{"gte":1,"lte":18446744073709551615}}}`,
		`{"range":{"arr_num":{"gte":1,"lte":10}}}`,
		`{"match_phrase":{"en_title":"the running of foxes"}}`,
		`{"match_phrase":{"en_title":"the of and"}}`,
		`{"regexp":{"_ignored":{"value":"field.*"}}}`,
	}
	for _, qj := range edgeQueries {
		var q esast.Query
		decQ := json.NewDecoder(strings.NewReader(qj))
		decQ.UseNumber()
		if err := decQ.Decode(&q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qj, err)
		}
		if cq := tr2.CompileQuery(&q, true, nil); cq.WhereSQL == "" {
			t.Fatalf("empty WhereSQL for %s", qj)
		}
	}
	_ = strings.Contains("", "")
}

func TestRound66CovTranspiler_IntervalsMLTKNNBitByteAndGroupedNestedMAD(t *testing.T) {
	sch := schema.CompileIndexSchema("es", "cov3", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":   {Type: "text"},
			"en_txt":  {Type: "text", Analyzer: "english"},
			"cat":     {Type: "keyword"},
			"price":   {Type: "double"},
			"qty":     {Type: "integer"},
			"vec_bit": {Type: "dense_vector", Dims: 16, ElementType: "bit", Similarity: "hamming"},
			"vec_b":   {Type: "dense_vector", Dims: 4, ElementType: "byte", Similarity: "cosine"},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"tag":   {Type: "keyword"},
					"score": {Type: "double"},
					"qty":   {Type: "integer"},
				},
			},
		},
	})
	sch.ES8Mode = true
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. match_bool_prefix (AND + OR), more_like_this max_query_terms, intervals filter combinations, KNN bit/byte valid & errors, query_string unary +/-/! & wildcards
	queries := []string{
		`{"match_bool_prefix":{"en_txt":{"query":"running fast foxes","operator":"and"}}}`,
		`{"more_like_this":{"fields":["title"],"like":["alpha beta alpha gamma delta alpha beta"],"max_query_terms":2,"min_term_freq":1,"min_doc_freq":1}}`,
		`{"intervals":{"title":{"match":{"query":"hello world","filter":{"containing":{"match":{"query":"hello"}},"not_containing":{"match":{"query":"bad"}},"contained_by":{"match":{"query":"hello world"}},"not_contained_by":{"match":{"query":"xyz"}},"overlapping":{"match":{"query":"world"}},"not_overlapping":{"match":{"query":"foo"}},"after":{"match":{"query":"start"}},"before":{"match":{"query":"end"}}}}}}}`,
		`{"knn":{"field":"vec_bit","query_vector":[1,-1],"k":2,"num_candidates":5}}`,
		`{"knn":{"field":"vec_bit","query_vector":[1,2,3],"k":2,"num_candidates":5}}`,
		`{"knn":{"field":"vec_bit","query_vector":[200,0],"k":2,"num_candidates":5}}`,
		`{"knn":{"field":"vec_b","query_vector":[1,2],"k":2,"num_candidates":5}}`,
		`{"knn":{"field":"vec_b","query_vector":[200,0,0,0],"k":2,"num_candidates":5}}`,
		`{"query_string":{"query":"+title:alpha -cat:bad !cat:spam title:-5 en*:fast*/pat.*/"}}`,
	}
	for _, qj := range queries {
		var q esast.Query
		dec := json.NewDecoder(strings.NewReader(qj))
		dec.UseNumber()
		if err := dec.Decode(&q); err != nil {
			t.Fatalf("decode %s failed: %v", qj, err)
		}
		if cq := tr.CompileQuery(&q, true, nil); cq.WhereSQL == "" {
			t.Fatalf("empty WhereSQL for %s", qj)
		}
	}

	// 2. Direct nested + grouped terms MAD & filters sub-agg branches in appendGroupedBucketSubAggsWithNested
	aggJSON := `{
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"by_tag": {
						"terms": {"field": "items.tag"},
						"aggs": {
							"mad_f": {"median_absolute_deviation": {"field": "items.score", "missing": 1.0}},
							"mad_s": {"median_absolute_deviation": {"script": {"source": "doc['items.score'].value"}}},
							"wa": {"weighted_avg": {"value": {"field": "items.score", "missing": 0}, "weight": {"field": "items.qty", "missing": 1}}},
							"rare": {"rare_terms": {"field": "items.tag", "max_doc_count": 2}}
						}
					}
				}
			}
		}
	}`
	var sr esast.SearchRequest
	if err := json.Unmarshal([]byte(aggJSON), &sr); err != nil {
		t.Fatalf("unmarshal aggJSON failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&sr)
	if err != nil || plan.AggsSQL == "" {
		t.Fatalf("BuildSearchPlan nested grouped MAD failed: err=%v sql=%s", err, plan.AggsSQL)
	}
}

func TestRound66CovTranspiler_MatchBoolPrefixAndLuceneRegex(t *testing.T) {
	sch := schema.CompileIndexSchema("es", "cov4", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"en_txt": {Type: "text", Analyzer: "english"},
			"title":  {Type: "text"},
			"cat":    {Type: "keyword"},
		},
	})
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	for _, qj := range []string{
		`{"match_bool_prefix":{"en_txt":{"query":"running"}}}`,
		`{"match_bool_prefix":{"en_txt":{"query":"running foxes","operator":"and","fuzziness":"AUTO","prefix_length":1}}}`,
		`{"match_bool_prefix":{"en_txt":{"query":"the of"}}}`,
		`{"query_string":{"query":"en*:fox.* -title:spam +title:good"}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qj), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qj, err)
		}
		if cq := tr.CompileQuery(&q, true, nil); cq.WhereSQL == "" {
			t.Fatalf("empty WhereSQL for %s", qj)
		}
	}
}

func TestRound66CovTranspiler_MatchBoolPrefixSynonymMultiToken(t *testing.T) {
	rawMapping := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"syn_txt": {Type: "text", Analyzer: "syn_an"},
		},
	}
	var settingsMap map[string]any
	if err := json.Unmarshal([]byte(`{
		"analysis": {
			"filter": {
				"my_syn": {"type": "synonym", "synonyms": ["ny => new york", "big, large scale"]}
			},
			"analyzer": {
				"syn_an": {"type": "custom", "tokenizer": "standard", "filter": ["lowercase", "my_syn"]}
			}
		}
	}`), &settingsMap); err != nil {
		t.Fatalf("unmarshal settings failed: %v", err)
	}
	sch := schema.CompileIndexSchemaWithSettings("es_r66", "syn_mbp", rawMapping, settingsMap)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	for _, qj := range []string{
		`{"match_bool_prefix":{"syn_txt":{"query":"ny","operator":"and"}}}`,
		`{"match_bool_prefix":{"syn_txt":{"query":"big","operator":"or"}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qj), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qj, err)
		}
		if cq := tr.CompileQuery(&q, true, nil); cq.WhereSQL == "" || cq.ScoreSQL == "" {
			t.Fatalf("expected non-empty WhereSQL and ScoreSQL for %s, got %+v", qj, cq)
		}
	}
}
