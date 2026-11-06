package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FileReport summarizes compliance execution for a single rest-api-spec YAML file.
type FileReport struct {
	File        string
	SectionsRun int
	StepsRun    int
}

// SuiteReport summarizes compliance execution across all rest-api-spec YAML files.
type SuiteReport struct {
	FilesRun    int
	SectionsRun int
	StepsRun    int
	FileReports []FileReport
}

// RunEmbeddedSuite executes all embedded specs/*.yml files against baseURL.
func RunEmbeddedSuite(t *testing.T, baseURL string) {
	t.Helper()
	report := RunSuiteFS(t, EmbeddedSpecsFS, baseURL)
	if report.FilesRun == 0 {
		t.Fatalf("no embedded rest-api-spec YAML files were executed")
	}
}

// RunSuiteFS discovers and runs all *.yml files in fsys (both root and specs/*.yml) against baseURL.
func RunSuiteFS(t *testing.T, fsys fs.FS, baseURL string) SuiteReport {
	t.Helper()
	var files []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed walking compliance spec filesystem: %v", err)
	}
	sort.Strings(files)

	client := &http.Client{Timeout: 30 * time.Second}
	var report SuiteReport

	for _, file := range files {
		rawBytes, readErr := fs.ReadFile(fsys, file)
		if readErr != nil {
			t.Fatalf("failed reading spec file %s: %v", file, readErr)
		}
		specDoc, parseErr := ParseSpecFile(string(rawBytes))
		if parseErr != nil {
			t.Fatalf("failed parsing spec file %s: %v", file, parseErr)
		}

		fileRep := FileReport{File: path.Base(file)}
		t.Run(path.Base(file), func(t *testing.T) {
			for _, sec := range specDoc.Sections {
				sec := sec
				fileRep.SectionsRun++
				report.SectionsRun++
				t.Run(sec.Name, func(t *testing.T) {
					ctx := newRunnerContext(client, strings.TrimRight(baseURL, "/"))
					defer ctx.cleanupAll()

					for i, step := range specDoc.Setup {
						fileRep.StepsRun++
						report.StepsRun++
						if err := ctx.execStep(step, false); err != nil {
							t.Fatalf("[setup step %d (%s)] %v", i+1, step.Op, err)
						}
					}

					var testErr error
					for i, step := range sec.Steps {
						fileRep.StepsRun++
						report.StepsRun++
						if err := ctx.execStep(step, false); err != nil {
							testErr = fmt.Errorf("[step %d (%s)] %w", i+1, step.Op, err)
							break
						}
					}

					for i, step := range specDoc.Teardown {
						fileRep.StepsRun++
						report.StepsRun++
						if err := ctx.execStep(step, true); err != nil && testErr == nil {
							testErr = fmt.Errorf("[teardown step %d (%s)] %w", i+1, step.Op, err)
						}
					}

					if testErr != nil {
						t.Fatal(testErr)
					}
				})
			}
		})
		report.FilesRun++
		report.FileReports = append(report.FileReports, fileRep)
	}

	return report
}

type runnerContext struct {
	client           *http.Client
	baseURL          string
	stash            map[string]any
	lastStatus       int
	lastMethod       string
	lastBodyRaw      string
	lastResponse     any
	createdIndices   map[string]bool
	createdTemplates map[string]bool
	createdCompTmpls map[string]bool
	createdPipelines map[string]bool
	createdAliases   map[string]string // alias -> index
}

func newRunnerContext(client *http.Client, baseURL string) *runnerContext {
	return &runnerContext{
		client:           client,
		baseURL:          baseURL,
		stash:            make(map[string]any),
		createdIndices:   make(map[string]bool),
		createdTemplates: make(map[string]bool),
		createdCompTmpls: make(map[string]bool),
		createdPipelines: make(map[string]bool),
		createdAliases:   make(map[string]string),
	}
}

func (c *runnerContext) cleanupAll() {
	for alias, idx := range c.createdAliases {
		if idx != "" && alias != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/"+url.PathEscape(idx)+"/_alias/"+url.PathEscape(alias), nil, nil, nil)
		}
	}
	for idx := range c.createdIndices {
		if idx != "" && !strings.HasPrefix(idx, "_") {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/"+url.PathEscape(idx), nil, nil, nil)
		}
	}
	for tmpl := range c.createdTemplates {
		if tmpl != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_index_template/"+url.PathEscape(tmpl), nil, nil, nil)
		}
	}
	for comp := range c.createdCompTmpls {
		if comp != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_component_template/"+url.PathEscape(comp), nil, nil, nil)
		}
	}
	for pipe := range c.createdPipelines {
		if pipe != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_ingest/pipeline/"+url.PathEscape(pipe), nil, nil, nil)
		}
	}
}

func (c *runnerContext) execStep(step SpecStep, isTeardown bool) error {
	switch step.Op {
	case "do":
		return c.execDo(step.Value, isTeardown)
	case "set":
		return c.execSet(step.Value)
	case "match":
		return c.execMatch(step.Value)
	case "is_true":
		return c.execIsTrue(step.Value)
	case "is_false":
		return c.execIsFalse(step.Value)
	case "length":
		return c.execLength(step.Value)
	case "gt":
		return c.execCompare("gt", step.Value)
	case "gte":
		return c.execCompare("gte", step.Value)
	case "lt":
		return c.execCompare("lt", step.Value)
	case "lte":
		return c.execCompare("lte", step.Value)
	default:
		return fmt.Errorf("unsupported spec step operation %q", step.Op)
	}
}

func (c *runnerContext) execDo(rawVal any, isTeardown bool) error {
	om, ok := rawVal.(*OrderedMap)
	if !ok {
		return fmt.Errorf("do step requires a mapping, got %T", rawVal)
	}

	var catchSpec string
	var headers map[string]string
	var ignoreStatuses map[int]bool
	var actionName string
	var actionParams any

	for _, f := range om.Fields {
		switch f.Key {
		case "catch":
			catchSpec = fmt.Sprintf("%v", c.expandStash(f.Value))
		case "headers":
			headers = make(map[string]string)
			if hm, ok := ToNative(c.expandStash(f.Value)).(map[string]any); ok {
				for hk, hv := range hm {
					headers[hk] = fmt.Sprintf("%v", hv)
				}
			}
		case "ignore":
			ignoreStatuses = parseIgnoreStatuses(c.expandStash(f.Value))
		case "warnings", "allowed_warnings", "allowed_warnings_regex":
			// Ignored warning metadata directives from upstream rest-api-spec
		default:
			actionName = f.Key
			actionParams = f.Value
		}
	}

	if actionName == "" {
		return fmt.Errorf("do step is missing API action name")
	}

	expandedParams := ToNative(c.expandStash(actionParams))
	paramMap, _ := expandedParams.(map[string]any)
	if paramMap == nil {
		paramMap = make(map[string]any)
	}
	if rawIgnore, ok := paramMap["ignore"]; ok {
		for code := range parseIgnoreStatuses(rawIgnore) {
			if ignoreStatuses == nil {
				ignoreStatuses = make(map[int]bool)
			}
			ignoreStatuses[code] = true
		}
		delete(paramMap, "ignore")
	}

	reqSpec, err := c.buildActionRequest(actionName, paramMap)
	if err != nil {
		return err
	}

	status, bodyStr, err := c.rawHTTP(reqSpec.method, reqSpec.path, reqSpec.query, reqSpec.body, headers)
	if err != nil {
		return fmt.Errorf("HTTP request %s %s failed: %w", reqSpec.method, reqSpec.path, err)
	}

	c.lastStatus = status
	c.lastMethod = reqSpec.method
	c.lastBodyRaw = bodyStr
	c.lastResponse = parseResponsePayload(bodyStr)

	// Record resources created during this section for automatic post-section cleanup
	c.trackCreatedResources(actionName, paramMap, c.lastResponse)

	if isTeardown && catchSpec == "" && (status == http.StatusNotFound || status == http.StatusBadRequest) {
		return nil
	}
	if ignoreStatuses != nil && ignoreStatuses[status] {
		return nil
	}

	if catchSpec != "" {
		return c.verifyCatch(catchSpec, actionName, status, bodyStr, c.lastResponse)
	}

	if reqSpec.method == http.MethodHead {
		// HEAD requests legitimately return 200 or 404 and are checked by subsequent is_true / is_false: ''
		if status == http.StatusOK || status == http.StatusNotFound {
			return nil
		}
	}

	if status >= 400 {
		return fmt.Errorf("action %s (%s %s) returned unexpected HTTP %d: %s", actionName, reqSpec.method, reqSpec.path, status, bodyStr)
	}
	return nil
}

func parseIgnoreStatuses(v any) map[int]bool {
	out := make(map[int]bool)
	switch val := v.(type) {
	case int:
		out[val] = true
	case int64:
		out[int(val)] = true
	case float64:
		out[int(val)] = true
	case string:
		for _, part := range strings.Split(val, ",") {
			if code, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				out[code] = true
			}
		}
	case []any:
		for _, item := range val {
			for k := range parseIgnoreStatuses(item) {
				out[k] = true
			}
		}
	}
	return out
}

func (c *runnerContext) verifyCatch(catchSpec, actionName string, status int, bodyStr string, parsed any) error {
	switch catchSpec {
	case "missing":
		if status != http.StatusNotFound {
			return fmt.Errorf("action %s expected catch: missing (HTTP 404), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	case "bad_request", "param":
		if status != http.StatusBadRequest {
			return fmt.Errorf("action %s expected catch: %s (HTTP 400), got HTTP %d: %s", actionName, catchSpec, status, bodyStr)
		}
		return nil
	case "conflict":
		if status != http.StatusConflict {
			return fmt.Errorf("action %s expected catch: conflict (HTTP 409), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	case "forbidden":
		if status != http.StatusForbidden {
			return fmt.Errorf("action %s expected catch: forbidden (HTTP 403), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	case "unauthorized":
		if status != http.StatusUnauthorized {
			return fmt.Errorf("action %s expected catch: unauthorized (HTTP 401), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	case "request_timeout":
		if status != http.StatusRequestTimeout {
			return fmt.Errorf("action %s expected catch: request_timeout (HTTP 408), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	}

	if strings.HasPrefix(catchSpec, "/") && strings.HasSuffix(catchSpec, "/") && len(catchSpec) >= 2 {
		pattern := catchSpec[1 : len(catchSpec)-1]
		if status < 400 {
			return fmt.Errorf("action %s expected error matching %s (HTTP >= 400), got HTTP %d: %s", actionName, catchSpec, status, bodyStr)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid catch regex %q: %w", catchSpec, err)
		}
		errText := extractErrorText(parsed, bodyStr)
		if !re.MatchString(errText) && !re.MatchString(bodyStr) {
			return fmt.Errorf("action %s error %q did not match catch regex %s", actionName, errText, catchSpec)
		}
		return nil
	}

	return fmt.Errorf("unsupported catch specification %q", catchSpec)
}

func extractErrorText(parsed any, raw string) string {
	if m, ok := parsed.(map[string]any); ok {
		switch errVal := m["error"].(type) {
		case string:
			return errVal
		case map[string]any:
			var parts []string
			if t, ok := errVal["type"].(string); ok {
				parts = append(parts, t)
			}
			if r, ok := errVal["reason"].(string); ok {
				parts = append(parts, r)
			}
			if len(parts) > 0 {
				return strings.Join(parts, ": ")
			}
		}
	}
	return raw
}

func (c *runnerContext) trackCreatedResources(action string, params map[string]any, resp any) {
	idx := paramString(params, "index")
	switch action {
	case "indices.create", "index", "create", "indices.put_mapping", "indices.put_settings":
		if idx != "" {
			for _, part := range strings.Split(idx, ",") {
				p := strings.TrimSpace(part)
				if p != "" && !strings.ContainsAny(p, "*?") {
					c.createdIndices[p] = true
				}
			}
		}
	case "bulk":
		if idx != "" {
			c.createdIndices[idx] = true
		}
		if bodySlice, ok := params["body"].([]any); ok {
			for _, item := range bodySlice {
				if m, ok := item.(map[string]any); ok {
					for _, opName := range []string{"index", "create", "update", "delete"} {
						if meta, ok := m[opName].(map[string]any); ok {
							if bIdx := paramString(meta, "_index"); bIdx != "" {
								c.createdIndices[bIdx] = true
							}
						}
					}
				}
			}
		}
	case "reindex":
		if bodyMap, ok := params["body"].(map[string]any); ok {
			if dest, ok := bodyMap["dest"].(map[string]any); ok {
				if dIdx := paramString(dest, "index"); dIdx != "" {
					c.createdIndices[dIdx] = true
				}
			}
		}
	case "indices.rollover":
		if newIdx := paramString(params, "new_index"); newIdx != "" {
			c.createdIndices[newIdx] = true
		}
		if rm, ok := resp.(map[string]any); ok {
			if newIdx, ok := rm["new_index"].(string); ok && newIdx != "" {
				c.createdIndices[newIdx] = true
			}
		}
	case "indices.put_alias":
		name := paramString(params, "name")
		if idx != "" && name != "" {
			c.createdIndices[idx] = true
			c.createdAliases[name] = idx
		}
	case "indices.put_index_template":
		if name := paramString(params, "name"); name != "" {
			c.createdTemplates[name] = true
		}
	case "cluster.put_component_template":
		if name := paramString(params, "name"); name != "" {
			c.createdCompTmpls[name] = true
		}
	case "ingest.put_pipeline":
		if id := paramString(params, "id"); id != "" {
			c.createdPipelines[id] = true
		}
	}
}

type httpRequestSpec struct {
	method string
	path   string
	query  url.Values
	body   []byte
}

func (c *runnerContext) buildActionRequest(action string, params map[string]any) (*httpRequestSpec, error) {
	// Clone params so we can pop path/body params and leave query params
	remaining := make(map[string]any, len(params))
	for k, v := range params {
		remaining[k] = v
	}

	popString := func(keys ...string) string {
		for _, k := range keys {
			if v, exists := remaining[k]; exists {
				delete(remaining, k)
				return joinParamValue(v)
			}
		}
		return ""
	}

	rawBody, hasBody := remaining["body"]
	delete(remaining, "body")

	var method string
	var reqPath string
	isNDJSON := false

	switch action {
	case "info":
		method = http.MethodGet
		reqPath = "/"

	case "cluster.health":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/_cluster/health/" + idx
		} else {
			reqPath = "/_cluster/health"
		}

	case "cluster.state":
		method = http.MethodGet
		reqPath = "/_cluster/state"

	case "cluster.stats":
		method = http.MethodGet
		reqPath = "/_cluster/stats"

	case "cluster.get_settings":
		method = http.MethodGet
		reqPath = "/_cluster/settings"

	case "cluster.put_settings":
		method = http.MethodPut
		reqPath = "/_cluster/settings"

	case "nodes.info":
		method = http.MethodGet
		reqPath = "/_nodes"

	case "nodes.stats":
		method = http.MethodGet
		reqPath = "/_nodes/stats"

	case "indices.create":
		method = http.MethodPut
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.create requires index parameter")
		}
		reqPath = "/" + idx

	case "indices.delete":
		method = http.MethodDelete
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.delete requires index parameter")
		}
		reqPath = "/" + idx

	case "indices.exists":
		method = http.MethodHead
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.exists requires index parameter")
		}
		reqPath = "/" + idx

	case "indices.get":
		method = http.MethodGet
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.get requires index parameter")
		}
		reqPath = "/" + idx

	case "indices.get_mapping":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_mapping"
		} else {
			reqPath = "/_mapping"
		}

	case "indices.put_mapping":
		method = http.MethodPut
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.put_mapping requires index parameter")
		}
		reqPath = "/" + idx + "/_mapping"

	case "indices.get_field_mapping":
		method = http.MethodGet
		idx := popString("index")
		fields := popString("fields", "field")
		if fields == "" {
			return nil, fmt.Errorf("indices.get_field_mapping requires fields parameter")
		}
		if idx != "" {
			reqPath = "/" + idx + "/_mapping/field/" + fields
		} else {
			reqPath = "/_mapping/field/" + fields
		}

	case "indices.get_settings":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_settings"
		} else {
			reqPath = "/_settings"
		}

	case "indices.put_settings":
		method = http.MethodPut
		idx := popString("index")
		if idx != "" {
			reqPath = "/" + idx + "/_settings"
		} else {
			reqPath = "/_settings"
		}

	case "indices.put_alias":
		method = http.MethodPut
		idx := popString("index")
		name := popString("name")
		if idx == "" || name == "" {
			return nil, fmt.Errorf("indices.put_alias requires index and name parameters")
		}
		reqPath = "/" + idx + "/_alias/" + name

	case "indices.get_alias":
		method = http.MethodGet
		idx := popString("index")
		name := popString("name")
		switch {
		case idx != "" && name != "":
			reqPath = "/" + idx + "/_alias/" + name
		case idx != "":
			reqPath = "/" + idx + "/_alias"
		case name != "":
			reqPath = "/_alias/" + name
		default:
			reqPath = "/_alias"
		}

	case "indices.delete_alias":
		method = http.MethodDelete
		idx := popString("index")
		name := popString("name")
		if idx == "" || name == "" {
			return nil, fmt.Errorf("indices.delete_alias requires index and name parameters")
		}
		reqPath = "/" + idx + "/_alias/" + name

	case "indices.exists_alias":
		method = http.MethodHead
		idx := popString("index")
		name := popString("name")
		switch {
		case idx != "" && name != "":
			reqPath = "/" + idx + "/_alias/" + name
		case idx != "":
			reqPath = "/" + idx + "/_alias"
		case name != "":
			reqPath = "/_alias/" + name
		default:
			reqPath = "/_alias"
		}

	case "indices.update_aliases":
		method = http.MethodPost
		reqPath = "/_aliases"

	case "indices.refresh":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_refresh"
		} else {
			reqPath = "/_refresh"
		}

	case "indices.flush":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_flush"
		} else {
			reqPath = "/_flush"
		}

	case "indices.forcemerge":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_forcemerge"
		} else {
			reqPath = "/_forcemerge"
		}

	case "indices.stats":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_stats"
		} else {
			reqPath = "/_stats"
		}

	case "indices.validate_query":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_validate/query"
		} else {
			reqPath = "/_validate/query"
		}

	case "indices.analyze":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_analyze"
		} else {
			reqPath = "/_analyze"
		}
		if !hasBody {
			bodyObj := make(map[string]any)
			for _, k := range []string{"text", "analyzer", "tokenizer", "filter", "char_filter", "field"} {
				if v, ok := remaining[k]; ok {
					bodyObj[k] = v
					delete(remaining, k)
				}
			}
			if len(bodyObj) > 0 {
				rawBody = bodyObj
				hasBody = true
			}
		}

	case "indices.rollover":
		method = http.MethodPost
		alias := popString("alias")
		newIdx := popString("new_index")
		if alias == "" {
			return nil, fmt.Errorf("indices.rollover requires alias parameter")
		}
		if newIdx != "" {
			reqPath = "/" + alias + "/_rollover/" + newIdx
		} else {
			reqPath = "/" + alias + "/_rollover"
		}

	case "indices.put_index_template":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.put_index_template requires name parameter")
		}
		reqPath = "/_index_template/" + name

	case "indices.get_index_template":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_index_template/" + name
		} else {
			reqPath = "/_index_template"
		}

	case "indices.delete_index_template":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.delete_index_template requires name parameter")
		}
		reqPath = "/_index_template/" + name

	case "indices.exists_index_template":
		method = http.MethodHead
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.exists_index_template requires name parameter")
		}
		reqPath = "/_index_template/" + name

	case "cluster.put_component_template":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("cluster.put_component_template requires name parameter")
		}
		reqPath = "/_component_template/" + name

	case "cluster.get_component_template":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_component_template/" + name
		} else {
			reqPath = "/_component_template"
		}

	case "cluster.delete_component_template":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("cluster.delete_component_template requires name parameter")
		}
		reqPath = "/_component_template/" + name

	case "cluster.exists_component_template":
		method = http.MethodHead
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("cluster.exists_component_template requires name parameter")
		}
		reqPath = "/_component_template/" + name

	case "index":
		idx := popString("index")
		id := popString("id")
		if idx == "" {
			return nil, fmt.Errorf("index requires index parameter")
		}
		if id != "" {
			method = http.MethodPut
			reqPath = "/" + idx + "/_doc/" + id
		} else {
			method = http.MethodPost
			reqPath = "/" + idx + "/_doc"
		}

	case "create":
		method = http.MethodPut
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("create requires index and id parameters")
		}
		reqPath = "/" + idx + "/_create/" + id

	case "get":
		method = http.MethodGet
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("get requires index and id parameters")
		}
		reqPath = "/" + idx + "/_doc/" + id

	case "get_source":
		method = http.MethodGet
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("get_source requires index and id parameters")
		}
		reqPath = "/" + idx + "/_source/" + id

	case "exists":
		method = http.MethodHead
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("exists requires index and id parameters")
		}
		reqPath = "/" + idx + "/_doc/" + id

	case "exists_source":
		method = http.MethodHead
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("exists_source requires index and id parameters")
		}
		reqPath = "/" + idx + "/_source/" + id

	case "delete":
		method = http.MethodDelete
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("delete requires index and id parameters")
		}
		reqPath = "/" + idx + "/_doc/" + id

	case "update":
		method = http.MethodPost
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("update requires index and id parameters")
		}
		reqPath = "/" + idx + "/_update/" + id

	case "mget":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_mget"
		} else {
			reqPath = "/_mget"
		}

	case "bulk":
		method = http.MethodPost
		isNDJSON = true
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_bulk"
		} else {
			reqPath = "/_bulk"
		}

	case "search":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_search"
		} else {
			reqPath = "/_search"
		}

	case "msearch":
		method = http.MethodPost
		isNDJSON = true
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_msearch"
		} else {
			reqPath = "/_msearch"
		}

	case "count":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_count"
		} else {
			reqPath = "/_count"
		}

	case "explain":
		method = http.MethodPost
		idx := popString("index")
		id := popString("id")
		if idx == "" || id == "" {
			return nil, fmt.Errorf("explain requires index and id parameters")
		}
		reqPath = "/" + idx + "/_explain/" + id

	case "field_caps":
		if hasBody {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_field_caps"
		} else {
			reqPath = "/_field_caps"
		}

	case "terms_enum":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("terms_enum requires index parameter")
		}
		reqPath = "/" + idx + "/_terms_enum"

	case "scroll":
		method = http.MethodPost
		reqPath = "/_search/scroll"
		if !hasBody {
			bodyObj := make(map[string]any)
			if sid := popString("scroll_id"); sid != "" {
				bodyObj["scroll_id"] = sid
			}
			if sc := popString("scroll"); sc != "" {
				bodyObj["scroll"] = sc
			}
			if len(bodyObj) > 0 {
				rawBody = bodyObj
				hasBody = true
			}
		}

	case "clear_scroll":
		method = http.MethodDelete
		reqPath = "/_search/scroll"
		if !hasBody {
			if sid := popString("scroll_id"); sid != "" {
				rawBody = map[string]any{"scroll_id": sid}
				hasBody = true
			}
		}

	case "open_point_in_time":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("open_point_in_time requires index parameter")
		}
		reqPath = "/" + idx + "/_pit"
		if _, ok := remaining["keep_alive"]; !ok {
			remaining["keep_alive"] = "1m"
		}

	case "close_point_in_time":
		method = http.MethodDelete
		reqPath = "/_pit"
		if !hasBody {
			if id := popString("id"); id != "" {
				rawBody = map[string]any{"id": id}
				hasBody = true
			}
		}

	case "update_by_query":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("update_by_query requires index parameter")
		}
		reqPath = "/" + idx + "/_update_by_query"

	case "delete_by_query":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("delete_by_query requires index parameter")
		}
		reqPath = "/" + idx + "/_delete_by_query"

	case "reindex":
		method = http.MethodPost
		reqPath = "/_reindex"

	case "ingest.put_pipeline":
		method = http.MethodPut
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("ingest.put_pipeline requires id parameter")
		}
		reqPath = "/_ingest/pipeline/" + id

	case "ingest.get_pipeline":
		method = http.MethodGet
		if id := popString("id"); id != "" {
			reqPath = "/_ingest/pipeline/" + id
		} else {
			reqPath = "/_ingest/pipeline"
		}

	case "ingest.delete_pipeline":
		method = http.MethodDelete
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("ingest.delete_pipeline requires id parameter")
		}
		reqPath = "/_ingest/pipeline/" + id

	case "ingest.simulate":
		method = http.MethodPost
		if id := popString("id"); id != "" {
			reqPath = "/_ingest/pipeline/" + id + "/_simulate"
		} else {
			reqPath = "/_ingest/pipeline/_simulate"
		}

	case "cat.indices":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/_cat/indices/" + idx
		} else {
			reqPath = "/_cat/indices"
		}

	case "cat.aliases":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_cat/aliases/" + name
		} else {
			reqPath = "/_cat/aliases"
		}

	case "cat.count":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/_cat/count/" + idx
		} else {
			reqPath = "/_cat/count"
		}

	case "cat.health":
		method = http.MethodGet
		reqPath = "/_cat/health"

	case "cat.nodes":
		method = http.MethodGet
		reqPath = "/_cat/nodes"

	case "cat.shards":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/_cat/shards/" + idx
		} else {
			reqPath = "/_cat/shards"
		}

	default:
		return nil, fmt.Errorf("unsupported rest-api-spec action %q", action)
	}

	query := url.Values{}
	for k, v := range remaining {
		if v == nil {
			continue
		}
		query.Set(k, joinParamValue(v))
	}

	var bodyBytes []byte
	if hasBody && rawBody != nil {
		var err error
		if isNDJSON {
			bodyBytes, err = serializeNDJSON(rawBody)
		} else {
			switch b := rawBody.(type) {
			case string:
				bodyBytes = []byte(b)
			default:
				bodyBytes, err = json.Marshal(b)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed serializing body for %s: %w", action, err)
		}
	}

	return &httpRequestSpec{
		method: method,
		path:   reqPath,
		query:  query,
		body:   bodyBytes,
	}, nil
}

func serializeNDJSON(rawBody any) ([]byte, error) {
	switch b := rawBody.(type) {
	case string:
		if !strings.HasSuffix(b, "\n") {
			b += "\n"
		}
		return []byte(b), nil
	case []any:
		var buf bytes.Buffer
		for _, item := range b {
			switch elem := item.(type) {
			case string:
				line := strings.TrimRight(elem, "\r\n")
				buf.WriteString(line)
				buf.WriteByte('\n')
			default:
				lineBytes, err := json.Marshal(elem)
				if err != nil {
					return nil, err
				}
				buf.Write(lineBytes)
				buf.WriteByte('\n')
			}
		}
		return buf.Bytes(), nil
	default:
		lineBytes, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		return append(lineBytes, '\n'), nil
	}
}

func joinParamValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", val)
	}
}

func paramString(m map[string]any, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return joinParamValue(v)
	}
	return ""
}

func (c *runnerContext) rawHTTP(method, reqPath string, query url.Values, body []byte, headers map[string]string) (int, string, error) {
	fullURL := c.baseURL + reqPath
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return 0, "", err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(respBytes), nil
}

func parseResponsePayload(bodyStr string) any {
	trimmed := strings.TrimSpace(bodyStr)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var parsed any
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&parsed); err == nil {
			return normalizeJSONNumbers(parsed)
		}
	}
	return bodyStr
}

func normalizeJSONNumbers(v any) any {
	switch val := v.(type) {
	case json.Number:
		if iv, err := val.Int64(); err == nil {
			return iv
		}
		if fv, err := val.Float64(); err == nil {
			return fv
		}
		return val.String()
	case map[string]any:
		for k, elem := range val {
			val[k] = normalizeJSONNumbers(elem)
		}
		return val
	case []any:
		for i, elem := range val {
			val[i] = normalizeJSONNumbers(elem)
		}
		return val
	default:
		return v
	}
}

func (c *runnerContext) expandStash(v any) any {
	switch val := v.(type) {
	case *OrderedMap:
		if val == nil {
			return nil
		}
		out := NewOrderedMap()
		for _, f := range val.Fields {
			expKey := c.expandStashString(f.Key)
			out.Set(expKey, c.expandStash(f.Value))
		}
		return out
	case OrderedMap:
		out := NewOrderedMap()
		for _, f := range val.Fields {
			expKey := c.expandStashString(f.Key)
			out.Set(expKey, c.expandStash(f.Value))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, elem := range val {
			expKey := c.expandStashString(k)
			out[expKey] = c.expandStash(elem)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = c.expandStash(elem)
		}
		return out
	case string:
		if strings.HasPrefix(val, "$") && !strings.ContainsAny(val[1:], " $./\\:") {
			stashKey := val[1:]
			if sv, ok := c.stash[stashKey]; ok {
				return sv
			}
		}
		return c.expandStashString(val)
	default:
		return v
	}
}

var reStashVar = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)

func (c *runnerContext) expandStashString(s string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	return reStashVar.ReplaceAllStringFunc(s, func(match string) string {
		key := match[1:]
		if sv, ok := c.stash[key]; ok {
			return fmt.Sprintf("%v", sv)
		}
		return match
	})
}

func (c *runnerContext) execSet(rawVal any) error {
	pairs, err := extractFieldPairs("set", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashString(p.Key)
		stashVar := fmt.Sprintf("%v", p.Value)
		stashVar = strings.TrimPrefix(stashVar, "$")
		val, found := c.lookupResponsePath(fieldPath)
		if !found {
			return fmt.Errorf("set: response path %q not found in %s", fieldPath, c.lastBodyRaw)
		}
		c.stash[stashVar] = val
	}
	return nil
}

func (c *runnerContext) execMatch(rawVal any) error {
	pairs, err := extractFieldPairs("match", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashString(p.Key)
		expected := ToNative(c.expandStash(p.Value))
		actual, found := c.lookupResponsePath(fieldPath)
		if !found {
			return fmt.Errorf("match: path %q not found in response: %s", fieldPath, c.lastBodyRaw)
		}
		if err := matchValues(fieldPath, actual, expected); err != nil {
			return err
		}
	}
	return nil
}

func matchValues(fieldPath string, actual, expected any) error {
	if expStr, ok := expected.(string); ok && strings.HasPrefix(expStr, "/") && strings.HasSuffix(expStr, "/") && len(expStr) >= 2 {
		pattern := expStr[1 : len(expStr)-1]
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("match %q: invalid regex %q: %w", fieldPath, expStr, err)
		}
		actStr := fmt.Sprintf("%v", actual)
		if !re.MatchString(actStr) {
			return fmt.Errorf("match %q: value %q did not match regex %s", fieldPath, actStr, expStr)
		}
		return nil
	}

	if valuesEqual(actual, expected) {
		return nil
	}
	actJSON, _ := json.Marshal(actual)
	expJSON, _ := json.Marshal(expected)
	return fmt.Errorf("match %q failed: got %s, expected %s", fieldPath, string(actJSON), string(expJSON))
}

func valuesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if af, aOk := toFloat64(a); aOk {
		if bf, bOk := toFloat64(b); bOk {
			return math.Abs(af-bf) <= 1e-6
		}
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, aElem := range av {
			bElem, exists := bv[k]
			if !exists || !valuesEqual(aElem, bElem) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valuesEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
}

func (c *runnerContext) execIsTrue(rawVal any) error {
	fieldPath := ""
	if rawVal != nil {
		fieldPath = c.expandStashString(fmt.Sprintf("%v", rawVal))
	}
	if fieldPath == "" {
		if c.lastMethod == http.MethodHead {
			if c.lastStatus == http.StatusOK {
				return nil
			}
			return fmt.Errorf("is_true '': expected HEAD HTTP 200, got %d", c.lastStatus)
		}
		if isTruthy(c.lastResponse) {
			return nil
		}
		return fmt.Errorf("is_true '': response is not truthy: %s", c.lastBodyRaw)
	}
	val, found := c.lookupResponsePath(fieldPath)
	if !found || !isTruthy(val) {
		return fmt.Errorf("is_true %q failed: found=%v, val=%v (response: %s)", fieldPath, found, val, c.lastBodyRaw)
	}
	return nil
}

func (c *runnerContext) execIsFalse(rawVal any) error {
	fieldPath := ""
	if rawVal != nil {
		fieldPath = c.expandStashString(fmt.Sprintf("%v", rawVal))
	}
	if fieldPath == "" {
		if c.lastMethod == http.MethodHead {
			if c.lastStatus == http.StatusNotFound {
				return nil
			}
			return fmt.Errorf("is_false '': expected HEAD HTTP 404, got %d", c.lastStatus)
		}
		if !isTruthy(c.lastResponse) {
			return nil
		}
		return fmt.Errorf("is_false '': response is truthy: %s", c.lastBodyRaw)
	}
	val, found := c.lookupResponsePath(fieldPath)
	if found && isTruthy(val) {
		return fmt.Errorf("is_false %q failed: got truthy value %v (response: %s)", fieldPath, val, c.lastBodyRaw)
	}
	return nil
}

func isTruthy(v any) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case int64:
		return val != 0
	case float64:
		return val != 0
	case string:
		return val != "" && val != "false" && val != "0"
	default:
		return true
	}
}

func (c *runnerContext) execLength(rawVal any) error {
	pairs, err := extractFieldPairs("length", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashString(p.Key)
		expFloat, ok := toFloat64(c.expandStash(p.Value))
		if !ok {
			return fmt.Errorf("length %q: expected integer length, got %v", fieldPath, p.Value)
		}
		expLen := int(expFloat)

		val, found := c.lookupResponsePath(fieldPath)
		if !found {
			return fmt.Errorf("length: path %q not found in response: %s", fieldPath, c.lastBodyRaw)
		}
		var actLen int
		switch tv := val.(type) {
		case string:
			actLen = len(tv)
		case []any:
			actLen = len(tv)
		case map[string]any:
			actLen = len(tv)
		default:
			return fmt.Errorf("length %q: unsupported value type %T (%v)", fieldPath, val, val)
		}
		if actLen != expLen {
			return fmt.Errorf("length %q failed: got %d, expected %d (value: %v)", fieldPath, actLen, expLen, val)
		}
	}
	return nil
}

func (c *runnerContext) execCompare(op string, rawVal any) error {
	pairs, err := extractFieldPairs(op, rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashString(p.Key)
		threshold, ok := toFloat64(c.expandStash(p.Value))
		if !ok {
			return fmt.Errorf("%s %q: threshold %v is not a number", op, fieldPath, p.Value)
		}
		val, found := c.lookupResponsePath(fieldPath)
		if !found {
			return fmt.Errorf("%s: path %q not found in response: %s", op, fieldPath, c.lastBodyRaw)
		}
		actual, ok := toFloat64(val)
		if !ok {
			return fmt.Errorf("%s %q: actual value %v (%T) is not a number", op, fieldPath, val, val)
		}
		var pass bool
		switch op {
		case "gt":
			pass = actual > threshold
		case "gte":
			pass = actual >= threshold
		case "lt":
			pass = actual < threshold
		case "lte":
			pass = actual <= threshold
		}
		if !pass {
			return fmt.Errorf("%s %q failed: actual %v is not %s %v", op, fieldPath, actual, op, threshold)
		}
	}
	return nil
}

func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	case json.Number:
		f, err := val.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func extractFieldPairs(op string, raw any) ([]YAMLField, error) {
	switch val := raw.(type) {
	case *OrderedMap:
		if val == nil {
			return nil, fmt.Errorf("%s requires a non-empty mapping", op)
		}
		return val.Fields, nil
	case OrderedMap:
		return val.Fields, nil
	case map[string]any:
		var fields []YAMLField
		for k, v := range val {
			fields = append(fields, YAMLField{Key: k, Value: v})
		}
		return fields, nil
	default:
		return nil, fmt.Errorf("%s requires a mapping, got %T", op, raw)
	}
}

func (c *runnerContext) lookupResponsePath(rawPath string) (any, bool) {
	if rawPath == "" || rawPath == "$body" {
		return c.lastResponse, c.lastResponse != nil
	}
	segments := splitEscapedPath(rawPath)
	cur := c.lastResponse
	for _, seg := range segments {
		if cur == nil {
			return nil, false
		}
		switch node := cur.(type) {
		case map[string]any:
			next, exists := node[seg]
			if !exists {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func splitEscapedPath(rawPath string) []string {
	var segments []string
	var sb strings.Builder
	for i := 0; i < len(rawPath); i++ {
		if rawPath[i] == '\\' && i+1 < len(rawPath) && rawPath[i+1] == '.' {
			sb.WriteByte('.')
			i++
			continue
		}
		if rawPath[i] == '.' {
			segments = append(segments, sb.String())
			sb.Reset()
			continue
		}
		sb.WriteByte(rawPath[i])
	}
	segments = append(segments, sb.String())
	return segments
}
