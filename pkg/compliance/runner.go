package compliance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"unicode/utf8"
)

const proxyTargetVersion = "7.10.2"

var supportedRunnerFeatures = map[string]bool{
	"headers":                true,
	"warnings":               true,
	"warning_headers":        true,
	"warnings_regex":         true,
	"allowed_warnings":       true,
	"allowed_warnings_regex": true,
	"contains":               true,
	"transform_and_set":      true,
	"arbitrary_key":          true,
	"regex":                  true,
	"gt":                     true,
	"gte":                    true,
	"lt":                     true,
	"lte":                    true,
	"catch_param":            true,
	"stash_in_key":           true,
	"stash_in_path":          true,
	"node_selector":          true,
	"default_shards":         true,
	"painless":               true,
	"mustache":               true,
	"clean_text":             true,
}

type errSkipSection struct {
	reason string
}

func (e *errSkipSection) Error() string {
	return "skip: " + e.reason
}

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
			probeCtx := newRunnerContext(client, strings.TrimRight(baseURL, "/"))
			for _, step := range specDoc.Setup {
				if step.Op == "skip" {
					fileRep.StepsRun++
					report.StepsRun++
					if err := probeCtx.execStep(step, false); err != nil {
						var skipErr *errSkipSection
						if errors.As(err, &skipErr) {
							t.Skipf("setup skipped: %s", skipErr.reason)
						}
						t.Fatalf("[setup skip] %v", err)
					}
				}
			}

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
							var skipErr *errSkipSection
							if errors.As(err, &skipErr) {
								t.Skipf("setup skipped: %s", skipErr.reason)
							}
							t.Fatalf("[setup step %d (%s)] %v", i+1, step.Op, err)
						}
					}

					var testErr error
					var skipErr *errSkipSection
					for i, step := range sec.Steps {
						fileRep.StepsRun++
						report.StepsRun++
						if err := ctx.execStep(step, false); err != nil {
							if errors.As(err, &skipErr) {
								break
							}
							testErr = fmt.Errorf("[step %d (%s)] %w", i+1, step.Op, err)
							break
						}
					}

					for i, step := range specDoc.Teardown {
						fileRep.StepsRun++
						report.StepsRun++
						if err := ctx.execStep(step, true); err != nil && testErr == nil && skipErr == nil {
							var tdSkip *errSkipSection
							if !errors.As(err, &tdSkip) {
								testErr = fmt.Errorf("[teardown step %d (%s)] %w", i+1, step.Op, err)
							}
						}
					}

					if skipErr != nil {
						t.Skipf("skipped: %s", skipErr.reason)
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
	client                     *http.Client
	baseURL                    string
	stash                      map[string]any
	lastStatus                 int
	lastMethod                 string
	lastBodyRaw                string
	lastResponse               any
	lastHeaders                map[string]any
	lastWarnings               []string
	createdIndices             map[string]bool
	createdDataStreams         map[string]bool
	createdTemplates           map[string]bool
	createdLegacyTmpls         map[string]bool
	createdCompTmpls           map[string]bool
	createdPipelines           map[string]bool
	createdILMPolicies         map[string]bool
	createdSLMPolicies         map[string]bool
	createdEnrichPols          map[string]bool
	createdWatches             map[string]bool
	createdTransforms          map[string]bool
	createdAutoscalingPolicies map[string]bool
	createdSynonymSets         map[string]bool
	createdQueryRulesets       map[string]bool
	createdRollupJobs          map[string]bool
	createdAutoFollowPatterns  map[string]bool
	createdLogstashPipelines   map[string]bool
	createdSecurityUsers       map[string]bool
	createdSecurityRoles       map[string]bool
	createdSecurityPrivileges  map[string]map[string]bool
	createdServiceTokens       map[string]bool
	createdShutdownNodes       map[string]bool
	createdInferenceEndpoints  map[string]bool
	createdConnectors          map[string]bool
	createdConnectorSyncJobs   map[string]bool
	createdSearchApps          map[string]bool
	createdAnalyticsColls      map[string]bool
	createdAsyncSearches       map[string]bool
	createdVotingExclusions    bool
	createdScripts             map[string]struct{}
	createdRepositories        map[string]struct{}
	createdAliases             map[string]string // alias -> index
}

func newRunnerContext(client *http.Client, baseURL string) *runnerContext {
	return &runnerContext{
		client:                     client,
		baseURL:                    baseURL,
		stash:                      make(map[string]any),
		lastHeaders:                make(map[string]any),
		createdIndices:             make(map[string]bool),
		createdDataStreams:         make(map[string]bool),
		createdTemplates:           make(map[string]bool),
		createdLegacyTmpls:         make(map[string]bool),
		createdCompTmpls:           make(map[string]bool),
		createdPipelines:           make(map[string]bool),
		createdILMPolicies:         make(map[string]bool),
		createdSLMPolicies:         make(map[string]bool),
		createdEnrichPols:          make(map[string]bool),
		createdWatches:             make(map[string]bool),
		createdTransforms:          make(map[string]bool),
		createdAutoscalingPolicies: make(map[string]bool),
		createdSynonymSets:         make(map[string]bool),
		createdQueryRulesets:       make(map[string]bool),
		createdRollupJobs:          make(map[string]bool),
		createdAutoFollowPatterns:  make(map[string]bool),
		createdLogstashPipelines:   make(map[string]bool),
		createdSecurityUsers:       make(map[string]bool),
		createdSecurityRoles:       make(map[string]bool),
		createdSecurityPrivileges:  make(map[string]map[string]bool),
		createdServiceTokens:       make(map[string]bool),
		createdShutdownNodes:       make(map[string]bool),
		createdInferenceEndpoints:  make(map[string]bool),
		createdConnectors:          make(map[string]bool),
		createdConnectorSyncJobs:   make(map[string]bool),
		createdSearchApps:          make(map[string]bool),
		createdAnalyticsColls:      make(map[string]bool),
		createdAsyncSearches:       make(map[string]bool),
		createdScripts:             make(map[string]struct{}),
		createdRepositories:        make(map[string]struct{}),
		createdAliases:             make(map[string]string),
	}
}

func (c *runnerContext) cleanupAll() {
	for alias, idx := range c.createdAliases {
		if idx != "" && alias != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/"+url.PathEscape(idx)+"/_alias/"+url.PathEscape(alias), nil, nil, nil)
		}
		if alias != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_all/_alias/"+url.PathEscape(alias), nil, nil, nil)
		}
	}
	for ds := range c.createdDataStreams {
		if ds != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_data_stream/"+url.PathEscape(ds), nil, nil, nil)
		}
	}
	unblockBody := []byte(`{"index.blocks.read_only":null,"index.blocks.read_only_allow_delete":null,"index.blocks.metadata":null,"index.blocks.write":null,"index.blocks.read":null}`)
	for idx := range c.createdIndices {
		if idx != "" && !strings.HasPrefix(idx, "_") {
			_, _, _ = c.rawHTTP(http.MethodPut, "/"+url.PathEscape(idx)+"/_settings", nil, unblockBody, nil)
			_, _, _ = c.rawHTTP(http.MethodDelete, "/"+url.PathEscape(idx), nil, nil, nil)
		}
	}
	for tmpl := range c.createdTemplates {
		if tmpl != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_index_template/"+url.PathEscape(tmpl), nil, nil, nil)
		}
	}
	for tmpl := range c.createdLegacyTmpls {
		if tmpl != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_template/"+url.PathEscape(tmpl), nil, nil, nil)
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
	for pol := range c.createdILMPolicies {
		if pol != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_ilm/policy/"+url.PathEscape(pol), nil, nil, nil)
		}
	}
	for pol := range c.createdSLMPolicies {
		if pol != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_slm/policy/"+url.PathEscape(pol), nil, nil, nil)
		}
	}
	for pol := range c.createdEnrichPols {
		if pol != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_enrich/policy/"+url.PathEscape(pol), nil, nil, nil)
		}
	}
	for watchID := range c.createdWatches {
		if watchID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_watcher/watch/"+url.PathEscape(watchID), nil, nil, nil)
		}
	}
	for transformID := range c.createdTransforms {
		if transformID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_transform/"+url.PathEscape(transformID), url.Values{"force": []string{"true"}}, nil, nil)
		}
	}
	for polName := range c.createdAutoscalingPolicies {
		if polName != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_autoscaling/policy/"+url.PathEscape(polName), nil, nil, nil)
		}
	}
	for synID := range c.createdSynonymSets {
		if synID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_synonyms/"+url.PathEscape(synID), nil, nil, nil)
		}
	}
	for rulesetID := range c.createdQueryRulesets {
		if rulesetID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_query_rules/"+url.PathEscape(rulesetID), nil, nil, nil)
		}
	}
	for jobID := range c.createdRollupJobs {
		if jobID != "" {
			_, _, _ = c.rawHTTP(http.MethodPost, "/_rollup/job/"+url.PathEscape(jobID)+"/_stop", nil, nil, nil)
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_rollup/job/"+url.PathEscape(jobID), nil, nil, nil)
		}
	}
	for patName := range c.createdAutoFollowPatterns {
		if patName != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_ccr/auto_follow/"+url.PathEscape(patName), nil, nil, nil)
		}
	}
	for pipeID := range c.createdLogstashPipelines {
		if pipeID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_logstash/pipeline/"+url.PathEscape(pipeID), nil, nil, nil)
		}
	}
	for username := range c.createdSecurityUsers {
		if username != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_security/user/"+url.PathEscape(username), nil, nil, nil)
		}
	}
	for roleName := range c.createdSecurityRoles {
		if roleName != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_security/role/"+url.PathEscape(roleName), nil, nil, nil)
		}
	}
	for app, privs := range c.createdSecurityPrivileges {
		for privName := range privs {
			if app != "" && privName != "" {
				_, _, _ = c.rawHTTP(http.MethodDelete, "/_security/privilege/"+url.PathEscape(app)+"/"+url.PathEscape(privName), nil, nil, nil)
			}
		}
	}
	for tokPath := range c.createdServiceTokens {
		if tokPath != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_security/service/"+tokPath, nil, nil, nil)
		}
	}
	for nodeID := range c.createdShutdownNodes {
		if nodeID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_nodes/"+url.PathEscape(nodeID)+"/shutdown", nil, nil, nil)
		}
	}
	for infID := range c.createdInferenceEndpoints {
		if infID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_inference/"+url.PathEscape(infID), nil, nil, nil)
		}
	}
	for jobID := range c.createdConnectorSyncJobs {
		if jobID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_connector/_sync_job/"+url.PathEscape(jobID), nil, nil, nil)
		}
	}
	for connID := range c.createdConnectors {
		if connID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_connector/"+url.PathEscape(connID), nil, nil, nil)
		}
	}
	for appName := range c.createdSearchApps {
		if appName != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_application/search_application/"+url.PathEscape(appName), nil, nil, nil)
		}
	}
	for collName := range c.createdAnalyticsColls {
		if collName != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_application/analytics/"+url.PathEscape(collName), nil, nil, nil)
		}
	}
	for asyncID := range c.createdAsyncSearches {
		if asyncID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_async_search/"+url.PathEscape(asyncID), nil, nil, nil)
		}
	}
	if c.createdVotingExclusions {
		_, _, _ = c.rawHTTP(http.MethodDelete, "/_cluster/voting_config_exclusions", nil, nil, nil)
	}
	for scriptID := range c.createdScripts {
		if scriptID != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_scripts/"+url.PathEscape(scriptID), nil, nil, nil)
		}
	}
	for repo := range c.createdRepositories {
		if repo != "" {
			_, _, _ = c.rawHTTP(http.MethodDelete, "/_snapshot/"+url.PathEscape(repo), nil, nil, nil)
		}
	}
}

func (c *runnerContext) execStep(step SpecStep, isTeardown bool) error {
	switch step.Op {
	case "skip":
		return c.execSkip(step.Value)
	case "do":
		return c.execDo(step.Value, isTeardown)
	case "set":
		return c.execSet(step.Value)
	case "transform_and_set":
		return c.execTransformAndSet(step.Value)
	case "match":
		return c.execMatch(step.Value)
	case "contains":
		return c.execContains(step.Value)
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
	var expectedWarnings []string
	var expectedWarningsRegex []string
	var actionName string
	var actionParams any

	for _, f := range om.Fields {
		switch f.Key {
		case "catch":
			catchSpec = fmt.Sprintf("%v", c.expandStash(f.Value))
		case "headers":
			if headers == nil {
				headers = make(map[string]string)
			}
			if hm, ok := ToNative(c.expandStash(f.Value)).(map[string]any); ok {
				for hk, hv := range hm {
					headers[hk] = fmt.Sprintf("%v", hv)
				}
			}
		case "ignore":
			ignoreStatuses = parseIgnoreStatuses(c.expandStash(f.Value))
		case "warnings", "warning_headers":
			expectedWarnings = append(expectedWarnings, extractStringSlice(c.expandStash(f.Value))...)
		case "warnings_regex":
			expectedWarningsRegex = append(expectedWarningsRegex, extractStringSlice(c.expandStash(f.Value))...)
		case "allowed_warnings", "allowed_warnings_regex", "node_selector":
			// Allowed warning and node selector metadata directives from upstream rest-api-spec
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
	if rawHeaders, ok := paramMap["headers"]; ok {
		switch hm := ToNative(rawHeaders).(type) {
		case map[string]any:
			if headers == nil {
				headers = make(map[string]string)
			}
			for hk, hv := range hm {
				headers[hk] = fmt.Sprintf("%v", hv)
			}
			delete(paramMap, "headers")
		case map[string]string:
			if headers == nil {
				headers = make(map[string]string)
			}
			for hk, hv := range hm {
				headers[hk] = hv
			}
			delete(paramMap, "headers")
		}
	}
	delete(paramMap, "node_selector")

	reqSpec, err := c.buildActionRequest(actionName, paramMap)
	if err != nil {
		if catchSpec == "param" || catchSpec == "bad_request" {
			return nil
		}
		if len(catchSpec) >= 2 && strings.HasPrefix(catchSpec, "/") && strings.HasSuffix(catchSpec, "/") {
			if re, compErr := regexp.Compile(catchSpec[1 : len(catchSpec)-1]); compErr == nil && re.MatchString(err.Error()) {
				return nil
			}
		}
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

	for _, expWarn := range expectedWarnings {
		matched := false
		for _, actualWarn := range c.lastWarnings {
			if actualWarn == expWarn || strings.Contains(actualWarn, expWarn) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("action %s expected warning %q, got %v", actionName, expWarn, c.lastWarnings)
		}
	}
	for _, expRegex := range expectedWarningsRegex {
		pattern := expRegex
		if len(pattern) >= 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
			pattern = pattern[1 : len(pattern)-1]
		}
		re, compErr := regexp.Compile(pattern)
		if compErr != nil {
			return fmt.Errorf("action %s invalid warnings_regex %q: %w", actionName, expRegex, compErr)
		}
		matched := false
		for _, actualWarn := range c.lastWarnings {
			if re.MatchString(actualWarn) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("action %s expected warning matching %q, got %v", actionName, expRegex, c.lastWarnings)
		}
	}

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

func extractStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if item != nil {
				out = append(out, fmt.Sprintf("%v", item))
			}
		}
		return out
	default:
		return []string{fmt.Sprintf("%v", val)}
	}
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
	case "unavailable":
		if status != http.StatusServiceUnavailable {
			return fmt.Errorf("action %s expected catch: unavailable (HTTP 503), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	case "gateway_timeout":
		if status != http.StatusGatewayTimeout {
			return fmt.Errorf("action %s expected catch: gateway_timeout (HTTP 504), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	case "method_not_allowed":
		if status != http.StatusMethodNotAllowed {
			return fmt.Errorf("action %s expected catch: method_not_allowed (HTTP 405), got HTTP %d: %s", actionName, status, bodyStr)
		}
		return nil
	}

	if code, err := strconv.Atoi(catchSpec); err == nil && code >= 100 && code < 600 {
		if status != code {
			return fmt.Errorf("action %s expected catch: %d, got HTTP %d: %s", actionName, code, status, bodyStr)
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
		if !re.MatchString(errText) && !re.MatchString(bodyStr) && !re.MatchString(strconv.Itoa(status)) {
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
	case "indices.create", "index", "create", "indices.put_mapping", "indices.put_settings", "indices.add_block":
		if idx != "" {
			for _, part := range strings.Split(idx, ",") {
				p := strings.TrimSpace(part)
				if p != "" && !strings.ContainsAny(p, "*?") {
					c.createdIndices[p] = true
				}
			}
		}
		if action == "indices.create" {
			if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
				if aliasesMap, ok := bodyMap["aliases"].(map[string]any); ok {
					for aliasName := range aliasesMap {
						if aliasName != "" {
							c.createdAliases[aliasName] = idx
						}
					}
				}
			}
		}
	case "indices.update_aliases":
		if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
			if actions, ok := bodyMap["actions"].([]any); ok {
				for _, actItem := range actions {
					actMap, ok := actItem.(map[string]any)
					if !ok {
						continue
					}
					addMap, ok := actMap["add"].(map[string]any)
					if !ok {
						continue
					}
					targetIdx := paramString(addMap, "index")
					if targetIdx == "" {
						targetIdx = paramString(addMap, "indices")
					}
					if al := paramString(addMap, "alias"); al != "" {
						for _, part := range strings.Split(al, ",") {
							if p := strings.TrimSpace(part); p != "" {
								c.createdAliases[p] = targetIdx
							}
						}
					}
					for _, al := range extractStringSlice(addMap["aliases"]) {
						for _, part := range strings.Split(al, ",") {
							if p := strings.TrimSpace(part); p != "" {
								c.createdAliases[p] = targetIdx
							}
						}
					}
				}
			}
		}
	case "bulk":
		if idx != "" {
			c.createdIndices[idx] = true
		}
		trackBulkMetaMap := func(m map[string]any) {
			for _, opName := range []string{"index", "create", "update", "delete"} {
				if meta, ok := ToNative(m[opName]).(map[string]any); ok {
					if bIdx := paramString(meta, "_index"); bIdx != "" {
						c.createdIndices[bIdx] = true
					}
				}
			}
		}
		trackBulkNDJSONString := func(s string) {
			for _, line := range strings.Split(s, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "{") {
					continue
				}
				var m map[string]any
				if err := json.Unmarshal([]byte(line), &m); err == nil {
					trackBulkMetaMap(m)
				}
			}
		}
		switch bodyVal := ToNative(params["body"]).(type) {
		case []any:
			for _, item := range bodyVal {
				switch elem := ToNative(item).(type) {
				case map[string]any:
					trackBulkMetaMap(elem)
				case string:
					trackBulkNDJSONString(elem)
				}
			}
		case string:
			trackBulkNDJSONString(bodyVal)
		}
	case "reindex":
		if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
			if dest, ok := ToNative(bodyMap["dest"]).(map[string]any); ok {
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
	case "indices.clone", "indices.shrink", "indices.split":
		if target := paramString(params, "target"); target != "" {
			c.createdIndices[target] = true
		}
		if idx != "" {
			c.createdIndices[idx] = true
		}
	case "indices.create_data_stream", "data_stream.create_data_stream", "indices.migrate_to_data_stream", "indices.promote_data_stream", "data_stream.promote_data_stream":
		if name := paramString(params, "name"); name != "" {
			c.createdDataStreams[name] = true
		}
	case "indices.modify_data_stream", "data_stream.modify_data_stream":
		if name := paramString(params, "name"); name != "" {
			c.createdDataStreams[name] = true
		}
		if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
			if actions, ok := bodyMap["actions"].([]any); ok {
				for _, actItem := range actions {
					actMap, ok := ToNative(actItem).(map[string]any)
					if !ok {
						continue
					}
					for _, opKey := range []string{"add_backing_index", "remove_backing_index"} {
						if subMap, ok := ToNative(actMap[opKey]).(map[string]any); ok {
							if ds := paramString(subMap, "data_stream"); ds != "" {
								c.createdDataStreams[ds] = true
							}
							if bIdx := paramString(subMap, "index"); bIdx != "" {
								c.createdIndices[bIdx] = true
							}
						}
					}
				}
			}
		}
	case "indices.put_alias":
		name := paramString(params, "name")
		if name == "" {
			name = paramString(params, "alias")
		}
		if idx != "" && name != "" {
			c.createdIndices[idx] = true
			c.createdAliases[name] = idx
		}
	case "indices.put_index_template":
		if name := paramString(params, "name"); name != "" {
			c.createdTemplates[name] = true
		}
	case "indices.put_template":
		if name := paramString(params, "name"); name != "" {
			c.createdLegacyTmpls[name] = true
		}
	case "cluster.put_component_template":
		if name := paramString(params, "name"); name != "" {
			c.createdCompTmpls[name] = true
		}
	case "ingest.put_pipeline":
		if id := paramString(params, "id"); id != "" {
			c.createdPipelines[id] = true
		} else if name := paramString(params, "name"); name != "" {
			c.createdPipelines[name] = true
		}
	case "ilm.put_lifecycle":
		if pol := paramString(params, "policy"); pol != "" {
			c.createdILMPolicies[pol] = true
		} else if polID := paramString(params, "policy_id"); polID != "" {
			c.createdILMPolicies[polID] = true
		} else if name := paramString(params, "name"); name != "" {
			c.createdILMPolicies[name] = true
		}
	case "slm.put_lifecycle":
		if pol := paramString(params, "policy_id"); pol != "" {
			c.createdSLMPolicies[pol] = true
		} else if pol := paramString(params, "policy"); pol != "" {
			c.createdSLMPolicies[pol] = true
		} else if pol := paramString(params, "id"); pol != "" {
			c.createdSLMPolicies[pol] = true
		} else if pol := paramString(params, "name"); pol != "" {
			c.createdSLMPolicies[pol] = true
		}
	case "enrich.put_policy":
		if name := paramString(params, "name"); name != "" {
			c.createdEnrichPols[name] = true
		}
	case "watcher.put_watch":
		if id := paramString(params, "id"); id != "" {
			c.createdWatches[id] = true
		} else if id := paramString(params, "watch_id"); id != "" {
			c.createdWatches[id] = true
		}
	case "transform.put_transform":
		if id := paramString(params, "transform_id"); id != "" {
			c.createdTransforms[id] = true
		} else if id := paramString(params, "id"); id != "" {
			c.createdTransforms[id] = true
		}
	case "autoscaling.put_autoscaling_policy":
		if name := paramString(params, "name"); name != "" {
			c.createdAutoscalingPolicies[name] = true
		}
	case "synonyms.put_synonym", "synonyms.put_synonym_rule":
		if id := firstNonEmptyParam(params, "set_id", "synonyms_set", "id"); id != "" {
			c.createdSynonymSets[id] = true
		}
	case "query_rules.put_ruleset", "query_rules.put_rule":
		if id := firstNonEmptyParam(params, "ruleset_id", "id"); id != "" {
			c.createdQueryRulesets[id] = true
		}
	case "rollup.put_job":
		if id := firstNonEmptyParam(params, "id", "job_id"); id != "" {
			c.createdRollupJobs[id] = true
		}
		if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
			if rIdx := paramString(bodyMap, "rollup_index"); rIdx != "" {
				c.createdIndices[rIdx] = true
			}
		}
	case "ccr.put_auto_follow_pattern":
		if name := paramString(params, "name"); name != "" {
			c.createdAutoFollowPatterns[name] = true
		}
	case "ccr.follow":
		if idx != "" {
			c.createdIndices[idx] = true
		}
	case "searchable_snapshots.mount":
		if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
			if ren := paramString(bodyMap, "renamed_index"); ren != "" {
				c.createdIndices[ren] = true
			} else if bIdx := paramString(bodyMap, "index"); bIdx != "" {
				c.createdIndices[bIdx] = true
			}
		}
	case "logstash.put_pipeline":
		if id := paramString(params, "id"); id != "" {
			c.createdLogstashPipelines[id] = true
		}
	case "security.put_user":
		if u := firstNonEmptyParam(params, "username", "name", "id"); u != "" {
			c.createdSecurityUsers[u] = true
		}
	case "security.put_role":
		if r := firstNonEmptyParam(params, "name", "id"); r != "" {
			c.createdSecurityRoles[r] = true
		}
	case "security.put_privileges":
		if bodyMap, ok := ToNative(params["body"]).(map[string]any); ok {
			for app, privsRaw := range bodyMap {
				privsMap, ok := ToNative(privsRaw).(map[string]any)
				if !ok {
					continue
				}
				if c.createdSecurityPrivileges[app] == nil {
					c.createdSecurityPrivileges[app] = make(map[string]bool)
				}
				for privName := range privsMap {
					c.createdSecurityPrivileges[app][privName] = true
				}
			}
		}
	case "security.create_service_token":
		ns := paramString(params, "namespace")
		svc := paramString(params, "service")
		tok := firstNonEmptyParam(params, "token_name", "name")
		if tok == "" {
			if rm, ok := resp.(map[string]any); ok {
				if tv, ok := rm["token"].(map[string]any); ok {
					tok = paramString(tv, "name")
				}
			}
		}
		if ns != "" && svc != "" && tok != "" {
			c.createdServiceTokens[url.PathEscape(ns)+"/"+url.PathEscape(svc)+"/credential/token/"+url.PathEscape(tok)] = true
		}
	case "shutdown.put_node":
		if nodeID := paramString(params, "node_id"); nodeID != "" {
			c.createdShutdownNodes[nodeID] = true
		}
	case "inference.put", "inference.put_model":
		if infID := firstNonEmptyParam(params, "inference_id", "id"); infID != "" {
			c.createdInferenceEndpoints[infID] = true
		}
	case "connector.put":
		if connID := firstNonEmptyParam(params, "connector_id", "id"); connID != "" {
			c.createdConnectors[connID] = true
		}
	case "connector.post":
		if rm, ok := resp.(map[string]any); ok {
			if connID := paramString(rm, "connector_id"); connID != "" {
				c.createdConnectors[connID] = true
			}
		}
	case "connector.sync_job_post":
		if rm, ok := resp.(map[string]any); ok {
			if jobID := firstNonEmptyParam(rm, "id", "connector_sync_job_id"); jobID != "" {
				c.createdConnectorSyncJobs[jobID] = true
			}
		}
	case "search_application.put":
		if name := firstNonEmptyParam(params, "name", "id"); name != "" {
			c.createdSearchApps[name] = true
		}
	case "behavioral_analytics.put_collection":
		if coll := firstNonEmptyParam(params, "collection_name", "name"); coll != "" {
			c.createdAnalyticsColls[coll] = true
		}
	case "async_search.submit":
		if rm, ok := resp.(map[string]any); ok {
			if id := paramString(rm, "id"); id != "" {
				c.createdAsyncSearches[id] = true
			}
		}
	case "cluster.post_voting_config_exclusions":
		c.createdVotingExclusions = true
	case "put_script":
		if id := paramString(params, "id"); id != "" {
			c.createdScripts[id] = struct{}{}
		}
	case "snapshot.create_repository", "snapshot.put_repository":
		if repo := paramString(params, "repository"); repo != "" {
			c.createdRepositories[repo] = struct{}{}
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
		metric := popString("metric")
		idx := popString("index")
		switch {
		case metric != "" && idx != "":
			reqPath = "/_cluster/state/" + metric + "/" + idx
		case metric != "":
			reqPath = "/_cluster/state/" + metric
		case idx != "":
			reqPath = "/_cluster/state/_all/" + idx
		default:
			reqPath = "/_cluster/state"
		}

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
		nodeID := popString("node_id")
		metric := popString("metric")
		switch {
		case nodeID != "" && metric != "":
			reqPath = "/_nodes/" + nodeID + "/" + metric
		case nodeID != "":
			reqPath = "/_nodes/" + nodeID
		case metric != "":
			reqPath = "/_nodes/_all/" + metric
		default:
			reqPath = "/_nodes"
		}

	case "nodes.stats":
		method = http.MethodGet
		nodeID := popString("node_id")
		metric := popString("metric")
		switch {
		case nodeID != "" && metric != "":
			reqPath = "/_nodes/" + nodeID + "/stats/" + metric
		case nodeID != "":
			reqPath = "/_nodes/" + nodeID + "/stats"
		case metric != "":
			reqPath = "/_nodes/stats/" + metric
		default:
			reqPath = "/_nodes/stats"
		}

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
		feature := popString("feature")
		if idx == "" {
			return nil, fmt.Errorf("indices.get requires index parameter")
		}
		if feature != "" {
			reqPath = "/" + idx + "/" + feature
		} else {
			reqPath = "/" + idx
		}

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
		idx := popString("index")
		name := popString("name")
		if name == "" {
			name = paramString(params, "prefix")
		}
		switch {
		case idx != "" && name != "":
			reqPath = "/" + idx + "/_settings/" + name
		case idx != "":
			reqPath = "/" + idx + "/_settings"
		case name != "":
			reqPath = "/_all/_settings/" + name
		default:
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
		name := popString("name", "alias")
		if idx == "" || name == "" {
			return nil, fmt.Errorf("indices.put_alias requires index and name parameters")
		}
		reqPath = "/" + idx + "/_alias/" + name

	case "indices.get_alias":
		method = http.MethodGet
		idx := popString("index")
		name := popString("name", "alias")
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
		name := popString("name", "alias")
		if idx == "" || name == "" {
			return nil, fmt.Errorf("indices.delete_alias requires index and name parameters")
		}
		reqPath = "/" + idx + "/_alias/" + name

	case "indices.exists_alias":
		method = http.MethodHead
		idx := popString("index")
		name := popString("name", "alias")
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
		idx := popString("index")
		metric := popString("metric")
		switch {
		case idx != "" && metric != "":
			reqPath = "/" + idx + "/_stats/" + metric
		case idx != "":
			reqPath = "/" + idx + "/_stats"
		case metric != "":
			reqPath = "/_stats/" + metric
		default:
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
		if name := popString("name", "alias"); name != "" {
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

	case "ping":
		method = http.MethodHead
		reqPath = "/"

	case "indices.resolve_index":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_resolve/index/" + name
		} else {
			reqPath = "/_resolve/index"
		}

	case "indices.create_data_stream", "data_stream.create_data_stream":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("%s requires name parameter", action)
		}
		reqPath = "/_data_stream/" + name

	case "indices.get_data_stream", "data_stream.get_data_stream":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_data_stream/" + name
		} else {
			reqPath = "/_data_stream"
		}

	case "indices.delete_data_stream", "data_stream.delete_data_stream":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("%s requires name parameter", action)
		}
		reqPath = "/_data_stream/" + name

	case "indices.data_stream_stats", "indices.data_streams_stats", "data_stream.data_stream_stats":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_data_stream/" + name + "/_stats"
		} else {
			reqPath = "/_data_stream/_stats"
		}

	case "indices.migrate_to_data_stream", "data_stream.migrate_to_data_stream":
		method = http.MethodPost
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("%s requires name parameter", action)
		}
		reqPath = "/_data_stream/_migrate/" + name

	case "indices.modify_data_stream", "data_stream.modify_data_stream":
		method = http.MethodPost
		reqPath = "/_data_stream/_modify"

	case "indices.promote_data_stream", "data_stream.promote_data_stream":
		method = http.MethodPost
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("%s requires name parameter", action)
		}
		reqPath = "/_data_stream/_promote/" + name

	case "indices.put_template":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.put_template requires name parameter")
		}
		reqPath = "/_template/" + name

	case "indices.get_template":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_template/" + name
		} else {
			reqPath = "/_template"
		}

	case "indices.delete_template":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.delete_template requires name parameter")
		}
		reqPath = "/_template/" + name

	case "indices.exists_template":
		method = http.MethodHead
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.exists_template requires name parameter")
		}
		reqPath = "/_template/" + name

	case "indices.clone":
		method = http.MethodPost
		idx := popString("index")
		target := popString("target")
		if idx == "" || target == "" {
			return nil, fmt.Errorf("indices.clone requires index and target parameters")
		}
		reqPath = "/" + idx + "/_clone/" + target

	case "indices.shrink":
		method = http.MethodPost
		idx := popString("index")
		target := popString("target")
		if idx == "" || target == "" {
			return nil, fmt.Errorf("indices.shrink requires index and target parameters")
		}
		reqPath = "/" + idx + "/_shrink/" + target

	case "indices.split":
		method = http.MethodPost
		idx := popString("index")
		target := popString("target")
		if idx == "" || target == "" {
			return nil, fmt.Errorf("indices.split requires index and target parameters")
		}
		reqPath = "/" + idx + "/_split/" + target

	case "search_shards":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_search_shards"
		} else {
			reqPath = "/_search_shards"
		}

	case "ilm.put_lifecycle":
		method = http.MethodPut
		pol := popString("policy", "policy_id", "name")
		if pol == "" {
			return nil, fmt.Errorf("ilm.put_lifecycle requires policy parameter")
		}
		reqPath = "/_ilm/policy/" + pol

	case "ilm.get_lifecycle":
		method = http.MethodGet
		if pol := popString("policy", "policy_id", "name"); pol != "" {
			reqPath = "/_ilm/policy/" + pol
		} else {
			reqPath = "/_ilm/policy"
		}

	case "ilm.delete_lifecycle":
		method = http.MethodDelete
		pol := popString("policy", "policy_id", "name")
		if pol == "" {
			return nil, fmt.Errorf("ilm.delete_lifecycle requires policy parameter")
		}
		reqPath = "/_ilm/policy/" + pol

	case "ilm.explain_lifecycle":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_ilm/explain"
		} else {
			reqPath = "/_ilm/explain"
		}

	case "ilm.get_status":
		method = http.MethodGet
		reqPath = "/_ilm/status"

	case "ilm.start":
		method = http.MethodPost
		reqPath = "/_ilm/start"

	case "ilm.stop":
		method = http.MethodPost
		reqPath = "/_ilm/stop"

	case "ilm.move_to_step":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ilm.move_to_step requires index parameter")
		}
		reqPath = "/_ilm/move/" + idx

	case "ilm.remove_policy":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ilm.remove_policy requires index parameter")
		}
		reqPath = "/" + idx + "/_ilm/remove"

	case "ilm.retry":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ilm.retry requires index parameter")
		}
		reqPath = "/" + idx + "/_ilm/retry"

	case "enrich.put_policy":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("enrich.put_policy requires name parameter")
		}
		reqPath = "/_enrich/policy/" + name

	case "enrich.get_policy":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_enrich/policy/" + name
		} else {
			reqPath = "/_enrich/policy"
		}

	case "enrich.delete_policy":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("enrich.delete_policy requires name parameter")
		}
		reqPath = "/_enrich/policy/" + name

	case "enrich.execute_policy":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("enrich.execute_policy requires name parameter")
		}
		reqPath = "/_enrich/policy/" + name + "/_execute"

	case "enrich.stats":
		method = http.MethodGet
		reqPath = "/_enrich/_stats"

	case "ingest.exists_pipeline":
		method = http.MethodHead
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("ingest.exists_pipeline requires id parameter")
		}
		reqPath = "/_ingest/pipeline/" + id

	case "put_script":
		method = http.MethodPut
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("put_script requires id parameter")
		}
		if ctxName := popString("context"); ctxName != "" {
			reqPath = "/_scripts/" + id + "/" + ctxName
		} else {
			reqPath = "/_scripts/" + id
		}

	case "get_script":
		method = http.MethodGet
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("get_script requires id parameter")
		}
		reqPath = "/_scripts/" + id

	case "delete_script":
		method = http.MethodDelete
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("delete_script requires id parameter")
		}
		reqPath = "/_scripts/" + id

	case "exists_script":
		method = http.MethodHead
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("exists_script requires id parameter")
		}
		reqPath = "/_scripts/" + id

	case "execute_painless_execute", "scripts_painless_execute":
		method = http.MethodPost
		reqPath = "/_scripts/painless/_execute"
		if !hasBody {
			bodyObj := make(map[string]any)
			for _, k := range []string{"script", "context", "context_setup"} {
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

	case "search_template":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_search/template"
		} else {
			reqPath = "/_search/template"
		}

	case "render_search_template":
		if hasBody && rawBody != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
		if id := popString("id"); id != "" {
			reqPath = "/_render/template/" + id
		} else {
			reqPath = "/_render/template"
		}

	case "msearch_template":
		method = http.MethodPost
		isNDJSON = true
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_msearch/template"
		} else {
			reqPath = "/_msearch/template"
		}

	case "termvectors", "indices.get_termvectors":
		if hasBody && rawBody != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("%s requires index parameter", action)
		}
		if id := popString("id"); id != "" {
			reqPath = "/" + idx + "/_termvectors/" + id
		} else {
			reqPath = "/" + idx + "/_termvectors"
		}

	case "mtermvectors":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_mtermvectors"
		} else {
			reqPath = "/_mtermvectors"
		}

	case "rank_eval":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_rank_eval"
		} else {
			reqPath = "/_rank_eval"
		}

	case "search_mvt":
		method = http.MethodGet
		idx := popString("index")
		field := popString("field")
		zoom := popString("zoom")
		x := popString("x")
		y := popString("y")
		if idx == "" || field == "" || zoom == "" || x == "" || y == "" {
			return nil, fmt.Errorf("search_mvt requires index, field, zoom, x, and y parameters")
		}
		reqPath = "/" + idx + "/_mvt/" + field + "/" + zoom + "/" + x + "/" + y

	case "cat.allocation":
		method = http.MethodGet
		if nodeID := popString("node_id"); nodeID != "" {
			reqPath = "/_cat/allocation/" + nodeID
		} else {
			reqPath = "/_cat/allocation"
		}

	case "cat.fielddata":
		method = http.MethodGet
		if fields := popString("fields"); fields != "" {
			reqPath = "/_cat/fielddata/" + fields
		} else {
			reqPath = "/_cat/fielddata"
		}

	case "cat.master":
		method = http.MethodGet
		reqPath = "/_cat/master"

	case "cat.nodeattrs":
		method = http.MethodGet
		reqPath = "/_cat/nodeattrs"

	case "cat.pending_tasks":
		method = http.MethodGet
		reqPath = "/_cat/pending_tasks"

	case "cat.plugins":
		method = http.MethodGet
		reqPath = "/_cat/plugins"

	case "cat.recovery":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/_cat/recovery/" + idx
		} else {
			reqPath = "/_cat/recovery"
		}

	case "cat.repositories":
		method = http.MethodGet
		reqPath = "/_cat/repositories"

	case "cat.segments":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/_cat/segments/" + idx
		} else {
			reqPath = "/_cat/segments"
		}

	case "cat.tasks":
		method = http.MethodGet
		reqPath = "/_cat/tasks"

	case "cat.thread_pool":
		method = http.MethodGet
		if patterns := popString("thread_pool_patterns"); patterns != "" {
			reqPath = "/_cat/thread_pool/" + patterns
		} else {
			reqPath = "/_cat/thread_pool"
		}

	case "cat.templates":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_cat/templates/" + name
		} else {
			reqPath = "/_cat/templates"
		}

	case "indices.recovery":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_recovery"
		} else {
			reqPath = "/_recovery"
		}

	case "indices.segments":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_segments"
		} else {
			reqPath = "/_segments"
		}

	case "indices.shard_stores":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_shard_stores"
		} else {
			reqPath = "/_shard_stores"
		}

	case "indices.clear_cache":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_cache/clear"
		} else {
			reqPath = "/_cache/clear"
		}

	case "indices.open":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.open requires index parameter")
		}
		reqPath = "/" + idx + "/_open"

	case "indices.close":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.close requires index parameter")
		}
		reqPath = "/" + idx + "/_close"

	case "tasks.list":
		method = http.MethodGet
		reqPath = "/_tasks"

	case "tasks.get":
		method = http.MethodGet
		taskID := popString("task_id")
		if taskID == "" {
			return nil, fmt.Errorf("tasks.get requires task_id parameter")
		}
		reqPath = "/_tasks/" + taskID

	case "tasks.cancel":
		method = http.MethodPost
		if taskID := popString("task_id"); taskID != "" {
			reqPath = "/_tasks/" + taskID + "/_cancel"
		} else {
			reqPath = "/_tasks/_cancel"
		}

	case "cluster.allocation_explain":
		if hasBody && rawBody != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
		reqPath = "/_cluster/allocation/explain"

	case "cluster.pending_tasks":
		method = http.MethodGet
		reqPath = "/_cluster/pending_tasks"

	case "cluster.reroute":
		method = http.MethodPost
		reqPath = "/_cluster/reroute"

	case "nodes.usage":
		method = http.MethodGet
		nodeID := popString("node_id")
		metric := popString("metric")
		switch {
		case nodeID != "" && metric != "":
			reqPath = "/_nodes/" + nodeID + "/usage/" + metric
		case nodeID != "":
			reqPath = "/_nodes/" + nodeID + "/usage"
		case metric != "":
			reqPath = "/_nodes/usage/" + metric
		default:
			reqPath = "/_nodes/usage"
		}

	case "nodes.hot_threads":
		method = http.MethodGet
		if nodeID := popString("node_id"); nodeID != "" {
			reqPath = "/_nodes/" + nodeID + "/hot_threads"
		} else {
			reqPath = "/_nodes/hot_threads"
		}

	case "knn_search":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_knn_search"
		} else {
			reqPath = "/_knn_search"
		}

	case "cat.data_streams":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_cat/data_streams/" + name
		} else {
			reqPath = "/_cat/data_streams"
		}

	case "snapshot.create_repository", "snapshot.put_repository":
		method = http.MethodPut
		repo := popString("repository")
		if repo == "" {
			return nil, fmt.Errorf("%s requires repository parameter", action)
		}
		reqPath = "/_snapshot/" + repo

	case "snapshot.get_repository":
		method = http.MethodGet
		if repo := popString("repository"); repo != "" {
			reqPath = "/_snapshot/" + repo
		} else {
			reqPath = "/_snapshot"
		}

	case "snapshot.delete_repository":
		method = http.MethodDelete
		repo := popString("repository")
		if repo == "" {
			return nil, fmt.Errorf("snapshot.delete_repository requires repository parameter")
		}
		reqPath = "/_snapshot/" + repo

	case "snapshot.verify_repository":
		method = http.MethodPost
		repo := popString("repository")
		if repo == "" {
			return nil, fmt.Errorf("snapshot.verify_repository requires repository parameter")
		}
		reqPath = "/_snapshot/" + repo + "/_verify"

	case "snapshot.create":
		method = http.MethodPut
		repo := popString("repository")
		snap := popString("snapshot")
		if repo == "" || snap == "" {
			return nil, fmt.Errorf("snapshot.create requires repository and snapshot parameters")
		}
		reqPath = "/_snapshot/" + repo + "/" + snap

	case "snapshot.get":
		method = http.MethodGet
		repo := popString("repository")
		snap := popString("snapshot")
		if repo == "" || snap == "" {
			return nil, fmt.Errorf("snapshot.get requires repository and snapshot parameters")
		}
		reqPath = "/_snapshot/" + repo + "/" + snap

	case "snapshot.delete":
		method = http.MethodDelete
		repo := popString("repository")
		snap := popString("snapshot")
		if repo == "" || snap == "" {
			return nil, fmt.Errorf("snapshot.delete requires repository and snapshot parameters")
		}
		reqPath = "/_snapshot/" + repo + "/" + snap

	case "snapshot.status":
		method = http.MethodGet
		repo := popString("repository")
		snap := popString("snapshot")
		switch {
		case repo != "" && snap != "":
			reqPath = "/_snapshot/" + repo + "/" + snap + "/_status"
		case repo != "":
			reqPath = "/_snapshot/" + repo + "/_status"
		default:
			reqPath = "/_snapshot/_status"
		}

	case "snapshot.restore":
		method = http.MethodPost
		repo := popString("repository")
		snap := popString("snapshot")
		if repo == "" || snap == "" {
			return nil, fmt.Errorf("snapshot.restore requires repository and snapshot parameters")
		}
		reqPath = "/_snapshot/" + repo + "/" + snap + "/_restore"

	case "cat.snapshots":
		method = http.MethodGet
		if repo := popString("repository"); repo != "" {
			reqPath = "/_cat/snapshots/" + repo
		} else {
			reqPath = "/_cat/snapshots"
		}

	case "cluster.remote_info":
		method = http.MethodGet
		reqPath = "/_remote/info"

	case "nodes.reload_secure_settings":
		method = http.MethodPost
		if nodeID := popString("node_id"); nodeID != "" {
			reqPath = "/_nodes/" + nodeID + "/reload_secure_settings"
		} else {
			reqPath = "/_nodes/reload_secure_settings"
		}

	case "indices.simulate_template":
		method = http.MethodPost
		if name := popString("name"); name != "" {
			reqPath = "/_index_template/_simulate/" + name
		} else {
			reqPath = "/_index_template/_simulate"
		}

	case "indices.simulate_index_template":
		method = http.MethodPost
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("indices.simulate_index_template requires name parameter")
		}
		reqPath = "/_index_template/_simulate_index/" + name

	case "indices.add_block":
		method = http.MethodPut
		idx := popString("index")
		block := popString("block")
		if idx == "" || block == "" {
			return nil, fmt.Errorf("indices.add_block requires index and block parameters")
		}
		reqPath = "/" + idx + "/_block/" + block

	case "indices.downgrade":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("indices.downgrade requires index parameter")
		}
		reqPath = "/" + idx + "/_downgrade"

	case "slm.put_lifecycle":
		method = http.MethodPut
		pol := popString("policy_id", "policy", "id", "name")
		if pol == "" {
			return nil, fmt.Errorf("slm.put_lifecycle requires policy_id parameter")
		}
		reqPath = "/_slm/policy/" + pol

	case "slm.get_lifecycle":
		method = http.MethodGet
		if pol := popString("policy_id", "policy", "id", "name"); pol != "" {
			reqPath = "/_slm/policy/" + pol
		} else {
			reqPath = "/_slm/policy"
		}

	case "slm.delete_lifecycle":
		method = http.MethodDelete
		pol := popString("policy_id", "policy", "id", "name")
		if pol == "" {
			return nil, fmt.Errorf("slm.delete_lifecycle requires policy_id parameter")
		}
		reqPath = "/_slm/policy/" + pol

	case "slm.execute_lifecycle":
		method = http.MethodPost
		pol := popString("policy_id", "policy", "id", "name")
		if pol == "" {
			return nil, fmt.Errorf("slm.execute_lifecycle requires policy_id parameter")
		}
		reqPath = "/_slm/policy/" + pol + "/_execute"

	case "slm.execute_retention":
		method = http.MethodPost
		reqPath = "/_slm/_execute_retention"

	case "slm.get_stats":
		method = http.MethodGet
		reqPath = "/_slm/stats"

	case "slm.get_status":
		method = http.MethodGet
		reqPath = "/_slm/status"

	case "slm.start":
		method = http.MethodPost
		reqPath = "/_slm/start"

	case "slm.stop":
		method = http.MethodPost
		reqPath = "/_slm/stop"

	case "ingest.processor_grok":
		method = http.MethodGet
		reqPath = "/_ingest/processor/grok"

	case "ingest.geo_ip_stats":
		method = http.MethodGet
		reqPath = "/_ingest/geoip/stats"

	case "watcher.put_watch":
		method = http.MethodPut
		id := popString("id", "watch_id")
		if id == "" {
			return nil, fmt.Errorf("watcher.put_watch requires id parameter")
		}
		reqPath = "/_watcher/watch/" + id

	case "watcher.get_watch":
		method = http.MethodGet
		id := popString("id", "watch_id")
		if id == "" {
			return nil, fmt.Errorf("watcher.get_watch requires id parameter")
		}
		reqPath = "/_watcher/watch/" + id

	case "watcher.delete_watch":
		method = http.MethodDelete
		id := popString("id", "watch_id")
		if id == "" {
			return nil, fmt.Errorf("watcher.delete_watch requires id parameter")
		}
		reqPath = "/_watcher/watch/" + id

	case "watcher.execute_watch":
		method = http.MethodPost
		if id := popString("id", "watch_id"); id != "" {
			reqPath = "/_watcher/watch/" + id + "/_execute"
		} else {
			reqPath = "/_watcher/watch/_execute"
		}

	case "watcher.ack_watch":
		method = http.MethodPut
		watchID := popString("watch_id", "id")
		actionID := popString("action_id")
		if watchID == "" {
			return nil, fmt.Errorf("watcher.ack_watch requires watch_id parameter")
		}
		if actionID != "" {
			reqPath = "/_watcher/watch/" + watchID + "/_ack/" + actionID
		} else {
			reqPath = "/_watcher/watch/" + watchID + "/_ack"
		}

	case "watcher.activate_watch":
		method = http.MethodPut
		watchID := popString("watch_id", "id")
		if watchID == "" {
			return nil, fmt.Errorf("watcher.activate_watch requires watch_id parameter")
		}
		reqPath = "/_watcher/watch/" + watchID + "/_activate"

	case "watcher.deactivate_watch":
		method = http.MethodPut
		watchID := popString("watch_id", "id")
		if watchID == "" {
			return nil, fmt.Errorf("watcher.deactivate_watch requires watch_id parameter")
		}
		reqPath = "/_watcher/watch/" + watchID + "/_deactivate"

	case "watcher.stats":
		method = http.MethodGet
		if metric := popString("metric"); metric != "" {
			reqPath = "/_watcher/stats/" + metric
		} else {
			reqPath = "/_watcher/stats"
		}

	case "watcher.start":
		method = http.MethodPost
		reqPath = "/_watcher/_start"

	case "watcher.stop":
		method = http.MethodPost
		reqPath = "/_watcher/_stop"

	case "transform.put_transform":
		method = http.MethodPut
		id := popString("transform_id", "id")
		if id == "" {
			return nil, fmt.Errorf("transform.put_transform requires transform_id parameter")
		}
		reqPath = "/_transform/" + id

	case "transform.get_transform":
		method = http.MethodGet
		if id := popString("transform_id", "id"); id != "" {
			reqPath = "/_transform/" + id
		} else {
			reqPath = "/_transform"
		}

	case "transform.delete_transform":
		method = http.MethodDelete
		id := popString("transform_id", "id")
		if id == "" {
			return nil, fmt.Errorf("transform.delete_transform requires transform_id parameter")
		}
		reqPath = "/_transform/" + id

	case "transform.start_transform":
		method = http.MethodPost
		id := popString("transform_id", "id")
		if id == "" {
			return nil, fmt.Errorf("transform.start_transform requires transform_id parameter")
		}
		reqPath = "/_transform/" + id + "/_start"

	case "transform.stop_transform":
		method = http.MethodPost
		id := popString("transform_id", "id")
		if id == "" {
			return nil, fmt.Errorf("transform.stop_transform requires transform_id parameter")
		}
		reqPath = "/_transform/" + id + "/_stop"

	case "transform.get_transform_stats":
		method = http.MethodGet
		if id := popString("transform_id", "id"); id != "" {
			reqPath = "/_transform/" + id + "/_stats"
		} else {
			reqPath = "/_transform/_stats"
		}

	case "transform.preview_transform":
		method = http.MethodPost
		reqPath = "/_transform/_preview"

	case "dangling_indices.list_dangling_indices":
		method = http.MethodGet
		reqPath = "/_dangling"

	case "dangling_indices.import_dangling_index":
		method = http.MethodPost
		uuid := popString("index_uuid")
		if uuid == "" {
			return nil, fmt.Errorf("dangling_indices.import_dangling_index requires index_uuid parameter")
		}
		reqPath = "/_dangling/" + uuid

	case "dangling_indices.delete_dangling_index":
		method = http.MethodDelete
		uuid := popString("index_uuid")
		if uuid == "" {
			return nil, fmt.Errorf("dangling_indices.delete_dangling_index requires index_uuid parameter")
		}
		reqPath = "/_dangling/" + uuid

	case "autoscaling.put_autoscaling_policy":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("autoscaling.put_autoscaling_policy requires name parameter")
		}
		reqPath = "/_autoscaling/policy/" + name

	case "autoscaling.get_autoscaling_policy":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_autoscaling/policy/" + name
		} else {
			reqPath = "/_autoscaling/policy"
		}

	case "autoscaling.delete_autoscaling_policy":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("autoscaling.delete_autoscaling_policy requires name parameter")
		}
		reqPath = "/_autoscaling/policy/" + name

	case "autoscaling.get_autoscaling_capacity":
		method = http.MethodGet
		reqPath = "/_autoscaling/capacity"

	case "transform.update_transform":
		method = http.MethodPost
		id := popString("transform_id", "id")
		if id == "" {
			return nil, fmt.Errorf("transform.update_transform requires transform_id parameter")
		}
		reqPath = "/_transform/" + id + "/_update"

	case "synonyms.put_synonym":
		method = http.MethodPut
		id := popString("id", "synonyms_set", "set_id")
		if id == "" {
			return nil, fmt.Errorf("synonyms.put_synonym requires id parameter")
		}
		reqPath = "/_synonyms/" + id

	case "synonyms.get_synonym":
		method = http.MethodGet
		id := popString("id", "synonyms_set", "set_id")
		if id == "" {
			return nil, fmt.Errorf("synonyms.get_synonym requires id parameter")
		}
		reqPath = "/_synonyms/" + id

	case "synonyms.get_synonyms_sets":
		method = http.MethodGet
		reqPath = "/_synonyms"

	case "synonyms.delete_synonym":
		method = http.MethodDelete
		id := popString("id", "synonyms_set", "set_id")
		if id == "" {
			return nil, fmt.Errorf("synonyms.delete_synonym requires id parameter")
		}
		reqPath = "/_synonyms/" + id

	case "synonyms.put_synonym_rule":
		method = http.MethodPut
		setID := popString("set_id", "synonyms_set", "id")
		ruleID := popString("rule_id")
		if setID == "" || ruleID == "" {
			return nil, fmt.Errorf("synonyms.put_synonym_rule requires set_id and rule_id parameters")
		}
		reqPath = "/_synonyms/" + setID + "/" + ruleID

	case "synonyms.get_synonym_rule":
		method = http.MethodGet
		setID := popString("set_id", "synonyms_set", "id")
		ruleID := popString("rule_id")
		if setID == "" || ruleID == "" {
			return nil, fmt.Errorf("synonyms.get_synonym_rule requires set_id and rule_id parameters")
		}
		reqPath = "/_synonyms/" + setID + "/" + ruleID

	case "synonyms.delete_synonym_rule":
		method = http.MethodDelete
		setID := popString("set_id", "synonyms_set", "id")
		ruleID := popString("rule_id")
		if setID == "" || ruleID == "" {
			return nil, fmt.Errorf("synonyms.delete_synonym_rule requires set_id and rule_id parameters")
		}
		reqPath = "/_synonyms/" + setID + "/" + ruleID

	case "synonyms.reload_synonym":
		method = http.MethodPost
		id := popString("id", "synonyms_set", "set_id")
		if id == "" {
			return nil, fmt.Errorf("synonyms.reload_synonym requires id parameter")
		}
		reqPath = "/_synonyms/" + id + "/_reload"

	case "query_rules.put_ruleset":
		method = http.MethodPut
		rulesetID := popString("ruleset_id", "id")
		if rulesetID == "" {
			return nil, fmt.Errorf("query_rules.put_ruleset requires ruleset_id parameter")
		}
		reqPath = "/_query_rules/" + rulesetID

	case "query_rules.get_ruleset":
		method = http.MethodGet
		rulesetID := popString("ruleset_id", "id")
		if rulesetID == "" {
			return nil, fmt.Errorf("query_rules.get_ruleset requires ruleset_id parameter")
		}
		reqPath = "/_query_rules/" + rulesetID

	case "query_rules.list_rulesets":
		method = http.MethodGet
		reqPath = "/_query_rules"

	case "query_rules.delete_ruleset":
		method = http.MethodDelete
		rulesetID := popString("ruleset_id", "id")
		if rulesetID == "" {
			return nil, fmt.Errorf("query_rules.delete_ruleset requires ruleset_id parameter")
		}
		reqPath = "/_query_rules/" + rulesetID

	case "query_rules.put_rule":
		method = http.MethodPut
		rulesetID := popString("ruleset_id", "id")
		ruleID := popString("rule_id")
		if rulesetID == "" || ruleID == "" {
			return nil, fmt.Errorf("query_rules.put_rule requires ruleset_id and rule_id parameters")
		}
		reqPath = "/_query_rules/" + rulesetID + "/_rule/" + ruleID

	case "query_rules.get_rule":
		method = http.MethodGet
		rulesetID := popString("ruleset_id", "id")
		ruleID := popString("rule_id")
		if rulesetID == "" || ruleID == "" {
			return nil, fmt.Errorf("query_rules.get_rule requires ruleset_id and rule_id parameters")
		}
		reqPath = "/_query_rules/" + rulesetID + "/_rule/" + ruleID

	case "query_rules.delete_rule":
		method = http.MethodDelete
		rulesetID := popString("ruleset_id", "id")
		ruleID := popString("rule_id")
		if rulesetID == "" || ruleID == "" {
			return nil, fmt.Errorf("query_rules.delete_rule requires ruleset_id and rule_id parameters")
		}
		reqPath = "/_query_rules/" + rulesetID + "/_rule/" + ruleID

	case "query_rules.test":
		method = http.MethodPost
		rulesetID := popString("ruleset_id", "id")
		if rulesetID == "" {
			return nil, fmt.Errorf("query_rules.test requires ruleset_id parameter")
		}
		reqPath = "/_query_rules/" + rulesetID + "/_test"

	case "features.get_features":
		method = http.MethodGet
		reqPath = "/_features"

	case "features.reset_features":
		method = http.MethodPost
		reqPath = "/_features/_reset"

	case "cluster.post_voting_config_exclusions":
		method = http.MethodPost
		reqPath = "/_cluster/voting_config_exclusions"

	case "cluster.delete_voting_config_exclusions":
		method = http.MethodDelete
		reqPath = "/_cluster/voting_config_exclusions"

	case "migration.deprecations":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_migration/deprecations"
		} else {
			reqPath = "/_migration/deprecations"
		}

	case "shutdown.put_node":
		method = http.MethodPut
		nodeID := popString("node_id")
		if nodeID == "" {
			return nil, fmt.Errorf("shutdown.put_node requires node_id parameter")
		}
		reqPath = "/_nodes/" + nodeID + "/shutdown"

	case "shutdown.get_node":
		method = http.MethodGet
		if nodeID := popString("node_id"); nodeID != "" {
			reqPath = "/_nodes/" + nodeID + "/shutdown"
		} else {
			reqPath = "/_nodes/shutdown"
		}

	case "shutdown.delete_node":
		method = http.MethodDelete
		nodeID := popString("node_id")
		if nodeID == "" {
			return nil, fmt.Errorf("shutdown.delete_node requires node_id parameter")
		}
		reqPath = "/_nodes/" + nodeID + "/shutdown"

	case "rollup.put_job":
		method = http.MethodPut
		id := popString("id", "job_id")
		if id == "" {
			return nil, fmt.Errorf("rollup.put_job requires id parameter")
		}
		reqPath = "/_rollup/job/" + id

	case "rollup.get_jobs":
		method = http.MethodGet
		if id := popString("id", "job_id"); id != "" {
			reqPath = "/_rollup/job/" + id
		} else {
			reqPath = "/_rollup/job"
		}

	case "rollup.delete_job":
		method = http.MethodDelete
		id := popString("id", "job_id")
		if id == "" {
			return nil, fmt.Errorf("rollup.delete_job requires id parameter")
		}
		reqPath = "/_rollup/job/" + id

	case "rollup.start_job":
		method = http.MethodPost
		id := popString("id", "job_id")
		if id == "" {
			return nil, fmt.Errorf("rollup.start_job requires id parameter")
		}
		reqPath = "/_rollup/job/" + id + "/_start"

	case "rollup.stop_job":
		method = http.MethodPost
		id := popString("id", "job_id")
		if id == "" {
			return nil, fmt.Errorf("rollup.stop_job requires id parameter")
		}
		reqPath = "/_rollup/job/" + id + "/_stop"

	case "rollup.get_rollup_caps":
		method = http.MethodGet
		if id := popString("id", "index"); id != "" {
			reqPath = "/_rollup/data/" + id
		} else {
			reqPath = "/_rollup/data/_all"
		}

	case "rollup.get_rollup_index_caps":
		method = http.MethodGet
		idx := popString("index", "id")
		if idx == "" {
			return nil, fmt.Errorf("rollup.get_rollup_index_caps requires index parameter")
		}
		reqPath = "/" + idx + "/_rollup/data"

	case "rollup.rollup_search":
		if hasBody && rawBody != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("rollup.rollup_search requires index parameter")
		}
		reqPath = "/" + idx + "/_rollup_search"

	case "ccr.put_auto_follow_pattern":
		method = http.MethodPut
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("ccr.put_auto_follow_pattern requires name parameter")
		}
		reqPath = "/_ccr/auto_follow/" + name

	case "ccr.get_auto_follow_pattern":
		method = http.MethodGet
		if name := popString("name"); name != "" {
			reqPath = "/_ccr/auto_follow/" + name
		} else {
			reqPath = "/_ccr/auto_follow"
		}

	case "ccr.delete_auto_follow_pattern":
		method = http.MethodDelete
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("ccr.delete_auto_follow_pattern requires name parameter")
		}
		reqPath = "/_ccr/auto_follow/" + name

	case "ccr.pause_auto_follow_pattern":
		method = http.MethodPost
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("ccr.pause_auto_follow_pattern requires name parameter")
		}
		reqPath = "/_ccr/auto_follow/" + name + "/_pause"

	case "ccr.resume_auto_follow_pattern":
		method = http.MethodPost
		name := popString("name")
		if name == "" {
			return nil, fmt.Errorf("ccr.resume_auto_follow_pattern requires name parameter")
		}
		reqPath = "/_ccr/auto_follow/" + name + "/_resume"

	case "ccr.follow":
		method = http.MethodPut
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.follow requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/follow"

	case "ccr.follow_info":
		method = http.MethodGet
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.follow_info requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/info"

	case "ccr.follow_stats":
		method = http.MethodGet
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.follow_stats requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/stats"

	case "ccr.pause_follow":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.pause_follow requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/pause_follow"

	case "ccr.resume_follow":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.resume_follow requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/resume_follow"

	case "ccr.unfollow":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.unfollow requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/unfollow"

	case "ccr.forget_follower":
		method = http.MethodPost
		idx := popString("index")
		if idx == "" {
			return nil, fmt.Errorf("ccr.forget_follower requires index parameter")
		}
		reqPath = "/" + idx + "/_ccr/forget_follower"

	case "ccr.stats":
		method = http.MethodGet
		reqPath = "/_ccr/stats"

	case "searchable_snapshots.mount":
		method = http.MethodPost
		repo := popString("repository")
		snap := popString("snapshot")
		if repo == "" || snap == "" {
			return nil, fmt.Errorf("searchable_snapshots.mount requires repository and snapshot parameters")
		}
		reqPath = "/_snapshot/" + repo + "/" + snap + "/_mount"

	case "searchable_snapshots.stats":
		method = http.MethodGet
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_searchable_snapshots/stats"
		} else {
			reqPath = "/_searchable_snapshots/stats"
		}

	case "searchable_snapshots.cache_stats":
		method = http.MethodGet
		reqPath = "/_searchable_snapshots/cache/stats"

	case "searchable_snapshots.clear_cache":
		method = http.MethodPost
		reqPath = "/_searchable_snapshots/cache/clear"

	case "security.authenticate":
		method = http.MethodGet
		reqPath = "/_security/_authenticate"

	case "security.put_user":
		method = http.MethodPut
		username := popString("username", "name", "id")
		if username == "" {
			return nil, fmt.Errorf("security.put_user requires username parameter")
		}
		reqPath = "/_security/user/" + username

	case "security.get_user":
		method = http.MethodGet
		if username := popString("username", "name", "id"); username != "" {
			reqPath = "/_security/user/" + username
		} else {
			reqPath = "/_security/user"
		}

	case "security.delete_user":
		method = http.MethodDelete
		username := popString("username", "name", "id")
		if username == "" {
			return nil, fmt.Errorf("security.delete_user requires username parameter")
		}
		reqPath = "/_security/user/" + username

	case "security.enable_user":
		method = http.MethodPut
		username := popString("username", "name", "id")
		if username == "" {
			return nil, fmt.Errorf("security.enable_user requires username parameter")
		}
		reqPath = "/_security/user/" + username + "/_enable"

	case "security.disable_user":
		method = http.MethodPut
		username := popString("username", "name", "id")
		if username == "" {
			return nil, fmt.Errorf("security.disable_user requires username parameter")
		}
		reqPath = "/_security/user/" + username + "/_disable"

	case "security.change_password":
		method = http.MethodPost
		if username := popString("username", "name", "id"); username != "" {
			reqPath = "/_security/user/" + username + "/_password"
		} else {
			reqPath = "/_security/user/_password"
		}

	case "security.has_privileges":
		method = http.MethodPost
		if username := popString("username", "name", "id"); username != "" {
			reqPath = "/_security/user/" + username + "/_has_privileges"
		} else {
			reqPath = "/_security/user/_has_privileges"
		}

	case "security.put_role":
		method = http.MethodPut
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("security.put_role requires name parameter")
		}
		reqPath = "/_security/role/" + name

	case "security.get_role":
		method = http.MethodGet
		if name := popString("name", "id"); name != "" {
			reqPath = "/_security/role/" + name
		} else {
			reqPath = "/_security/role"
		}

	case "security.delete_role":
		method = http.MethodDelete
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("security.delete_role requires name parameter")
		}
		reqPath = "/_security/role/" + name

	case "security.clear_cached_roles":
		method = http.MethodPost
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("security.clear_cached_roles requires name parameter")
		}
		reqPath = "/_security/role/" + name + "/_clear_cache"

	case "security.create_api_key":
		method = http.MethodPost
		reqPath = "/_security/api_key"

	case "security.get_api_key":
		method = http.MethodGet
		reqPath = "/_security/api_key"

	case "security.invalidate_api_key":
		method = http.MethodDelete
		reqPath = "/_security/api_key"

	case "security.grant_api_key":
		method = http.MethodPost
		reqPath = "/_security/api_key/_grant"

	case "security.query_api_keys":
		method = http.MethodPost
		reqPath = "/_security/_query/api_key"

	case "security.clear_api_key_cache":
		method = http.MethodPost
		reqPath = "/_security/_clear_api_key_cache"

	case "security.get_builtin_privileges":
		method = http.MethodGet
		reqPath = "/_security/privilege/_builtin"

	case "security.put_privileges":
		method = http.MethodPut
		reqPath = "/_security/privilege"

	case "security.get_privileges":
		method = http.MethodGet
		app := popString("application")
		name := popString("name")
		switch {
		case app != "" && name != "":
			reqPath = "/_security/privilege/" + app + "/" + name
		case app != "":
			reqPath = "/_security/privilege/" + app
		default:
			reqPath = "/_security/privilege"
		}

	case "security.delete_privileges":
		method = http.MethodDelete
		app := popString("application")
		name := popString("name")
		if app == "" || name == "" {
			return nil, fmt.Errorf("security.delete_privileges requires application and name parameters")
		}
		reqPath = "/_security/privilege/" + app + "/" + name

	case "security.create_service_token":
		method = http.MethodPost
		ns := popString("namespace")
		svc := popString("service")
		tokenName := popString("token_name", "name")
		if ns == "" || svc == "" {
			return nil, fmt.Errorf("security.create_service_token requires namespace and service parameters")
		}
		if tokenName != "" {
			reqPath = "/_security/service/" + ns + "/" + svc + "/credential/token/" + tokenName
		} else {
			reqPath = "/_security/service/" + ns + "/" + svc + "/credential/token"
		}

	case "security.delete_service_token":
		method = http.MethodDelete
		ns := popString("namespace")
		svc := popString("service")
		tokenName := popString("token_name", "name")
		if ns == "" || svc == "" || tokenName == "" {
			return nil, fmt.Errorf("security.delete_service_token requires namespace, service, and token_name parameters")
		}
		reqPath = "/_security/service/" + ns + "/" + svc + "/credential/token/" + tokenName

	case "security.list_service_tokens":
		method = http.MethodGet
		ns := popString("namespace")
		svc := popString("service")
		if ns == "" || svc == "" {
			return nil, fmt.Errorf("security.list_service_tokens requires namespace and service parameters")
		}
		reqPath = "/_security/service/" + ns + "/" + svc + "/credential/token"

	case "security.get_service_accounts":
		method = http.MethodGet
		ns := popString("namespace")
		svc := popString("service")
		switch {
		case ns != "" && svc != "":
			reqPath = "/_security/service/" + ns + "/" + svc
		case ns != "":
			reqPath = "/_security/service/" + ns
		default:
			reqPath = "/_security/service"
		}

	case "security.get_service_credentials":
		method = http.MethodGet
		ns := popString("namespace")
		svc := popString("service")
		if ns == "" || svc == "" {
			return nil, fmt.Errorf("security.get_service_credentials requires namespace and service parameters")
		}
		reqPath = "/_security/service/" + ns + "/" + svc + "/credential"

	case "security.get_token":
		method = http.MethodPost
		reqPath = "/_security/oauth2/token"

	case "security.invalidate_token":
		method = http.MethodDelete
		reqPath = "/_security/oauth2/token"

	case "logstash.put_pipeline":
		method = http.MethodPut
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("logstash.put_pipeline requires id parameter")
		}
		reqPath = "/_logstash/pipeline/" + id

	case "logstash.get_pipeline":
		method = http.MethodGet
		if id := popString("id"); id != "" {
			reqPath = "/_logstash/pipeline/" + id
		} else {
			reqPath = "/_logstash/pipeline"
		}

	case "logstash.delete_pipeline":
		method = http.MethodDelete
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("logstash.delete_pipeline requires id parameter")
		}
		reqPath = "/_logstash/pipeline/" + id

	case "inference.put", "inference.put_model":
		method = http.MethodPut
		taskType := popString("task_type")
		infID := popString("inference_id", "id")
		if infID == "" {
			return nil, fmt.Errorf("%s requires inference_id parameter", action)
		}
		if taskType != "" {
			reqPath = "/_inference/" + taskType + "/" + infID
		} else {
			reqPath = "/_inference/" + infID
		}

	case "inference.get", "inference.get_model":
		method = http.MethodGet
		taskType := popString("task_type")
		infID := popString("inference_id", "id")
		switch {
		case taskType != "" && infID != "":
			reqPath = "/_inference/" + taskType + "/" + infID
		case infID != "":
			reqPath = "/_inference/" + infID
		case taskType != "":
			reqPath = "/_inference/" + taskType
		default:
			reqPath = "/_inference"
		}

	case "inference.delete", "inference.delete_model":
		method = http.MethodDelete
		taskType := popString("task_type")
		infID := popString("inference_id", "id")
		if infID == "" {
			return nil, fmt.Errorf("%s requires inference_id parameter", action)
		}
		if taskType != "" {
			reqPath = "/_inference/" + taskType + "/" + infID
		} else {
			reqPath = "/_inference/" + infID
		}

	case "inference.inference", "inference.post":
		method = http.MethodPost
		taskType := popString("task_type")
		infID := popString("inference_id", "id")
		if infID == "" {
			return nil, fmt.Errorf("%s requires inference_id parameter", action)
		}
		if taskType != "" {
			reqPath = "/_inference/" + taskType + "/" + infID
		} else {
			reqPath = "/_inference/" + infID
		}

	case "connector.put":
		method = http.MethodPut
		connID := popString("connector_id", "id")
		if connID == "" {
			return nil, fmt.Errorf("connector.put requires connector_id parameter")
		}
		reqPath = "/_connector/" + connID

	case "connector.post":
		method = http.MethodPost
		reqPath = "/_connector"

	case "connector.get":
		method = http.MethodGet
		connID := popString("connector_id", "id")
		if connID == "" {
			return nil, fmt.Errorf("connector.get requires connector_id parameter")
		}
		reqPath = "/_connector/" + connID

	case "connector.list":
		method = http.MethodGet
		reqPath = "/_connector"

	case "connector.delete":
		method = http.MethodDelete
		connID := popString("connector_id", "id")
		if connID == "" {
			return nil, fmt.Errorf("connector.delete requires connector_id parameter")
		}
		reqPath = "/_connector/" + connID

	case "connector.update_name", "connector.update_native", "connector.update_service_type",
		"connector.update_status", "connector.update_error", "connector.update_filtering",
		"connector.update_configuration", "connector.update_pipeline", "connector.last_sync":
		method = http.MethodPut
		connID := popString("connector_id", "id")
		if connID == "" {
			return nil, fmt.Errorf("%s requires connector_id parameter", action)
		}
		suffixMap := map[string]string{
			"connector.update_name":          "/_name",
			"connector.update_native":        "/_native",
			"connector.update_service_type":  "/_service_type",
			"connector.update_status":        "/_status",
			"connector.update_error":         "/_error",
			"connector.update_filtering":     "/_filtering",
			"connector.update_configuration": "/_configuration",
			"connector.update_pipeline":      "/_pipeline",
			"connector.last_sync":            "/_last_sync",
		}
		reqPath = "/_connector/" + connID + suffixMap[action]

	case "connector.sync_job_post":
		method = http.MethodPost
		reqPath = "/_connector/_sync_job"

	case "connector.sync_job_get":
		method = http.MethodGet
		jobID := popString("connector_sync_job_id", "id")
		if jobID == "" {
			return nil, fmt.Errorf("connector.sync_job_get requires connector_sync_job_id parameter")
		}
		reqPath = "/_connector/_sync_job/" + jobID

	case "connector.sync_job_list":
		method = http.MethodGet
		reqPath = "/_connector/_sync_job"

	case "connector.sync_job_delete":
		method = http.MethodDelete
		jobID := popString("connector_sync_job_id", "id")
		if jobID == "" {
			return nil, fmt.Errorf("connector.sync_job_delete requires connector_sync_job_id parameter")
		}
		reqPath = "/_connector/_sync_job/" + jobID

	case "connector.sync_job_cancel":
		method = http.MethodPost
		jobID := popString("connector_sync_job_id", "id")
		if jobID == "" {
			return nil, fmt.Errorf("connector.sync_job_cancel requires connector_sync_job_id parameter")
		}
		reqPath = "/_connector/_sync_job/" + jobID + "/_cancel"

	case "connector.sync_job_check_in":
		method = http.MethodPost
		jobID := popString("connector_sync_job_id", "id")
		if jobID == "" {
			return nil, fmt.Errorf("connector.sync_job_check_in requires connector_sync_job_id parameter")
		}
		reqPath = "/_connector/_sync_job/" + jobID + "/_check_in"

	case "connector.sync_job_error":
		method = http.MethodPut
		jobID := popString("connector_sync_job_id", "id")
		if jobID == "" {
			return nil, fmt.Errorf("connector.sync_job_error requires connector_sync_job_id parameter")
		}
		reqPath = "/_connector/_sync_job/" + jobID + "/_error"

	case "connector.sync_job_update_stats":
		method = http.MethodPut
		jobID := popString("connector_sync_job_id", "id")
		if jobID == "" {
			return nil, fmt.Errorf("connector.sync_job_update_stats requires connector_sync_job_id parameter")
		}
		reqPath = "/_connector/_sync_job/" + jobID + "/_stats"

	case "search_application.put":
		method = http.MethodPut
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("search_application.put requires name parameter")
		}
		reqPath = "/_application/search_application/" + name

	case "search_application.get":
		method = http.MethodGet
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("search_application.get requires name parameter")
		}
		reqPath = "/_application/search_application/" + name

	case "search_application.delete":
		method = http.MethodDelete
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("search_application.delete requires name parameter")
		}
		reqPath = "/_application/search_application/" + name

	case "search_application.list":
		method = http.MethodGet
		reqPath = "/_application/search_application"

	case "search_application.search":
		method = http.MethodPost
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("search_application.search requires name parameter")
		}
		reqPath = "/_application/search_application/" + name + "/_search"

	case "search_application.render_query":
		method = http.MethodPost
		name := popString("name", "id")
		if name == "" {
			return nil, fmt.Errorf("search_application.render_query requires name parameter")
		}
		reqPath = "/_application/search_application/" + name + "/_render_query"

	case "behavioral_analytics.put_collection":
		method = http.MethodPut
		coll := popString("collection_name", "name")
		if coll == "" {
			return nil, fmt.Errorf("behavioral_analytics.put_collection requires collection_name parameter")
		}
		reqPath = "/_application/analytics/" + coll

	case "behavioral_analytics.get_collections":
		method = http.MethodGet
		if coll := popString("collection_name", "name"); coll != "" {
			reqPath = "/_application/analytics/" + coll
		} else {
			reqPath = "/_application/analytics"
		}

	case "behavioral_analytics.delete_collection":
		method = http.MethodDelete
		coll := popString("collection_name", "name")
		if coll == "" {
			return nil, fmt.Errorf("behavioral_analytics.delete_collection requires collection_name parameter")
		}
		reqPath = "/_application/analytics/" + coll

	case "behavioral_analytics.post_event":
		method = http.MethodPost
		coll := popString("collection_name", "name")
		evType := popString("event_type", "type")
		if coll == "" || evType == "" {
			return nil, fmt.Errorf("behavioral_analytics.post_event requires collection_name and event_type parameters")
		}
		reqPath = "/_application/analytics/" + coll + "/event/" + evType

	case "text_structure.find_structure":
		method = http.MethodPost
		reqPath = "/_text_structure/find_structure"

	case "text_structure.find_field_structure":
		method = http.MethodPost
		reqPath = "/_text_structure/find_field_structure"

	case "text_structure.find_message_structure":
		method = http.MethodPost
		reqPath = "/_text_structure/find_message_structure"

	case "text_structure.test_grok_pattern":
		method = http.MethodPost
		reqPath = "/_text_structure/test_grok_pattern"

	case "profiling.status":
		method = http.MethodGet
		reqPath = "/_profiling/status"

	case "profiling.flamegraph":
		method = http.MethodPost
		reqPath = "/_profiling/flamegraph"

	case "profiling.stacktraces":
		method = http.MethodPost
		reqPath = "/_profiling/stacktraces"

	case "profiling.topn_functions":
		method = http.MethodPost
		reqPath = "/_profiling/topn_functions"

	case "async_search.submit":
		method = http.MethodPost
		if idx := popString("index"); idx != "" {
			reqPath = "/" + idx + "/_async_search"
		} else {
			reqPath = "/_async_search"
		}

	case "async_search.get":
		method = http.MethodGet
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("async_search.get requires id parameter")
		}
		reqPath = "/_async_search/" + id

	case "async_search.status":
		method = http.MethodGet
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("async_search.status requires id parameter")
		}
		reqPath = "/_async_search/status/" + id

	case "async_search.delete":
		method = http.MethodDelete
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("async_search.delete requires id parameter")
		}
		reqPath = "/_async_search/" + id

	case "esql.query":
		method = http.MethodPost
		reqPath = "/_query"

	case "esql.async_query":
		method = http.MethodPost
		reqPath = "/_query/async"

	case "esql.async_query_get":
		method = http.MethodGet
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("esql.async_query_get requires id parameter")
		}
		reqPath = "/_query/async/" + id

	case "esql.async_query_stop":
		method = http.MethodPost
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("esql.async_query_stop requires id parameter")
		}
		reqPath = "/_query/async/" + id + "/_stop"

	case "esql.async_query_delete":
		method = http.MethodDelete
		id := popString("id")
		if id == "" {
			return nil, fmt.Errorf("esql.async_query_delete requires id parameter")
		}
		reqPath = "/_query/async/" + id

	case "watcher.query_watches":
		method = http.MethodPost
		reqPath = "/_watcher/_query/watches"

	case "watcher.get_settings":
		method = http.MethodGet
		reqPath = "/_watcher/settings"

	case "watcher.update_settings":
		method = http.MethodPut
		reqPath = "/_watcher/settings"

	case "cat.transforms":
		method = http.MethodGet
		if id := popString("transform_id", "id"); id != "" {
			reqPath = "/_cat/transforms/" + id
		} else {
			reqPath = "/_cat/transforms"
		}

	case "license.get":
		method = http.MethodGet
		reqPath = "/_license"

	case "license.delete":
		method = http.MethodDelete
		reqPath = "/_license"

	case "license.post_start_basic":
		method = http.MethodPost
		reqPath = "/_license/start_basic"

	case "license.get_basic_status":
		method = http.MethodGet
		reqPath = "/_license/basic_status"

	case "license.post_start_trial":
		method = http.MethodPost
		reqPath = "/_license/start_trial"

	case "license.get_trial_status":
		method = http.MethodGet
		reqPath = "/_license/trial_status"

	case "xpack.info":
		method = http.MethodGet
		reqPath = "/_xpack"

	case "xpack.usage":
		method = http.MethodGet
		reqPath = "/_xpack/usage"

	case "ssl.certificates":
		method = http.MethodGet
		reqPath = "/_ssl/certificates"

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

func firstNonEmptyParam(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := paramString(m, k); s != "" {
			return s
		}
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
	c.lastHeaders = make(map[string]any, len(resp.Header))
	for k, vals := range resp.Header {
		if len(vals) == 1 {
			c.lastHeaders[strings.ToLower(k)] = vals[0]
		} else if len(vals) > 1 {
			c.lastHeaders[strings.ToLower(k)] = strings.Join(vals, ", ")
		}
	}
	c.lastWarnings = append([]string(nil), resp.Header.Values("Warning")...)
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

func (c *runnerContext) expandStashPath(s string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	return reStashVar.ReplaceAllStringFunc(s, func(match string) string {
		key := match[1:]
		if sv, ok := c.stash[key]; ok {
			strVal := fmt.Sprintf("%v", sv)
			return strings.ReplaceAll(strVal, ".", `\.`)
		}
		return match
	})
}

func (c *runnerContext) execSkip(rawVal any) error {
	pairs, err := extractFieldPairs("skip", rawVal)
	if err != nil {
		return err
	}
	var versionSpec string
	var reason string
	var features []string
	for _, p := range pairs {
		switch p.Key {
		case "version":
			if p.Value != nil {
				versionSpec = strings.TrimSpace(fmt.Sprintf("%v", c.expandStash(p.Value)))
			}
		case "reason":
			if p.Value != nil {
				reason = strings.TrimSpace(fmt.Sprintf("%v", c.expandStash(p.Value)))
			}
		case "features":
			for _, f := range extractStringSlice(c.expandStash(p.Value)) {
				for _, part := range strings.Split(f, ",") {
					if trimmed := strings.TrimSpace(part); trimmed != "" {
						features = append(features, trimmed)
					}
				}
			}
		}
	}
	for _, feat := range features {
		if !supportedRunnerFeatures[feat] {
			r := reason
			if r == "" {
				r = fmt.Sprintf("unsupported feature %s", feat)
			}
			return &errSkipSection{reason: r}
		}
	}
	if versionSpec != "" && versionInRange(proxyTargetVersion, versionSpec) {
		r := reason
		if r == "" {
			r = fmt.Sprintf("version %s in skip range %s", proxyTargetVersion, versionSpec)
		}
		return &errSkipSection{reason: r}
	}
	return nil
}

func versionInRange(target, versionRange string) bool {
	vr := strings.TrimSpace(versionRange)
	if vr == "" {
		return false
	}
	if strings.EqualFold(vr, "all") {
		return true
	}
	if !strings.Contains(vr, "-") {
		return compareSemver(target, vr) == 0
	}
	parts := strings.SplitN(vr, "-", 2)
	minVer := strings.TrimSpace(parts[0])
	maxVer := strings.TrimSpace(parts[1])
	if minVer != "" && compareSemver(target, minVer) < 0 {
		return false
	}
	if maxVer != "" && compareSemver(target, maxVer) > 0 {
		return false
	}
	return true
}

func compareSemver(a, b string) int {
	pa := parseSemverParts(a)
	pb := parseSemverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseSemverParts(v string) [3]int {
	var out [3]int
	v = strings.TrimSpace(v)
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	segs := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(segs); i++ {
		if n, err := strconv.Atoi(strings.TrimSpace(segs[i])); err == nil {
			out[i] = n
		}
	}
	return out
}

func (c *runnerContext) execSet(rawVal any) error {
	pairs, err := extractFieldPairs("set", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashPath(p.Key)
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

var reTransformExpr = regexp.MustCompile(`^([A-Za-z0-9_]+)\((.+)\)$`)

func (c *runnerContext) execTransformAndSet(rawVal any) error {
	pairs, err := extractFieldPairs("transform_and_set", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		keyStr := strings.TrimSpace(p.Key)
		valStr := strings.TrimSpace(fmt.Sprintf("%v", p.Value))

		var varName, exprStr string
		if reTransformExpr.MatchString(valStr) && !reTransformExpr.MatchString(keyStr) {
			varName = keyStr
			exprStr = valStr
		} else if reTransformExpr.MatchString(keyStr) {
			exprStr = keyStr
			varName = valStr
		} else {
			return fmt.Errorf("transform_and_set: invalid transform expression in %q: %q", keyStr, valStr)
		}

		m := reTransformExpr.FindStringSubmatch(exprStr)
		fnName := m[1]
		rawPath := strings.TrimSpace(m[2])
		fieldPath := c.expandStashPath(rawPath)

		val, found := c.lookupResponsePath(fieldPath)
		if !found && strings.HasPrefix(rawPath, "$") {
			val, found = c.stash[strings.TrimPrefix(rawPath, "$")]
		}
		if !found || val == nil {
			return fmt.Errorf("transform_and_set: response path %q not found in %s", fieldPath, c.lastBodyRaw)
		}

		strVal, ok := val.(string)
		if !ok {
			strVal = fmt.Sprintf("%v", val)
		}
		var transformed any
		switch fnName {
		case "base64Encode":
			transformed = base64.StdEncoding.EncodeToString([]byte(strVal))
		case "base64Decode":
			decoded, decErr := decodeBase64String(strVal)
			if decErr != nil {
				return fmt.Errorf("transform_and_set: base64Decode failed: %w", decErr)
			}
			transformed = decoded
		case "base64UrlEncode":
			transformed = base64.RawURLEncoding.EncodeToString([]byte(strVal))
		case "base64UrlDecode":
			decodedBytes, decErr := base64.RawURLEncoding.DecodeString(strVal)
			if decErr != nil {
				decodedBytes, decErr = base64.URLEncoding.DecodeString(strVal)
			}
			if decErr != nil {
				return fmt.Errorf("transform_and_set: base64UrlDecode failed: %w", decErr)
			}
			transformed = string(decodedBytes)
		case "length", "size":
			switch tv := val.(type) {
			case []any:
				transformed = len(tv)
			case map[string]any:
				transformed = len(tv)
			case string:
				transformed = len(tv)
			default:
				transformed = len(strVal)
			}
		case "lower":
			transformed = strings.ToLower(strVal)
		case "upper":
			transformed = strings.ToUpper(strVal)
		case "trim":
			transformed = strings.TrimSpace(strVal)
		default:
			return fmt.Errorf("transform_and_set: unsupported transform function %q", fnName)
		}

		varName = strings.TrimPrefix(varName, "$")
		c.stash[varName] = transformed
	}
	return nil
}

func decodeBase64String(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("invalid base64 input %q", s)
}

func (c *runnerContext) execContains(rawVal any) error {
	pairs, err := extractFieldPairs("contains", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashPath(p.Key)
		expected := ToNative(c.expandStash(p.Value))
		actual, found := c.lookupResponsePath(fieldPath)
		if !found {
			return fmt.Errorf("contains: path %q not found in response: %s", fieldPath, c.lastBodyRaw)
		}
		switch actVal := actual.(type) {
		case []any:
			matched := false
			for _, elem := range actVal {
				if containsElementMatch(elem, expected) {
					matched = true
					break
				}
			}
			if !matched {
				actJSON, _ := json.Marshal(actual)
				expJSON, _ := json.Marshal(expected)
				return fmt.Errorf("contains %q failed: no element in %s matched %s", fieldPath, string(actJSON), string(expJSON))
			}
		case string:
			if !strings.Contains(actVal, fmt.Sprintf("%v", expected)) && matchValues("", actVal, expected) != nil {
				return fmt.Errorf("contains %q failed: string %q does not contain %v", fieldPath, actVal, expected)
			}
		case map[string]any:
			if !containsElementMatch(actVal, expected) {
				actJSON, _ := json.Marshal(actual)
				expJSON, _ := json.Marshal(expected)
				return fmt.Errorf("contains %q failed: map %s did not match %s", fieldPath, string(actJSON), string(expJSON))
			}
		default:
			return fmt.Errorf("contains %q: expected slice, string, or map in response, got %T (%v)", fieldPath, actual, actual)
		}
	}
	return nil
}

func containsElementMatch(elem, expected any) bool {
	switch expVal := expected.(type) {
	case map[string]any:
		actMap, ok := elem.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range expVal {
			actVal, exists := actMap[k]
			if !exists || !containsElementMatch(actVal, v) {
				return false
			}
		}
		return true
	case []any:
		elemSlice, ok := elem.([]any)
		if !ok || len(elemSlice) != len(expVal) {
			return false
		}
		for i := range expVal {
			if !containsElementMatch(elemSlice[i], expVal[i]) {
				return false
			}
		}
		return true
	default:
		return matchValues("", elem, expected) == nil
	}
}

func (c *runnerContext) execMatch(rawVal any) error {
	pairs, err := extractFieldPairs("match", rawVal)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		fieldPath := c.expandStashPath(p.Key)
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
	if actStr, aOk := actual.(string); aOk {
		if expStr, eOk := expected.(string); eOk {
			if cleanTextString(actStr) == cleanTextString(expStr) {
				return nil
			}
		}
	}
	actJSON, _ := json.Marshal(actual)
	expJSON, _ := json.Marshal(expected)
	return fmt.Errorf("match %q failed: got %s, expected %s", fieldPath, string(actJSON), string(expJSON))
}

func cleanTextString(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(strings.Trim(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func valuesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if bs, ok := b.(string); ok && len(bs) >= 2 && strings.HasPrefix(bs, "/") && strings.HasSuffix(bs, "/") {
		pattern := bs[1 : len(bs)-1]
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", a))
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
		fieldPath = c.expandStashPath(fmt.Sprintf("%v", rawVal))
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
		fieldPath = c.expandStashPath(fmt.Sprintf("%v", rawVal))
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
		fieldPath := c.expandStashPath(p.Key)
		expLen, ok := toInt(c.expandStash(p.Value))
		if !ok {
			return fmt.Errorf("length %q: expected integer length, got %v", fieldPath, p.Value)
		}

		val, found := c.lookupResponsePath(fieldPath)
		if !found {
			return fmt.Errorf("length: path %q not found in response: %s", fieldPath, c.lastBodyRaw)
		}
		var actLen int
		switch tv := val.(type) {
		case string:
			actLen = utf8.RuneCountInString(tv)
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
		fieldPath := c.expandStashPath(p.Key)
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

func toInt(v any) (int, bool) {
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	case json.Number:
		if iv, err := val.Int64(); err == nil {
			return int(iv), true
		}
		if fv, err := val.Float64(); err == nil {
			return int(fv), true
		}
		return 0, false
	case string:
		trimmed := strings.TrimSpace(val)
		if iv, err := strconv.Atoi(trimmed); err == nil {
			return iv, true
		}
		if fv, err := strconv.ParseFloat(trimmed, 64); err == nil {
			return int(fv), true
		}
		return 0, false
	default:
		return 0, false
	}
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
	rawPath = strings.TrimPrefix(rawPath, "$body.")
	if rawPath == "$headers" {
		return c.lastHeaders, c.lastHeaders != nil
	}
	if strings.HasPrefix(rawPath, "$headers.") {
		hdrKey := strings.ToLower(strings.TrimPrefix(rawPath, "$headers."))
		val, ok := c.lastHeaders[hdrKey]
		return val, ok
	}
	if strings.HasPrefix(rawPath, "headers.") {
		hasBodyHeaders := false
		if bodyMap, ok := c.lastResponse.(map[string]any); ok {
			_, hasBodyHeaders = bodyMap["headers"]
		}
		if !hasBodyHeaders {
			hdrKey := strings.ToLower(strings.TrimPrefix(rawPath, "headers."))
			val, ok := c.lastHeaders[hdrKey]
			return val, ok
		}
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
				if len(segments) == 1 && strings.Contains(seg, ".") {
					subCur := any(node)
					subFound := true
					for _, subSeg := range strings.Split(seg, ".") {
						switch sn := subCur.(type) {
						case map[string]any:
							sv, ok := sn[subSeg]
							if !ok {
								subFound = false
							} else {
								subCur = sv
							}
						case []any:
							idx, err := strconv.Atoi(subSeg)
							if err == nil && idx < 0 {
								idx = len(sn) + idx
							}
							if err != nil || idx < 0 || idx >= len(sn) {
								subFound = false
							} else {
								subCur = sn[idx]
							}
						default:
							subFound = false
						}
						if !subFound {
							break
						}
					}
					if subFound {
						return subCur, true
					}
				}
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err == nil && idx < 0 {
				idx = len(node) + idx
			}
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
