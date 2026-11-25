package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

type round65CustomUnwrapWriter struct {
	http.ResponseWriter
}

func (w *round65CustomUnwrapWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func doR65Req(t *testing.T, h http.Handler, method, path, body string) (int, http.Header, map[string]any, string) {
	t.Helper()
	return doRound61AdminReq(t, h, method, path, body, nil)
}

func r65Int(v any) int64 {
	n, _ := toInt64(v)
	return n
}

func TestRound65_SnapshotRepoURLSecurityAndFS(t *testing.T) {
	tmpRoot := t.TempDir()
	pathRepoDir := filepath.Join(tmpRoot, "repo_root")
	safeSubDir := filepath.Join(pathRepoDir, "safe_sub")
	outsideDir := filepath.Join(tmpRoot, "outside_secret")
	if err := os.MkdirAll(safeSubDir, 0o750); err != nil {
		t.Fatalf("mkdir safe_sub: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	insideLink := filepath.Join(pathRepoDir, "safe_link")
	escapeLink := filepath.Join(pathRepoDir, "escape_link")
	danglingLink := filepath.Join(pathRepoDir, "dangling_link")
	_ = os.Symlink(safeSubDir, insideLink)
	_ = os.Symlink(outsideDir, escapeLink)
	_ = os.Symlink(filepath.Join(outsideDir, "future_catalog"), danglingLink)

	resolvedRoot, err := resolveSymlinkBestEffortR65(pathRepoDir)
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	resolvedSafe, err := resolveSymlinkBestEffortR65(safeSubDir)
	if err != nil {
		t.Fatalf("resolve safe: %v", err)
	}
	filePrefix := "file:///" + strings.TrimPrefix(filepath.ToSlash(pathRepoDir), "/") + "/"

	// extractConfiguredPathReposLockedR65 supports []string, []any, comma string, nested {path:{repo:...}}
	for _, tc := range []struct {
		name     string
		settings map[string]any
		wantLen  int
	}{
		{"flat_string_slice", map[string]any{"path.repo": []string{pathRepoDir, safeSubDir}}, 2},
		{"flat_any_slice", map[string]any{"path.repo": []any{pathRepoDir}}, 1},
		{"flat_comma_str", map[string]any{"path.repo": pathRepoDir + "," + safeSubDir}, 2},
		{"nested_map", map[string]any{"path": map[string]any{"repo": []any{pathRepoDir}}}, 1},
		{"empty", map[string]any{}, 0},
	} {
		got := extractConfiguredPathReposLockedR65(tc.settings)
		if len(got) != tc.wantLen {
			t.Fatalf("%s: expected %d path.repo roots, got %d (%v)", tc.name, tc.wantLen, len(got), got)
		}
	}

	pathRepos := []string{resolvedRoot}
	allowed := []string{
		"http://snapshot.test*",
		"https://snapshot.test*",
		"http://127.0.0.1:19200/*",
		filePrefix + "*",
	}

	// Valid URLs
	for _, raw := range []string{
		"http://snapshot.test/repo",
		"https://snapshot.test/sub/dir",
		"http://127.0.0.1:19200/catalog",
		"file:///" + strings.TrimPrefix(filepath.ToSlash(safeSubDir), "/") + "/snap",
		"file:///" + strings.TrimPrefix(filepath.ToSlash(insideLink), "/") + "/snap",
	} {
		if v, vErr := parseAndValidateSnapshotRepoURLR65(raw, pathRepos, allowed); vErr != nil || v == nil {
			t.Fatalf("expected valid URL %q, got err=%v", raw, vErr)
		}
	}

	// Blocked SSRF, LFI, symlink escape, non-canonical numeric IPs, credentials, query/fragment
	wildcardHTTP := []string{"http://*", "https://*", "*"}
	for _, tc := range []struct {
		name      string
		rawURL    string
		pathRepos []string
		patterns  []string
	}{
		{"empty", "", pathRepos, allowed},
		{"ftp_scheme", "ftp://snapshot.test/repo", pathRepos, allowed},
		{"gopher_scheme", "gopher://127.0.0.1:6379/_INFO", pathRepos, wildcardHTTP},
		{"userinfo", "http://user:pass@snapshot.test/", pathRepos, allowed},
		{"query", "http://snapshot.test/?q=1", pathRepos, allowed},
		{"fragment", "http://snapshot.test/#frag", pathRepos, allowed},
		{"null_byte", "http://snapshot.test/\x00", pathRepos, allowed},
		{"dotdot", "http://snapshot.test/a/../b", pathRepos, allowed},
		{"pct_dotdot", "http://snapshot.test/%2e%2e/secret", pathRepos, allowed},
		{"unlisted_host", "http://evil.example/repo", pathRepos, allowed},
		{"loopback_without_explicit_allow", "http://127.0.0.1:9200/", pathRepos, allowed},
		{"loopback_with_wildcard_only", "http://127.0.0.1:9200/", pathRepos, wildcardHTTP},
		{"rfc1918_10_wildcard", "http://10.0.0.1/", pathRepos, wildcardHTTP},
		{"rfc1918_192_wildcard", "http://192.168.1.50/", pathRepos, wildcardHTTP},
		{"imds_v4_exact_allow", "http://169.254.169.254/latest/meta-data/", pathRepos, []string{"http://169.254.169.254/*"}},
		{"imds_v4_mapped_v6", "http://[::ffff:169.254.169.254]/latest/meta-data/", pathRepos, wildcardHTTP},
		{"imds_v6_ec2", "http://[fd00:ec2::254]/latest/meta-data/", pathRepos, wildcardHTTP},
		{"gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/", pathRepos, []string{"http://metadata.google.internal/*"}},
		{"decimal_ip", "http://2130706433/", pathRepos, wildcardHTTP},
		{"octal_ip", "http://0177.0.0.1/", pathRepos, wildcardHTTP},
		{"hex_ip", "http://0x7f000001/", pathRepos, wildcardHTTP},
		{"shorthand_ip", "http://127.1/", pathRepos, wildcardHTTP},
		{"file_no_path_repo", "file:///" + strings.TrimPrefix(filepath.ToSlash(safeSubDir), "/") + "/x", nil, []string{"file://*"}},
		{"file_no_allowed_urls", "file:///" + strings.TrimPrefix(filepath.ToSlash(safeSubDir), "/") + "/x", pathRepos, nil},
		{"file_outside_root", "file:///" + strings.TrimPrefix(filepath.ToSlash(outsideDir), "/") + "/x", pathRepos, []string{"file://*"}},
		{"file_non_empty_host", "file://localhost/" + strings.TrimPrefix(filepath.ToSlash(safeSubDir), "/"), pathRepos, []string{"file://*"}},
		{"file_symlink_escape", "file:///" + strings.TrimPrefix(filepath.ToSlash(escapeLink), "/") + "/secret", pathRepos, []string{"file://*"}},
		{"file_dangling_symlink_escape", "file:///" + strings.TrimPrefix(filepath.ToSlash(danglingLink), "/") + "/secret", pathRepos, []string{"file://*"}},
	} {
		if _, err := parseAndValidateSnapshotRepoURLR65(tc.rawURL, tc.pathRepos, tc.patterns); err == nil {
			t.Fatalf("%s: expected rejection for %q", tc.name, tc.rawURL)
		}
	}

	// FS location containment validator
	if got, err := validateFSRepoLocationR65(safeSubDir, pathRepos); err != nil || !isPathContainedR65(got, resolvedSafe) {
		t.Fatalf("expected safe FS location, got %q err=%v", got, err)
	}
	if _, err := validateFSRepoLocationR65(escapeLink, pathRepos); err == nil {
		t.Fatalf("expected symlink escape rejection in validateFSRepoLocationR65")
	}
	if _, err := validateFSRepoLocationR65(outsideDir, pathRepos); err == nil {
		t.Fatalf("expected outside dir rejection in validateFSRepoLocationR65")
	}

	// Dial-time IP enforcement
	vHost, err := parseAndValidateSnapshotRepoURLR65("http://127.0.0.1:19200/repo", pathRepos, allowed)
	if err != nil {
		t.Fatalf("parse explicit loopback: %v", err)
	}
	if !isIPAuthorizedByExplicitAllowlistR65(netip.MustParseAddr("127.0.0.1"), vHost) {
		t.Fatalf("expected explicit loopback IP to be authorized")
	}
	if isIPAuthorizedByExplicitAllowlistR65(netip.MustParseAddr("169.254.169.254"), vHost) {
		t.Fatalf("IMDS IP must never be authorized")
	}
	if tr := buildSnapshotURLTransportR65(vHost); tr == nil || tr.Proxy != nil || !tr.DisableKeepAlives {
		t.Fatalf("expected isolated transport with Proxy=nil and DisableKeepAlives=true")
	}

	// Live HTTP integration: snapshot URL redirect rejection, size cap, HEAD Content-Length, FS persistence
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/big") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("a"), maxSnapshotURLCatalogBytesR65+1024))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/redir") {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		if r.URL.Path == "/ok/index.json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"snapshots":{"s1":{"snapshot":"s1","state":"SUCCESS","indices":[]}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer redirectSrv.Close()

	srv, handler := newRound61AdminTestServer(t, "8.15.5")
	srv.SetStaticPathRepo([]string{filepath.ToSlash(pathRepoDir)})
	srv.SetStaticRepositoriesURLAllowedURLs([]string{redirectSrv.URL + "/*", filePrefix + "*"})

	// PUT valid HTTP URL repo + HEAD compat & Content-Length + _all/_verify
	cPut, _, _, rawPut := doR65Req(t, handler, http.MethodPut, "/_snapshot/r_ok",
		`{"type":"url","settings":{"url":"`+redirectSrv.URL+`/ok"}}`)
	if cPut != http.StatusOK {
		t.Fatalf("expected 200 on PUT url repo, got %d: %s", cPut, rawPut)
	}
	cHead, hdrHead, _, _ := doRound61AdminReq(t, handler, http.MethodHead, "/_snapshot/r_ok", "",
		map[string]string{"Accept": "application/vnd.elasticsearch+json; compatible-with=8"})
	if cHead != http.StatusOK || hdrHead.Get("X-Elastic-Product") != "Elasticsearch" || hdrHead.Get("Content-Length") == "" {
		t.Fatalf("HEAD /_snapshot/r_ok missing compat headers: code=%d hdr=%v", cHead, hdrHead)
	}

	// SSRF blocked targets
	if cBad, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_snapshot/r_imds",
		`{"type":"url","settings":{"url":"http://169.254.169.254/latest"}}`); cBad != http.StatusBadRequest {
		t.Fatalf("expected 400 on IMDS URL repo, got %d", cBad)
	}
	if cEsc, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_snapshot/r_esc",
		`{"type":"fs","settings":{"location":"`+filepath.ToSlash(escapeLink)+`"}}`); cEsc != http.StatusBadRequest {
		t.Fatalf("expected 400 on FS symlink escape location, got %d", cEsc)
	}

	// Valid FS repo persists atomic index.json and verifies clean
	if cFS, _, _, rawFS := doR65Req(t, handler, http.MethodPut, "/_snapshot/r_fs",
		`{"type":"fs","settings":{"location":"`+filepath.ToSlash(safeSubDir)+`"}}`); cFS != http.StatusOK {
		t.Fatalf("expected 200 on valid FS repo, got %d: %s", cFS, rawFS)
	}
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/r65_idx", `{}`)
	if cSnap, _, _, rawSnap := doR65Req(t, handler, http.MethodPut, "/_snapshot/r_fs/s_disk?wait_for_completion=true",
		`{"indices":"r65_idx"}`); cSnap != http.StatusOK {
		t.Fatalf("expected 200 on snapshot create, got %d: %s", cSnap, rawSnap)
	}
	if _, statErr := os.Stat(filepath.Join(safeSubDir, proxySnapshotCatalogFileR64)); statErr != nil {
		t.Fatalf("expected disk snapshot catalog in %s: %v", safeSubDir, statErr)
	}

	// URL sync ignores redirect/oversized payloads safely
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/_snapshot/r_redir",
		`{"type":"url","settings":{"url":"`+redirectSrv.URL+`/redir"}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/_snapshot/r_big",
		`{"type":"url","settings":{"url":"`+redirectSrv.URL+`/big"}}`)
	srv.syncURLRepoSnapshotsByExprR64("r_redir,r_big,r_ok")
	srv.syncAllFSRepositoriesDiskR64()

	// Concurrent snapshot sync under -race
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.syncAllFSRepositoriesDiskR64()
			srv.syncURLRepoSnapshotsByExprR64("r_ok")
		}()
	}
	wg.Wait()
}

func TestRound65_ShardCacheAuthIsolation(t *testing.T) {
	srv, _ := newRound61AdminTestServer(t, "8.15.5")
	srv.mu.Lock()
	srv.securityUsers["alice"] = map[string]any{"username": "alice", "roles": []any{"reader"}}
	srv.securityUsers["bob"] = map[string]any{"username": "bob", "roles": []any{"writer"}}
	srv.securityRoles["reader"] = map[string]any{"indices": []any{"idx*"}}
	srv.securityRoles["writer"] = map[string]any{"indices": []any{"idx*"}}
	srv.securityAPIKeys["kid1"] = map[string]any{"id": "kid1", "username": "alice", "name": "k1"}
	srv.mu.Unlock()

	sReq := &esast.SearchRequest{}
	rawBody := []byte(`{"query":{"match_all":{}}}`)

	makeReq := func(authHdr, runAs string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/idx_a/_search", bytes.NewReader(rawBody))
		if authHdr != "" {
			r.Header.Set("Authorization", authHdr)
		}
		if runAs != "" {
			r.Header.Set("es-security-runas-user", runAs)
		}
		return r
	}

	kAnon := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	basicAlice := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pw"))
	basicBob := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:pw"))
	kAlice := srv.buildShardRequestCacheKeyR63(makeReq(basicAlice, ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	kBob := srv.buildShardRequestCacheKeyR63(makeReq(basicBob, ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	kRunAsBob := srv.buildShardRequestCacheKeyR63(makeReq(basicAlice, "bob"), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	apiKeyHdr := "ApiKey " + base64.StdEncoding.EncodeToString([]byte("kid1:secret"))
	kAPIKey := srv.buildShardRequestCacheKeyR63(makeReq(apiKeyHdr, ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	kBearer := srv.buildShardRequestCacheKeyR63(makeReq("Bearer tok1", ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)

	seen := map[string]string{
		kAnon:     "anon",
		kAlice:    "alice",
		kBob:      "bob",
		kRunAsBob: "runas",
		kAPIKey:   "apikey",
		kBearer:   "bearer",
	}
	if len(seen) != 6 {
		t.Fatalf("expected 6 distinct auth cache keys, got %d", len(seen))
	}

	// Mutating role privileges or invalidating API key must bust cache key
	srv.mu.Lock()
	srv.securityRoles["reader"] = map[string]any{"indices": []any{"other*"}}
	srv.mu.Unlock()
	kAliceAfterRole := srv.buildShardRequestCacheKeyR63(makeReq(basicAlice, ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	if kAliceAfterRole == kAlice {
		t.Fatalf("expected role update to bust shard request cache key")
	}

	srv.mu.Lock()
	srv.securityAPIKeys["kid1"]["invalidated"] = true
	srv.mu.Unlock()
	kAPIKeyAfter := srv.buildShardRequestCacheKeyR63(makeReq(apiKeyHdr, ""), []string{"idx_a"}, []string{"idx_a"}, sReq, rawBody)
	if kAPIKeyAfter == kAPIKey {
		t.Fatalf("expected API key mutation to bust shard request cache key")
	}
}

func TestRound65_CompatHeadersQZeroAndUnwrap(t *testing.T) {
	if mt, _, ok := parsePreferredAcceptCompatMediaTypeR65("application/vnd.elasticsearch+json; compatible-with=8; q=0, application/json; q=0.9"); !ok || mt != "application/json" {
		t.Fatalf("expected q=0 media type skipped, got mt=%q ok=%v", mt, ok)
	}
	if _, _, ok := parsePreferredAcceptCompatMediaTypeR65("application/json; q=0"); ok {
		t.Fatalf("expected single q=0 entry rejected")
	}

	rec := httptest.NewRecorder()
	fw := &esFormatResponseWriter{ResponseWriter: rec}
	hw := &headResponseWriterR64{ResponseWriter: fw}
	cw := &round65CustomUnwrapWriter{ResponseWriter: hw}

	req := httptest.NewRequest(http.MethodHead, "/_license?pretty=true&filter_path=ok", nil)
	req.Header.Set("Accept", "application/vnd.elasticsearch+json;compatible-with=8")
	writeJSONWithRequest(cw, req, http.StatusOK, map[string]any{"ok": true, "ignored": 1})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 status, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD request must not write body, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "compatible-with=8") {
		t.Fatalf("expected compatible-with=8 content type, got %q", rec.Header().Get("Content-Type"))
	}
	if !fw.opts.pretty {
		t.Fatalf("expected Unwrap loop to propagate format options to esFormatResponseWriter")
	}
}

func TestRound65_SearchableSnapshotsLicenseProfilingText(t *testing.T) {
	srv, handler := newRound61AdminTestServer(t, "8.15.5")
	repoDir := t.TempDir()
	srv.SetStaticPathRepo([]string{filepath.ToSlash(repoDir)})
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_snapshot/ss_repo",
		`{"type":"fs","settings":{"location":"`+filepath.ToSlash(repoDir)+`"}}`); c != http.StatusOK {
		t.Fatalf("PUT repo failed: %d %s", c, raw)
	}
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/ss_docs", `{}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/ss_docs/_doc/1?refresh=true", `{"field":"foo"}`)
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_snapshot/ss_repo/ss_snap?wait_for_completion=true", `{"indices":"ss_docs"}`); c != http.StatusOK {
		t.Fatalf("PUT snap failed: %d %s", c, raw)
	}
	_, _, _, _ = doR65Req(t, handler, http.MethodDelete, "/ss_docs", "")
	if c, _, _, raw := doR65Req(t, handler, http.MethodPost, "/_snapshot/ss_repo/ss_snap/_mount?storage=full_copy",
		`{"index":"ss_docs","renamed_index":"ss_fc"}`); c != http.StatusOK {
		t.Fatalf("mount full_copy failed: %d %s", c, raw)
	}
	if c, _, _, raw := doR65Req(t, handler, http.MethodPost, "/_snapshot/ss_repo/ss_snap/_mount?storage=shared_cache",
		`{"index":"ss_docs","renamed_index":"ss_sc"}`); c != http.StatusOK {
		t.Fatalf("mount shared_cache failed: %d %s", c, raw)
	}
	// Trigger syncCatalogFromBackend before /_xpack/usage to verify store.snapshot.storage survived persistence!
	_ = srv.syncCatalogFromBackend(context.Background())
	cUse, _, usage, rawUse := doR65Req(t, handler, http.MethodGet, "/_xpack/usage", "")
	if cUse != http.StatusOK {
		t.Fatalf("GET /_xpack/usage failed: %d %s", cUse, rawUse)
	}
	ssMap, _ := usage["searchable_snapshots"].(map[string]any)
	if r65Int(ssMap["indices_count"]) != 2 || r65Int(ssMap["full_copy_indices_count"]) != 1 || r65Int(ssMap["shared_cache_indices_count"]) != 1 {
		t.Fatalf("unexpected searchable_snapshots usage: %v", ssMap)
	}

	// License conformance cases
	cLic, _, mLic, _ := doR65Req(t, handler, http.MethodGet, "/_license", "")
	if cLic != http.StatusOK || len(mLic["license"].(map[string]any)) != 12 {
		t.Fatalf("expected 12-attr license, got %d %v", cLic, mLic)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodGet, "/_license?accept_enterprise=false", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on accept_enterprise=false, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_license?acknowledge=true", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty license post, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_license?acknowledge=true", `{"license":{"type":"basic"}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 posting basic license, got %d", c)
	}
	if c, _, m, _ := doR65Req(t, handler, http.MethodGet, "/_license/trial_status", ""); c != http.StatusOK || m["eligible_to_start_trial"] != false {
		t.Fatalf("expected eligible_to_start_trial=false on initial trial, got %d %v", c, m)
	}
	if c, _, m, _ := doR65Req(t, handler, http.MethodPost, "/_license/start_basic", ""); c != http.StatusOK || m["basic_was_started"] != false || m["acknowledged"] != false {
		t.Fatalf("expected 200 Needs acknowledgement, got %d %v", c, m)
	}
	if c, _, m, _ := doR65Req(t, handler, http.MethodPost, "/_license/start_basic?acknowledge=true", ""); c != http.StatusOK || m["basic_was_started"] != true {
		t.Fatalf("expected basic_was_started=true, got %d %v", c, m)
	}
	if c, _, m, _ := doR65Req(t, handler, http.MethodGet, "/_license/basic_status", ""); c != http.StatusOK || m["eligible_to_start_basic"] != false {
		t.Fatalf("expected eligible_to_start_basic=false, got %d %v", c, m)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_license/start_basic", ""); c != http.StatusForbidden {
		t.Fatalf("expected 403 when already basic, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_license/start_trial?type=basic", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on start_trial?type=basic, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_license/start_trial?acknowledge=true", ""); c != http.StatusForbidden {
		t.Fatalf("expected 403 on repeat start_trial, got %d", c)
	}

	// Text structure multiline log messages -> num_lines_analyzed == 3
	cTS, _, mTS, rawTS := doR65Req(t, handler, http.MethodPost, "/_text_structure/find_message_structure",
		`{"messages":["2019-05-16 16:56:14 line 1 abc","2019-05-16 16:56:14 line 2\ncont\ncont\n","2019-05-16 16:56:14 line 3"]}`)
	if cTS != http.StatusOK || r65Int(mTS["num_lines_analyzed"]) != 3 || r65Int(mTS["num_messages_analyzed"]) != 3 {
		t.Fatalf("unexpected find_message_structure result: %d %s", cTS, rawTS)
	}
	if cCS, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_text_structure/find_structure?charset=BOGUS", `{"text":"a"}`); cCS != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid charset, got %d", cCS)
	}

	// Profiling endpoints
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/profiling-events-all/_doc/1?refresh=true",
		`{"Stacktrace.id":["ST1"],"Stacktrace.count":[1]}`)
	for i := 0; i < 12; i++ {
		_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/profiling-stackframes/_doc/"+string(rune('a'+i))+"?refresh=true",
			`{"Stackframe.function.name":["fn_`+string(rune('a'+i))+`"]}`)
	}
	cPS, _, mPS, _ := doR65Req(t, handler, http.MethodGet, "/_profiling/status", "")
	if cPS != http.StatusOK || mPS["profiling"].(map[string]any)["enabled"] != true {
		t.Fatalf("unexpected profiling status: %d %v", cPS, mPS)
	}
	cFG, _, mFG, _ := doR65Req(t, handler, http.MethodPost, "/_profiling/flamegraph", `{}`)
	if cFG != http.StatusOK || r65Int(mFG["Size"]) != 47 {
		t.Fatalf("unexpected flamegraph: %d %v", cFG, mFG)
	}
	cST, _, mST, _ := doR65Req(t, handler, http.MethodPost, "/_profiling/stacktraces", `{}`)
	if cST != http.StatusOK || r65Int(mST["stack_traces"].(map[string]any)["ST1"].(map[string]any)["count"]) != 1 {
		t.Fatalf("unexpected stacktraces: %d %v", cST, mST)
	}
	cTN, _, mTN, _ := doR65Req(t, handler, http.MethodPost, "/_profiling/topn_functions", `{"limit":10}`)
	if cTN != http.StatusOK || len(mTN["topn"].([]any)) != 10 {
		t.Fatalf("unexpected topn_functions: %d %v", cTN, mTN)
	}
}

func TestRound65_RollupTransformAdminTemplatesESQL(t *testing.T) {
	_, handler := newRound61AdminTestServer(t, "8.15.5")

	// Source index with explicit mapping + non-rollup index
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/src_orders",
		`{"mappings":{"properties":{"ts":{"type":"date"},"airline":{"type":"keyword"},"price":{"type":"double"},"agg_metric":{"type":"aggregate_metric_double","metrics":["min","max"],"default_metric":"max"}}}}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/src_orders/_doc/1?refresh=true",
		`{"ts":"2017-01-01T05:10:00Z","airline":"AAL","price":10}`)
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/non_rollup_idx",
		`{"mappings":{"properties":{"x":{"type":"keyword"}}}}`)

	// Rollup validations
	if c, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_rollup/job/bad_hdr",
		`{"headers":{},"index_pattern":"src_orders","rollup_index":"r_dest","cron":"0 * * * * ?","page_size":10,"groups":{"date_histogram":{"field":"ts","calendar_interval":"1h"}}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown headers field, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_rollup/job/bad_metric",
		`{"index_pattern":"src_orders","rollup_index":"r_dest","cron":"0 * * * * ?","page_size":10,"groups":{"date_histogram":{"field":"ts","calendar_interval":"1h"}},"metrics":[{"field":"price","metrics":["bogus"]}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unsupported rollup metric, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_rollup/job/bad_field",
		`{"index_pattern":"src_orders","rollup_index":"r_dest","cron":"0 * * * * ?","page_size":10,"groups":{"date_histogram":{"field":"missing_ts","calendar_interval":"1h"}}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing mapped field, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_rollup/job/bad_dest",
		`{"index_pattern":"src_orders","rollup_index":"non_rollup_idx","cron":"0 * * * * ?","page_size":10,"groups":{"date_histogram":{"field":"ts","calendar_interval":"1h"}}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on non-rollup index target, got %d", c)
	}

	cPutRJ, hdrRJ, _, rawRJ := doR65Req(t, handler, http.MethodPut, "/_rollup/job/job_a",
		`{"index_pattern":"src_orders","rollup_index":"r_dest","cron":"0 * * * * ?","page_size":10,"groups":{"date_histogram":{"field":"ts","calendar_interval":"1h","time_zone":"Canada/Mountain"}},"metrics":[{"field":"price","metrics":["max"]}]}`)
	if cPutRJ != http.StatusOK || !strings.Contains(hdrRJ.Get("Warning"), "America/Edmonton") {
		t.Fatalf("expected 200 with Canada/Mountain warning, got %d hdr=%v %s", cPutRJ, hdrRJ, rawRJ)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_rollup/job/job_a/_start", ""); c != http.StatusOK {
		t.Fatalf("expected 200 starting job_a, got %d", c)
	}
	if c, _, m, _ := doR65Req(t, handler, http.MethodDelete, "/_rollup/job/job_a", ""); c != http.StatusBadRequest || m["acknowledged"] != false {
		t.Fatalf("expected 400 deleting running rollup job, got %d %v", c, m)
	}
	if c, _, _, raw := doR65Req(t, handler, http.MethodDelete, "/_rollup/job/missing_rj", ""); c != http.StatusNotFound || !strings.Contains(raw, "doesn't exist") {
		t.Fatalf("expected 404 doesn't exist, got %d %s", c, raw)
	}
	if c, _, m, _ := doR65Req(t, handler, http.MethodGet, "/_rollup/job/missing_rj", ""); c != http.StatusOK || len(m["jobs"].([]any)) != 0 {
		t.Fatalf("expected 200 empty jobs on GET missing rollup job, got %d %v", c, m)
	}

	// Pre-seeded v1 .timestamp rollup doc evaluation in _rollup_search
	if cJ, _, _, rawJ := doR65Req(t, handler, http.MethodPut, "/_rollup/job/job_v1",
		`{"index_pattern":"src_orders","rollup_index":"v1_rollup_idx","cron":"0 * * * * ?","page_size":10,"groups":{"date_histogram":{"field":"ts","calendar_interval":"1h"}}}`); cJ != http.StatusOK {
		t.Fatalf("PUT job_v1 failed: %d %s", cJ, rawJ)
	}
	_, _, _, _ = doR65Req(t, handler, http.MethodPut, "/v1_rollup_idx/_doc/d1?refresh=true",
		`{"ts.date_histogram.timestamp":"2017-01-01T05:00:00Z","ts.date_histogram._count":3,"_rollup.id":"job_v1"}`)
	cRS, _, mRS, rawRS := doR65Req(t, handler, http.MethodPost, "/v1_rollup_idx/_rollup_search",
		`{"size":0,"aggs":{"histo":{"date_histogram":{"field":"ts","calendar_interval":"1h"}}}}`)
	if cRS != http.StatusOK || len(mRS["aggregations"].(map[string]any)["histo"].(map[string]any)["buckets"].([]any)) != 1 {
		t.Fatalf("expected 1 v1 rollup_search bucket, got %d %s", cRS, rawRS)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/v1_rollup_idx,r_dest/_rollup_search", `{"size":0}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on multi-rollup_search, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_rollup_search", `{"size":0}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on _rollup_search without index, got %d", c)
	}

	// Transform validations + lifecycle + reset + cat
	for _, bad := range []struct {
		path string
		body string
	}{
		{"/_transform/Bad_ID", `{"source":{"index":"src_orders"},"dest":{"index":"tf_d"},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"create_time":1,"source":{"index":"src_orders"},"dest":{"index":"tf_d"},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"version":"8.0.0","source":{"index":"src_orders"},"dest":{"index":"tf_d"},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"source":{"index":"src_orders"},"dest":{"index":"BadDest"},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"source":{"index":"src_orders"},"dest":{"index":"src_orders"},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"source":{"index":"src_orders"},"dest":{"index":"tf_d"},"pivot":{"max_page_search_size":5,"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"source":{"index":"src_orders"},"dest":{"index":"tf_d"},"settings":{"num_failure_retries":-2},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"source":{"index":"src_orders"},"dest":{"index":"tf_d","pipeline":"missing_pipe"},"pivot":{"group_by":{"a":{"terms":{"field":"airline"}}}}}`},
		{"/_transform/tf_bad", `{"source":{"index":"src_orders"},"dest":{"index":"tf_d"},"latest":{"unique_key":["agg_metric"],"sort":"ts"}}`},
	} {
		if c, _, _, raw := doR65Req(t, handler, http.MethodPut, bad.path, bad.body); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on PUT %s (%s), got %d: %s", bad.path, bad.body, c, raw)
		}
	}

	if c, _, _, _ := doR65Req(t, handler, http.MethodGet, "/_transform?size=1001", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on GET /_transform?size=1001, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_transform/_all/_schedule_now", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on _all/_schedule_now, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_transform/_preview", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty preview, got %d", c)
	}

	// Transform with deduce_mappings=false & reset
	if c, _, _, raw := doR65Req(t, handler, http.MethodPut, "/_transform/tf_nodup",
		`{"source":{"index":"src_orders"},"dest":{"index":"tf_dest_nodup"},"settings":{"deduce_mappings":false},"pivot":{"group_by":{"airline":{"terms":{"field":"airline"}}},"aggs":{"max_p":{"max":{"field":"price"}}}}}`); c != http.StatusOK {
		t.Fatalf("PUT tf_nodup failed: %d %s", c, raw)
	}
	_, _, getTF, _ := doR65Req(t, handler, http.MethodGet, "/_transform/tf_nodup", "")
	firstTF := getTF["transforms"].([]any)[0].(map[string]any)
	if _, okSlice := firstTF["source"].(map[string]any)["index"].([]any); !okSlice {
		t.Fatalf("expected source.index array normalization, got %v", firstTF["source"])
	}
	if _, okAggs := firstTF["pivot"].(map[string]any)["aggregations"]; !okAggs {
		t.Fatalf("expected pivot.aggregations normalization, got %v", firstTF["pivot"])
	}
	if c, _, _, raw := doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_preview", `{"source":{}}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 preview with both id & body, got %d %s", c, raw)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_start", ""); c != http.StatusOK {
		t.Fatalf("start tf_nodup failed: %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_start", ""); c != http.StatusConflict {
		t.Fatalf("expected 409 on double start, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_stop?force=true&wait_for_checkpoint=true", ""); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on force+wait_for_checkpoint, got %d", c)
	}
	if c, _, _, raw := doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_update", `{"sync":{"time":{"field":"ts"}}}`); c != http.StatusBadRequest || !strings.Contains(raw, "from [null] to [time]") {
		t.Fatalf("expected 400 changing sync null->time, got %d %s", c, raw)
	}
	cCat, _, _, rawCat := doR65Req(t, handler, http.MethodGet, "/_cat/transforms?v&h=id,version", "")
	if cCat != http.StatusOK || !strings.Contains(rawCat, "8.12.0") {
		t.Fatalf("unexpected /_cat/transforms: %d %s", cCat, rawCat)
	}
	_, _, _, _ = doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_stop", "")
	if c, _, _, _ := doR65Req(t, handler, http.MethodPost, "/_transform/tf_nodup/_reset", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on _reset, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodHead, "/tf_dest_nodup", ""); c != http.StatusNotFound {
		t.Fatalf("expected dest index dropped after reset, got %d", c)
	}

	// Autoscaling, Inference, Shutdown admin APIs
	if c, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_autoscaling/policy/as1", `{"roles":["data_content"]}`); c != http.StatusOK {
		t.Fatalf("expected 200 on PUT autoscaling policy, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodGet, "/_autoscaling/capacity", ""); c != http.StatusOK {
		t.Fatalf("expected 200 on GET /_autoscaling/capacity, got %d", c)
	}
	if c, _, _, _ := doR65Req(t, handler, http.MethodPut, "/_inference/bad_task/id1", `{}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid inference task_type, got %d", c)
	}

	// Legacy template ?template= deprecation warning + GeoIP version + ILM + ES|QL + Migration system_features
	cT, hdrT, _, _ := doR65Req(t, handler, http.MethodPut, "/_template/r65_tpl?template=logs-*",
		`{"index_patterns":["logs-*"]}`)
	if cT != http.StatusOK || hdrT.Get("Warning") == "" {
		t.Fatalf("expected deprecation warning on ?template=, got %d %v", cT, hdrT)
	}
	if cG, _, mG, _ := doR65Req(t, handler, http.MethodPut, "/_ingest/geoip/database/geo1",
		`{"database_file":"GeoLite2-City.mmdb"}`); cG != http.StatusOK || mG["acknowledged"] != true {
		t.Fatalf("expected acknowledged=true on geoip database PUT, got %d %v", cG, mG)
	}
	if cGG, _, mGG, rawGG := doR65Req(t, handler, http.MethodGet, "/_ingest/geoip/database/geo1", ""); cGG != http.StatusOK || !strings.Contains(rawGG, `"version":1`) || mGG["databases"] == nil {
		t.Fatalf("expected version:1 on geoip database GET, got %d %s", cGG, rawGG)
	}
	if cILM, _, mILM, _ := doR65Req(t, handler, http.MethodPost, "/_ilm/migrate_to_data_tiers", `{}`); cILM != http.StatusOK || mILM["removed_legacy_template"] == nil {
		t.Fatalf("expected removed_legacy_template on ILM migrate, got %d %v", cILM, mILM)
	}
	if cEQ, _, _, rawEQ := doR65Req(t, handler, http.MethodPost, "/_query",
		`{"query":"FROM src_orders | SORT @unknown_meta"}`); cEQ != http.StatusBadRequest {
		t.Fatalf("expected 400 on SORT @unknown_meta, got %d %s", cEQ, rawEQ)
	}
	if cEQ2, _, _, rawEQ2 := doR65Req(t, handler, http.MethodPost, "/_query",
		`{"query":"FROM src_orders | STATS c = COUNT(agg_metric)"}`); cEQ2 != http.StatusBadRequest {
		t.Fatalf("expected 400 on aggregate_metric_double STATS, got %d %s", cEQ2, rawEQ2)
	}
	if cMSF, _, mMSF, _ := doR65Req(t, handler, http.MethodPost, "/_migration/system_features", `{}`); cMSF != http.StatusOK || mMSF["accepted"] != true {
		t.Fatalf("expected accepted=true on /_migration/system_features, got %d %v", cMSF, mMSF)
	}
}
