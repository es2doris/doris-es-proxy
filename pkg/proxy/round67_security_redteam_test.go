package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR67RedTeamServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	mb := NewMemoryBackend(false)
	s := NewServer("es_compat", mb, transpiler.TranspilerOptions{})
	t.Cleanup(func() {
		_ = s.Close(context.Background())
	})
	return s, s.Handler()
}

func doR67Req(t *testing.T, h http.Handler, method, target, body string, headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	var reqBody *bytes.Reader
	if body != "" {
		reqBody = bytes.NewReader([]byte(body))
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &parsed)
	}
	return rec.Code, parsed, raw
}

func basicHdrR67(user, pass string) map[string]string {
	tok := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return map[string]string{"Authorization": "Basic " + tok}
}

type failAlterDDLBackendR67 struct {
	*MemoryBackend
	failAlter bool
}

func (f *failAlterDDLBackendR67) ExecDDL(ctx context.Context, ddl string) error {
	if f.failAlter && strings.Contains(strings.ToUpper(ddl), "ALTER TABLE") {
		return errors.New("injected alter ddl failure")
	}
	return f.MemoryBackend.ExecDDL(ctx, ddl)
}

func TestRound67_RedTeam_PutMappingConcurrentDDLAndErrorPropagation(t *testing.T) {
	mb := &failAlterDDLBackendR67{MemoryBackend: NewMemoryBackend(false)}
	s := NewServer("es_compat", mb, transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	h := s.Handler()

	// Create base index.
	code, _, raw := doR67Req(t, h, http.MethodPut, "/r67_map_idx", `{"mappings":{"properties":{"title":{"type":"text"}}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create index failed (%d): %s", code, raw)
	}

	// Inject ALTER DDL failure: PUT /_mapping must fail AND keep old schema unpublished.
	mb.failAlter = true
	code, _, raw = doR67Req(t, h, http.MethodPut, "/r67_map_idx/_mapping", `{"properties":{"evil_unapplied":{"type":"keyword"}}}`, nil)
	if code < 400 {
		t.Fatalf("expected PUT _mapping error when ExecDDL fails, got %d: %s", code, raw)
	}
	s.mu.RLock()
	sc := s.indices["r67_map_idx"]
	s.mu.RUnlock()
	if sc == nil {
		t.Fatalf("expected index schema to remain present")
	}
	if _, leaked := sc.Fields["evil_unapplied"]; leaked {
		t.Fatalf("failed ExecDDL published new field into s.indices before DDL succeeded")
	}

	// Verify validateAndEvolveExistingIndexR61CRUD also withholds schema evolution on DDL error.
	_, err := s.validateAndEvolveExistingIndexR61CRUD(context.Background(), false, "r67_map_idx", sc, []json.RawMessage{json.RawMessage(`{"evil_doc_col":"v"}`)})
	if err == nil {
		t.Fatalf("expected error from validateAndEvolveExistingIndexR61CRUD when ALTER DDL fails")
	}
	s.mu.RLock()
	scAfter := s.indices["r67_map_idx"]
	s.mu.RUnlock()
	if _, leaked := scAfter.Fields["evil_doc_col"]; leaked {
		t.Fatalf("validateAndEvolveExistingIndexR61CRUD published schema despite failed ExecDDL")
	}

	// Now allow DDL and race mapping evolutions against concurrent searches, mappings GETs, and doc writes.
	mb.failAlter = false
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 6; i++ {
				field := fmt.Sprintf("f_%d_%d", id, i)
				_, _, _ = doR67Req(t, h, http.MethodPut, "/r67_map_idx/_mapping", fmt.Sprintf(`{"properties":{%q:{"type":"keyword"}}}`, field), nil)
				_, _, _ = doR67Req(t, h, http.MethodGet, "/r67_map_idx/_mapping", "", nil)
				_, _, _ = doR67Req(t, h, http.MethodPost, "/r67_map_idx/_doc", fmt.Sprintf(`{"title":"hello","%s":"val"}`, field), nil)
				_, _, _ = doR67Req(t, h, http.MethodGet, "/r67_map_idx/_search", `{"query":{"match_all":{}}}`, nil)
			}
		}(g)
	}
	wg.Wait()
}

func TestRound67_RedTeam_InferenceAnalyticsSQLMapCloneRace(t *testing.T) {
	_, h := newR67RedTeamServer(t)

	code, _, raw := doR67Req(t, h, http.MethodPut, "/r67_race_sql", `{"mappings":{"properties":{"name":{"type":"keyword"}}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create index failed (%d): %s", code, raw)
	}
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_inference/text_embedding/r67_inf", `{"service":"openai","service_settings":{"api_key":"sk-secret"}}`, nil)
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_application/analytics/r67_coll", `{}`, nil)
	code, sqlResp, sqlRaw := doR67Req(t, h, http.MethodPost, "/_sql", `{"query":"SELECT name FROM r67_race_sql","wait_for_completion_timeout":"1s"}`, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_sql failed (%d): %s", code, sqlRaw)
	}
	sqlID, _ := sqlResp["id"].(string)
	if sqlID == "" {
		t.Fatalf("expected async sql id, got %s", sqlRaw)
	}

	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				_, _, _ = doR67Req(t, h, http.MethodGet, "/_inference/r67_inf", "", nil)
				_, _, _ = doR67Req(t, h, http.MethodPut, "/_inference/text_embedding/r67_inf", fmt.Sprintf(`{"service":"openai","service_settings":{"api_key":"sk-%d-%d"}}`, worker, i), nil)
				_, _, _ = doR67Req(t, h, http.MethodGet, "/_application/analytics/r67_coll", "", nil)
				_, _, _ = doR67Req(t, h, http.MethodPut, "/_application/analytics/r67_coll", `{}`, nil)
				_, _, _ = doR67Req(t, h, http.MethodGet, "/_sql/async_search/"+sqlID, "", nil)
			}
		}(g)
	}
	wg.Wait()
}

func TestRound67_RedTeam_OpaquePITAndSQLHandlesAndPrincipalIsolation(t *testing.T) {
	s, h := newR67RedTeamServer(t)

	// Configure users secadmin, alice & bob with read access.
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/role/r67_reader", `{"cluster":["monitor"],"indices":[{"names":["*"],"privileges":["all"]}]}`, nil)
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/user/secadmin", `{"password":"SecAdmin123!","roles":["superuser"]}`, nil)
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/user/alice", `{"password":"AlicePass123!","roles":["r67_reader"]}`, basicHdrR67("secadmin", "SecAdmin123!"))
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/user/bob", `{"password":"BobPass123!","roles":["r67_reader"]}`, basicHdrR67("secadmin", "SecAdmin123!"))
	_, _, _ = doR67Req(t, h, http.MethodPut, "/r67_pit_idx", `{"mappings":{"properties":{"msg":{"type":"keyword"}}}}`, basicHdrR67("alice", "AlicePass123!"))
	_, _, _ = doR67Req(t, h, http.MethodPut, "/r67_pit_idx/_doc/1", `{"msg":"a"}`, basicHdrR67("alice", "AlicePass123!"))
	_, _, _ = doR67Req(t, h, http.MethodPut, "/r67_pit_idx/_doc/2", `{"msg":"b"}`, basicHdrR67("alice", "AlicePass123!"))

	// Alice opens 2 PITs: tokens must be unpredictable (not sequential #1/#2) and decode via decodePITIndex.
	_, pit1Resp, raw1 := doR67Req(t, h, http.MethodPost, "/r67_pit_idx/_pit?keep_alive=1m", ``, basicHdrR67("alice", "AlicePass123!"))
	_, pit2Resp, raw2 := doR67Req(t, h, http.MethodPost, "/r67_pit_idx/_pit?keep_alive=1m", ``, basicHdrR67("alice", "AlicePass123!"))
	pit1, _ := pit1Resp["id"].(string)
	pit2, _ := pit2Resp["id"].(string)
	if pit1 == "" || pit2 == "" || pit1 == pit2 {
		t.Fatalf("expected distinct opaque PIT IDs, got %q and %q (%s / %s)", pit1, pit2, raw1, raw2)
	}
	dec1, _ := base64.RawURLEncoding.DecodeString(pit1)
	if strings.HasSuffix(string(dec1), "#1") || !strings.HasPrefix(string(dec1), "pit:r67_pit_idx#") || len(dec1) < len("pit:r67_pit_idx#")+24 {
		t.Fatalf("expected random PIT token with pit:r67_pit_idx# prefix and >= 24 chars, got decoded %q", string(dec1))
	}
	if sc, sResp, sRaw := doR67Req(t, h, http.MethodPost, "/_search", fmt.Sprintf(`{"pit":{"id":%q,"keep_alive":"1m"}}`, pit1), basicHdrR67("alice", "AlicePass123!")); sc != http.StatusOK || sResp["pit_id"] != pit1 {
		t.Fatalf("expected PIT search to succeed with opaque pit1, got %d: %s", sc, sRaw)
	}

	// Bob tries to delete Alice's PIT directly and via DELETE /_pit/_all: must fail / preserve Alice's PIT!
	code, delBobResp, _ := doR67Req(t, h, http.MethodDelete, "/_pit", fmt.Sprintf(`{"id":%q}`, pit1), basicHdrR67("bob", "BobPass123!"))
	if code != http.StatusOK || delBobResp["succeeded"] != false {
		t.Fatalf("expected bob's delete of alice's PIT to fail cleanly, got %d: %+v", code, delBobResp)
	}
	_, _, _ = doR67Req(t, h, http.MethodDelete, "/_pit/_all", "", basicHdrR67("bob", "BobPass123!"))
	s.mu.RLock()
	stillExists := s.pits[pit1] != nil
	s.mu.RUnlock()
	if !stillExists {
		t.Fatalf("bob's DELETE /_pit/_all deleted alice's PIT")
	}

	// Alice deletes her own PIT -> succeeds.
	code, delAliceResp, _ := doR67Req(t, h, http.MethodDelete, "/_pit", fmt.Sprintf(`{"id":%q}`, pit1), basicHdrR67("alice", "AlicePass123!"))
	if code != http.StatusOK || delAliceResp["succeeded"] != true {
		t.Fatalf("expected alice to delete own PIT, got %d: %+v", code, delAliceResp)
	}

	// Alice runs paginated SQL query -> non-sequential sql_ / sqlcur_ IDs isolated from Bob!
	code, sqlResp, sqlRaw := doR67Req(t, h, http.MethodPost, "/_sql", `{"query":"SELECT msg FROM r67_pit_idx ORDER BY msg","fetch_size":1,"wait_for_completion_timeout":"1s"}`, basicHdrR67("alice", "AlicePass123!"))
	if code != http.StatusOK {
		t.Fatalf("alice SQL failed (%d): %s", code, sqlRaw)
	}
	sqlID, _ := sqlResp["id"].(string)
	cursorID, _ := sqlResp["cursor"].(string)
	if !strings.HasPrefix(sqlID, "sql_") || len(sqlID) < 20 {
		t.Fatalf("expected opaque sql_ token, got %q", sqlID)
	}
	if !strings.HasPrefix(cursorID, "sqlcur_") || len(cursorID) < 24 || strings.Contains(cursorID, sqlID) {
		t.Fatalf("expected opaque sqlcur_ token decoupled from sqlID, got %q", cursorID)
	}

	// Bob cannot read, status-check, delete, close, or consume Alice's SQL async search or cursor.
	if c, _, _ := doR67Req(t, h, http.MethodGet, "/_sql/async/"+sqlID, "", basicHdrR67("bob", "BobPass123!")); c != http.StatusNotFound {
		t.Fatalf("expected 404 when bob accesses alice's sql async search, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodGet, "/_sql/async/status/"+sqlID, "", basicHdrR67("bob", "BobPass123!")); c != http.StatusNotFound {
		t.Fatalf("expected 404 when bob checks alice's sql status, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodDelete, "/_sql/async/"+sqlID, "", basicHdrR67("bob", "BobPass123!")); c != http.StatusNotFound {
		t.Fatalf("expected 404 when bob deletes alice's sql async search, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_sql/close", fmt.Sprintf(`{"cursor":%q}`, cursorID), basicHdrR67("bob", "BobPass123!")); c != http.StatusNotFound {
		t.Fatalf("expected 404 when bob closes alice's sql cursor, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_sql", fmt.Sprintf(`{"cursor":%q}`, cursorID), basicHdrR67("bob", "BobPass123!")); c != http.StatusNotFound {
		t.Fatalf("expected 404 when bob consumes alice's sql cursor, got %d", c)
	}

	// Alice can still consume her own cursor and read her async search cleanly (and __owner_principal is not leaked).
	c, curResp, curRaw := doR67Req(t, h, http.MethodPost, "/_sql", fmt.Sprintf(`{"cursor":%q}`, cursorID), basicHdrR67("alice", "AlicePass123!"))
	if c != http.StatusOK || curResp["__owner_principal"] != nil {
		t.Fatalf("expected alice to consume cursor without internal leak, got %d: %s", c, curRaw)
	}
	c, asyncResp, asyncRaw := doR67Req(t, h, http.MethodGet, "/_sql/async/"+sqlID, "", basicHdrR67("alice", "AlicePass123!"))
	if c != http.StatusOK || asyncResp["__owner_principal"] != nil {
		t.Fatalf("expected alice to read async search without internal leak, got %d: %s", c, asyncRaw)
	}
}

func TestRound67_RedTeam_CryptographicCredentialsAndEpochInvalidation(t *testing.T) {
	s, h := newR67RedTeamServer(t)

	// 1. User creation stores PBKDF2 hash, strips secrets on GET, bumps epoch.
	ep0 := s.SecurityEpoch()
	c, _, raw := doR67Req(t, h, http.MethodPut, "/_security/role/limited_role", `{"cluster":["monitor"],"indices":[{"names":["logs-*"],"privileges":["read"]}]}`, nil)
	if c != http.StatusOK {
		t.Fatalf("put role failed (%d): %s", c, raw)
	}
	if s.SecurityEpoch() <= ep0 {
		t.Fatalf("expected SecurityEpoch bump on PUT role")
	}

	ep1 := s.SecurityEpoch()
	c, _, raw = doR67Req(t, h, http.MethodPut, "/_security/user/alice", `{"password":"StrongPassword!99","roles":["limited_role"]}`, nil)
	if c != http.StatusOK || s.SecurityEpoch() <= ep1 {
		t.Fatalf("put user failed or did not bump epoch (%d): %s", c, raw)
	}
	s.mu.RLock()
	uRec := s.securityUsers["alice"]
	pb, _ := uRec["__password_pbkdf2"].(string)
	_, hasPlain := uRec["password"]
	_, hasSHA := uRec["__password_sha256"]
	s.mu.RUnlock()
	if !strings.HasPrefix(pb, "$pbkdf2-sha256$4096$") || hasPlain || hasSHA {
		t.Fatalf("expected PBKDF2-SHA256 storage without plaintext/sha256, got %+v", uRec)
	}
	c, uGet, uRaw := doR67Req(t, h, http.MethodGet, "/_security/user/alice", "", basicHdrR67("alice", "StrongPassword!99"))
	if c != http.StatusOK {
		t.Fatalf("GET user failed (%d): %s", c, uRaw)
	}
	if strings.Contains(uRaw, "StrongPassword") || strings.Contains(uRaw, "$pbkdf2-sha256$") {
		t.Fatalf("GET /_security/user leaked secret/hash: %+v", uGet)
	}

	// 2. Superuser bootstrap for admin-only credential minting.
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/user/secadmin", `{"password":"AdminPassword!99","roles":["superuser"]}`, basicHdrR67("alice", "StrongPassword!99"))
	// Wait: alice shouldn't be able to create superuser! Verify 403 when RBAC blocks alice.
	cAliceCreate, _, _ := doR67Req(t, h, http.MethodPut, "/_security/user/secadmin2", `{"password":"x","roles":["superuser"]}`, basicHdrR67("alice", "StrongPassword!99"))
	if cAliceCreate != http.StatusForbidden {
		t.Fatalf("expected 403 when limited user creates another user, got %d", cAliceCreate)
	}

	// Grant secadmin via static admin header after SetAuth, then unset or add directly for test setup.
	s.mu.Lock()
	s.securityUsers["secadmin"] = map[string]any{
		"username":          "secadmin",
		"roles":             []string{"superuser"},
		"enabled":           true,
		"__password_pbkdf2": hashSecuritySecretPBKDF2R67("AdminPassword!99"),
	}
	s.mu.Unlock()

	// 3. API key creation uses random CSPRNG secrets & no plaintext api_key in memory.
	epBeforeKey := s.SecurityEpoch()
	c, akResp, akRaw := doR67Req(t, h, http.MethodPost, "/_security/api_key", `{"name":"alice-key"}`, basicHdrR67("alice", "StrongPassword!99"))
	if c != http.StatusOK || s.SecurityEpoch() <= epBeforeKey {
		t.Fatalf("api_key creation failed or missed epoch bump (%d): %s", c, akRaw)
	}
	keyID, _ := akResp["id"].(string)
	secret, _ := akResp["api_key"].(string)
	encoded, _ := akResp["encoded"].(string)
	if strings.HasPrefix(keyID, "key-") || strings.HasPrefix(secret, "secret-") || len(secret) < 32 {
		t.Fatalf("expected CSPRNG api_key ID/secret, got id=%q secret=%q", keyID, secret)
	}
	s.mu.RLock()
	akStored := s.securityAPIKeys[keyID]
	_, hasPlainAK := akStored["api_key"]
	akPB, _ := akStored["__secret_pbkdf2"].(string)
	s.mu.RUnlock()
	if hasPlainAK || !strings.HasPrefix(akPB, "$pbkdf2-sha256$4096$") {
		t.Fatalf("expected hashed __secret_pbkdf2 without plaintext api_key in store: %+v", akStored)
	}
	// Authenticated request with ApiKey works, and GET _security/api_key never leaks secret.
	c, authResp, _ := doR67Req(t, h, http.MethodGet, "/_security/_authenticate", "", map[string]string{"Authorization": "ApiKey " + encoded})
	if c != http.StatusOK || authResp["username"] != "alice" {
		t.Fatalf("expected ApiKey auth as alice, got %d: %+v", c, authResp)
	}
	c, _, queryAKRaw := doR67Req(t, h, http.MethodGet, "/_security/api_key?id="+keyID, "", basicHdrR67("secadmin", "AdminPassword!99"))
	if c != http.StatusOK || strings.Contains(queryAKRaw, secret) || strings.Contains(queryAKRaw, "$pbkdf2-sha256$") {
		t.Fatalf("GET /_security/api_key leaked secret (%d): %s", c, queryAKRaw)
	}

	// 4. API key _grant checks password, access_token, and run_as!
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/api_key/grant", `{"grant_type":"password","username":"alice","api_key":{"name":"x"}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing password in grant, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/api_key/grant", `{"grant_type":"password","username":"alice","password":"WrongPassword","api_key":{"name":"x"}}`, nil); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password in grant, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/api_key/grant", `{"grant_type":"password","username":"alice","password":"StrongPassword!99","run_as":"secadmin","api_key":{"name":"esc"}}`, nil); c != http.StatusForbidden {
		t.Fatalf("expected 403 on unauthorized run_as privilege escalation, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/api_key/grant", `{"grant_type":"access_token","access_token":"forged-tok","api_key":{"name":"x"}}`, nil); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 on forged access_token in grant, got %d", c)
	}

	// 5. OAuth2 requires real credentials & hashes tokens in session map.
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"client_credentials"}`, nil); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 on anonymous oauth2 client_credentials when security configured, got %d", c)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"alice","password":"bad"}`, nil); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad oauth2 password grant, got %d", c)
	}
	c, oaResp, oaRaw := doR67Req(t, h, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"alice","password":"StrongPassword!99"}`, nil)
	if c != http.StatusOK {
		t.Fatalf("valid oauth2 password grant failed (%d): %s", c, oaRaw)
	}
	accTok, _ := oaResp["access_token"].(string)
	refTok, _ := oaResp["refresh_token"].(string)
	if accTok == "doris-oauth2-access-token" || len(accTok) < 32 {
		t.Fatalf("expected random oauth2 access_token, got %q", accTok)
	}
	// Granting API key using issued access_token succeeds for alice!
	c, gTokResp, gTokRaw := doR67Req(t, h, http.MethodPost, "/_security/api_key/grant", fmt.Sprintf(`{"grant_type":"access_token","access_token":%q,"api_key":{"name":"via-oauth"}}`, accTok), nil)
	if c != http.StatusOK || gTokResp["api_key"] == nil {
		t.Fatalf("expected valid oauth2 access_token to mint api_key, got %d: %s", c, gTokRaw)
	}
	// Refresh token rotation invalidates previous refresh token.
	c, oaRef2, _ := doR67Req(t, h, http.MethodPost, "/_security/oauth2/token", fmt.Sprintf(`{"grant_type":"refresh_token","refresh_token":%q}`, refTok), nil)
	if c != http.StatusOK || oaRef2["access_token"] == accTok {
		t.Fatalf("expected refresh_token rotation, got %d: %+v", c, oaRef2)
	}
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/oauth2/token", fmt.Sprintf(`{"grant_type":"refresh_token","refresh_token":%q}`, refTok), nil); c != http.StatusUnauthorized {
		t.Fatalf("expected old rotated refresh_token to fail, got %d", c)
	}
	// Revoke via DELETE and verify invalidated_tokens == 1.
	accTok2, _ := oaRef2["access_token"].(string)
	c, delOAResp, _ := doR67Req(t, h, http.MethodDelete, "/_security/oauth2/token", fmt.Sprintf(`{"token":%q}`, accTok2), basicHdrR67("secadmin", "AdminPassword!99"))
	if c != http.StatusOK || delOAResp["invalidated_tokens"] != float64(1) {
		t.Fatalf("expected oauth2 token revocation count 1, got %d: %+v", c, delOAResp)
	}

	// 6. Service tokens: low-priv alice rejected (403), secadmin succeeds, stored as PBKDF2, Bearer auth works, GET strips secret.
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_security/service/elastic/fleet-server/credential/token/svc1", ``, basicHdrR67("alice", "StrongPassword!99")); c != http.StatusForbidden {
		t.Fatalf("expected 403 when limited user creates service token, got %d", c)
	}
	c, svcResp, svcRaw := doR67Req(t, h, http.MethodPost, "/_security/service/elastic/fleet-server/credential/token/svc1", ``, basicHdrR67("secadmin", "AdminPassword!99"))
	if c != http.StatusOK {
		t.Fatalf("service token create failed (%d): %s", c, svcRaw)
	}
	tokObj, _ := svcResp["token"].(map[string]any)
	svcVal, _ := tokObj["value"].(string)
	if svcVal == "" || strings.HasPrefix(svcVal, "aae_doris_service_token_") || !strings.HasPrefix(svcVal, "aae_") {
		t.Fatalf("expected CSPRNG service token value, got %q", svcVal)
	}
	// Verify Bearer auth succeeds with the minted token.
	c, _, svcGetRaw := doR67Req(t, h, http.MethodGet, "/_security/service/elastic/fleet-server/credential", "", map[string]string{"Authorization": "Bearer " + svcVal})
	if c != http.StatusOK || strings.Contains(svcGetRaw, svcVal) || strings.Contains(svcGetRaw, "$pbkdf2-sha256$") {
		t.Fatalf("service credential GET failed or leaked token (%d): %s", c, svcGetRaw)
	}

	// 7. Disabling user bumps epoch and locks out future auth + invalidates api_key/bearer!
	epBeforeDis := s.SecurityEpoch()
	c, _, _ = doR67Req(t, h, http.MethodPut, "/_security/user/alice/_disable", ``, basicHdrR67("secadmin", "AdminPassword!99"))
	if c != http.StatusOK || s.SecurityEpoch() <= epBeforeDis {
		t.Fatalf("disable user failed or missed epoch bump")
	}
	if c, _, _ := doR67Req(t, h, http.MethodGet, "/_security/_authenticate", "", map[string]string{"Authorization": "ApiKey " + encoded}); c != http.StatusUnauthorized {
		t.Fatalf("expected disabled user's ApiKey to fail auth, got %d", c)
	}
}

func TestRound67_RedTeam_SecretRedactionMassAssignmentAndOpenRoot(t *testing.T) {
	_, h := newR67RedTeamServer(t)

	// 1. Connector secret GET strips value.
	c, _, raw := doR67Req(t, h, http.MethodPost, "/_connector/_secret", `{"id":"r67-sec","name":"db-pw","value":"super-secret-db-pass"}`, nil)
	if c != http.StatusCreated {
		t.Fatalf("create connector secret failed (%d): %s", c, raw)
	}
	c, secGet, secRaw := doR67Req(t, h, http.MethodGet, "/_connector/_secret/r67-sec", "", nil)
	if c != http.StatusOK || secGet["value"] != nil || secGet["__value"] != nil || secGet["has_value"] != true || strings.Contains(secRaw, "super-secret-db-pass") {
		t.Fatalf("expected redacted connector secret GET, got %d: %s", c, secRaw)
	}

	// 2. Inference PUT & GET redact service_settings secrets.
	c, putInf, putInfRaw := doR67Req(t, h, http.MethodPut, "/_inference/text_embedding/r67-ep", `{
		"service":"openai",
		"service_settings":{"api_key":"sk-live-secret-999","token":"tok-999","model_id":"text-embedding-3-small"}
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("PUT inference failed (%d): %s", c, putInfRaw)
	}
	if strings.Contains(putInfRaw, "sk-live-secret-999") || strings.Contains(putInfRaw, "tok-999") {
		t.Fatalf("PUT inference echoed sensitive service_settings: %+v", putInf)
	}
	c, getInf, getInfRaw := doR67Req(t, h, http.MethodGet, "/_inference/r67-ep", "", nil)
	if c != http.StatusOK || strings.Contains(getInfRaw, "sk-live-secret-999") || strings.Contains(getInfRaw, "tok-999") {
		t.Fatalf("GET inference leaked sensitive service_settings (%d): %+v / %s", c, getInf, getInfRaw)
	}
	if !strings.Contains(getInfRaw, `"****"`) || !strings.Contains(getInfRaw, "text-embedding-3-small") {
		t.Fatalf("expected masked secrets and preserved model_id in GET inference, got %s", getInfRaw)
	}

	// 3. Connector _last_sync ignores non-allowlisted mass-assignment keys.
	c, _, raw = doR67Req(t, h, http.MethodPut, "/_connector/r67-conn", `{"name":"c1","service_type":"s3","index_name":"idx-c1"}`, nil)
	if c != http.StatusCreated && c != http.StatusOK {
		t.Fatalf("create connector failed (%d): %s", c, raw)
	}
	c, _, raw = doR67Req(t, h, http.MethodPost, "/_connector/r67-conn/_last_sync", `{
		"last_sync_status":"completed",
		"last_sync_doc_count":42,
		"is_native":true,
		"index_name":"hijacked-idx",
		"__proto_pollute":"bad"
	}`, nil)
	if c != http.StatusOK {
		t.Fatalf("POST _last_sync failed (%d): %s", c, raw)
	}
	c, connGet, connRaw := doR67Req(t, h, http.MethodGet, "/_connector/r67-conn", "", nil)
	if c != http.StatusOK {
		t.Fatalf("GET connector failed (%d): %s", c, connRaw)
	}
	if connGet["last_sync_status"] != "completed" || connGet["index_name"] != "idx-c1" || connGet["is_native"] != false || connGet["__proto_pollute"] != nil {
		t.Fatalf("mass-assignment mutated connector fields: %+v", connGet)
	}

	// 4. persistFSSnapshotsDiskPayloadR65 via os.OpenRoot refuses symlinks outside root and creates 0600 catalog.
	tmpRoot := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "outside.json")
	if err := os.WriteFile(outsideTarget, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	repoDir := filepath.Join(tmpRoot, "repo")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(tmpRoot)
	if err != nil {
		resolvedRoot = tmpRoot
	}
	repoObj := map[string]any{"type": "fs", "settings": map[string]any{"location": repoDir}}
	persistFSSnapshotsDiskPayloadR65(repoObj, []byte(`{"ok":true}`), []string{resolvedRoot})
	catPath := filepath.Join(repoDir, proxySnapshotCatalogFileR64)
	info, err := os.Lstat(catPath)
	if err != nil {
		t.Fatalf("expected snapshot catalog inside root: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("expected 0600 permissions on catalog file, got %v", info.Mode().Perm())
	}

	// Replace catalog with symlink pointing outside root -> must refuse overwrite!
	_ = os.Remove(catPath)
	if err := os.Symlink(outsideTarget, catPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	persistFSSnapshotsDiskPayloadR65(repoObj, []byte(`{"pwn":true}`), []string{resolvedRoot})
	gotOutside, err := os.ReadFile(outsideTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotOutside) != "ORIGINAL" {
		t.Fatalf("symlink TOCTOU overwrote outside target: %q", string(gotOutside))
	}
}

func TestRound67_RedTeam_TestAdminFixtureGateAndFailClosedRBAC(t *testing.T) {
	s, h := newR67RedTeamServer(t)

	// Default server must reject hardcoded test_admin fixture even when open!
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_monitoring/bulk", `{}`, basicHdrR67("test_admin", "x-pack-test-password")); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 for test_admin when AllowTestFixtureAuth is false, got %d", c)
	}

	// Create restricted user & role.
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/role/logs_only", `{
		"cluster":["monitor"],
		"indices":[{"names":["logs-*"],"privileges":["read"]}],
		"applications":[{"application":"kibana","privileges":["read"],"resources":["space:default"]}]
	}`, nil)
	_, _, _ = doR67Req(t, h, http.MethodPut, "/_security/user/reader", `{"password":"ReaderPass1!","roles":["logs_only"]}`, nil)

	// Once dynamic security exists: anonymous /_monitoring/bulk must fail closed (401).
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_monitoring/bulk", `{}`, nil); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 on anonymous /_monitoring/bulk with dynamic users configured, got %d", c)
	}

	// And test_admin remains rejected!
	if c, _, _ := doR67Req(t, h, http.MethodPost, "/_monitoring/bulk", `{}`, basicHdrR67("test_admin", "x-pack-test-password")); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 for test_admin with dynamic users configured, got %d", c)
	}

	// _terms_enum index privilege entry with nil/missing "privileges" must fail closed.
	if entryPrivilegesAllowTermsEnumR65(map[string]any{"names": []any{"*"}}) {
		t.Fatalf("expected entryPrivilegesAllowTermsEnumR65 to fail closed when privileges is omitted")
	}

	// _terms_enum fail-closed on empty Authorization when dynamic security exists.
	_, _, _ = doR67Req(t, h, http.MethodPut, "/logs-1", `{"mappings":{"properties":{"host":{"type":"keyword"}}}}`, basicHdrR67("reader", "ReaderPass1!"))
	_, _, _ = doR67Req(t, h, http.MethodPut, "/logs-1/_doc/1", `{"host":"web-01"}`, nil)
	targets, _ := s.resolveAuthorizedTermsEnumTargetsAndFiltersR66(&http.Request{Header: http.Header{}}, "logs-1", []string{"logs-1"}, nil, "host")
	if len(targets) != 0 {
		t.Fatalf("expected fail-closed 0 authorized targets for anonymous _terms_enum with dynamic security configured, got %v", targets)
	}

	// Verify AllowTestFixtureAuth flag works ONLY when true & open.
	s2, _ := newR67RedTeamServer(t)
	s2.mu.RLock()
	if s2.matchesTestFixtureAdminLockedR66("test_admin:x-pack-test-password", "", "") {
		s2.mu.RUnlock()
		t.Fatalf("expected matchesTestFixtureAdminLockedR66 false by default")
	}
	s2.mu.RUnlock()
	s2.SetAllowTestFixtureAuth(true)
	s2.mu.RLock()
	if !s2.matchesTestFixtureAdminLockedR66("test_admin:x-pack-test-password", "", "") {
		s2.mu.RUnlock()
		t.Fatalf("expected matchesTestFixtureAdminLockedR66 true when AllowTestFixtureAuth enabled")
	}
	s2.mu.RUnlock()

	// Add admin user to verify HTTP RBAC introspection + profile APIs alongside direct handler checks for reader.
	s.mu.Lock()
	s.securityUsers["secadmin"] = map[string]any{
		"username":          "secadmin",
		"roles":             []string{"superuser"},
		"enabled":           true,
		"__password_pbkdf2": hashSecuritySecretPBKDF2R67("AdminPass1!"),
	}
	s.mu.Unlock()
	s.bumpSecurityEpoch()

	// Real RBAC evaluation on POST /_security/user/_has_privileges (reader directly via handleSecurityAPI AND secadmin querying user/reader/_has_privileges).
	privReqBody := `{
		"cluster":["monitor","manage"],
		"index":[
			{"names":["logs-1"],"privileges":["read","write"]},
			{"names":["secrets-1"],"privileges":["read"]}
		],
		"application":[
			{"application":"kibana","privileges":["read","all"],"resources":["space:default"]}
		]
	}`
	hpReq := httptest.NewRequest(http.MethodPost, "/_security/user/_has_privileges", strings.NewReader(privReqBody))
	hpReq.Header.Set("Authorization", basicHdrR67("reader", "ReaderPass1!")["Authorization"])
	hpRec := httptest.NewRecorder()
	s.handleSecurityAPI(hpRec, hpReq, []string{"_security", "user", "_has_privileges"})
	var hp map[string]any
	_ = json.Unmarshal(hpRec.Body.Bytes(), &hp)
	if hpRec.Code != http.StatusOK || hp["has_all_requested"] != false {
		t.Fatalf("expected real RBAC _has_privileges with has_all_requested=false, got %d: %s", hpRec.Code, hpRec.Body.String())
	}
	clMap, _ := hp["cluster"].(map[string]any)
	if clMap["monitor"] != true || clMap["manage"] != false {
		t.Fatalf("unexpected cluster privs for reader: %+v", clMap)
	}
	idxMap, _ := hp["index"].(map[string]any)
	logsPrivs, _ := idxMap["logs-1"].(map[string]any)
	secPrivs, _ := idxMap["secrets-1"].(map[string]any)
	if logsPrivs["read"] != true || logsPrivs["write"] != false || secPrivs["read"] != false {
		t.Fatalf("unexpected index privs for reader: %+v", idxMap)
	}
	c, hpAdmin, hpAdminRaw := doR67Req(t, h, http.MethodPost, "/_security/user/reader/_has_privileges", privReqBody, basicHdrR67("secadmin", "AdminPass1!"))
	if c != http.StatusOK || hpAdmin["has_all_requested"] != false || hpAdmin["username"] != "reader" {
		t.Fatalf("expected admin target user _has_privileges to evaluate reader's roles, got %d: %s", c, hpAdminRaw)
	}

	// GET /_security/user/_privileges returns reader's real cluster privs (NOT superuser "all").
	upReq := httptest.NewRequest(http.MethodGet, "/_security/user/_privileges", nil)
	upReq.Header.Set("Authorization", basicHdrR67("reader", "ReaderPass1!")["Authorization"])
	upRec := httptest.NewRecorder()
	s.handleSecurityAPI(upRec, upReq, []string{"_security", "user", "_privileges"})
	if upRec.Code != http.StatusOK || strings.Contains(upRec.Body.String(), `"all"`) {
		t.Fatalf("expected non-superuser privileges for reader, got %d: %s", upRec.Code, upRec.Body.String())
	}

	// Profile _has_privileges (both /{uid}/_has_privileges and /_has_privileges) also enforces reader's role rather than blind true!
	_, profAct, profRaw := doR67Req(t, h, http.MethodPut, "/_security/profile/_activate", `{"username":"reader","roles":["logs_only"]}`, basicHdrR67("secadmin", "AdminPass1!"))
	uid, _ := profAct["uid"].(string)
	if uid == "" {
		t.Fatalf("expected profile uid on _activate, got %s", profRaw)
	}
	_, profHP, profHPRaw := doR67Req(t, h, http.MethodPost, "/_security/profile/"+uid+"/_has_privileges", `{"cluster":["monitor","manage"]}`, basicHdrR67("secadmin", "AdminPass1!"))
	if profHP["has_all_requested"] != false {
		t.Fatalf("expected profile _has_privileges to evaluate real roles, got %s", profHPRaw)
	}
	_, profBulkHP, profBulkHPRaw := doR67Req(t, h, http.MethodPost, "/_security/profile/_has_privileges", fmt.Sprintf(`{"uids":[%q],"privileges":{"cluster":["manage"]}}`, uid), basicHdrR67("secadmin", "AdminPass1!"))
	if hpUIDs, _ := profBulkHP["has_privilege_uids"].([]any); len(hpUIDs) != 0 {
		t.Fatalf("expected bulk profile _has_privileges to exclude reader missing cluster:manage, got %s", profBulkHPRaw)
	}
}

func TestRound67_RedTeam_BoundedRegexAsyncSemAndAdminStoreCaps(t *testing.T) {
	s, h := newR67RedTeamServer(t)

	// 1. Runtime regex calls reject over-length patterns cleanly without panic/hang.
	hugePat := strings.Repeat("a", 8192)
	c, _, _ := doR67Req(t, h, http.MethodPost, "/_esql", fmt.Sprintf(`{"query":"FROM dummy | WHERE msg RLIKE %q"}`, hugePat), nil)
	if c >= 500 {
		t.Fatalf("expected graceful non-5xx on oversized ESQL RLIKE regex, got %d", c)
	}
	ex, err := evalEQLExpr(&eqlBinExpr{op: "regex", left: &eqlLitExpr{val: "abc"}, right: &eqlLitExpr{val: hugePat}}, map[string]any{})
	if err == nil || ex != nil {
		t.Fatalf("expected error on oversized EQL regex, got val=%v err=%v", ex, err)
	}

	// 2. Async task semaphore bounds concurrent background tasks with 429 and releases slots on exit.
	var acquired int
	for acquired < 1024 && s.acquireAsyncTaskSlot() {
		acquired++
	}
	if acquired == 0 || acquired >= 1024 {
		t.Fatalf("expected bounded async task slot count between 1 and 1023, got %d", acquired)
	}
	taskReq := httptest.NewRequest(http.MethodPost, "/_reindex?wait_for_completion=false", strings.NewReader(`{}`))
	taskRec := httptest.NewRecorder()
	execRan := false
	s.launchAsyncTaskRound60(taskRec, taskReq, []byte(`{}`), "indices:data/write/reindex", "reindex", 0, func(w http.ResponseWriter, r *http.Request) {
		execRan = true
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	if execRan || taskRec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when async task slots saturated, got execRan=%v code=%d body=%s", execRan, taskRec.Code, taskRec.Body.String())
	}
	for i := 0; i < acquired; i++ {
		s.releaseAsyncTaskSlot()
	}

	// Verify real launched task completes with bounded timeout context and releases its slot.
	doneCh := make(chan struct{})
	taskRecOK := httptest.NewRecorder()
	s.launchAsyncTaskRound60(taskRecOK, taskReq, []byte(`{}`), "indices:data/write/reindex", "reindex", 0, func(w http.ResponseWriter, r *http.Request) {
		defer close(doneCh)
		if _, hasDeadline := r.Context().Deadline(); !hasDeadline {
			t.Errorf("expected bounded timeout deadline on detached async task context")
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	if taskRecOK.Code != http.StatusOK {
		t.Fatalf("expected 200 async task launch after slot release, got code=%d body=%s", taskRecOK.Code, taskRecOK.Body.String())
	}
	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("async task did not complete in time")
	}
	// Verify all slots are recoverable (no leaked slot).
	time.Sleep(20 * time.Millisecond)
	var reacquired int
	for reacquired < acquired && s.acquireAsyncTaskSlot() {
		reacquired++
	}
	if reacquired != acquired {
		t.Fatalf("async task slot leaked: expected %d slots back, got %d", acquired, reacquired)
	}
	for i := 0; i < reacquired; i++ {
		s.releaseAsyncTaskSlot()
	}

	// 3. Admin store cap (4096) returns 429 on 4097th creation while allowing existing key update.
	s.mu.Lock()
	if s.fleetSecrets == nil {
		s.fleetSecrets = make(map[string]map[string]any)
	}
	for i := 0; i < maxAdminStoreEntriesR67; i++ {
		s.fleetSecrets[fmt.Sprintf("pre-%d", i)] = map[string]any{"id": fmt.Sprintf("pre-%d", i), "__value": "v"}
	}
	if s.watches == nil {
		s.watches = make(map[string]map[string]any)
	}
	for i := 0; i < maxAdminStoreEntriesR67; i++ {
		s.watches[fmt.Sprintf("w-%d", i)] = map[string]any{"_id": fmt.Sprintf("w-%d", i), "_version": int64(1)}
	}
	if s.connectorSyncJobs == nil {
		s.connectorSyncJobs = make(map[string]map[string]any)
	}
	s.connectors["conn-cap"] = map[string]any{"id": "conn-cap", "index_name": "idx", "service_type": "s3"}
	for i := 0; i < maxAdminStoreEntriesR67; i++ {
		s.connectorSyncJobs[fmt.Sprintf("sj-%d", i)] = map[string]any{"id": fmt.Sprintf("sj-%d", i), "created_at": fmt.Sprintf("2026-01-01T00:00:%02dZ", i%60)}
	}
	s.mu.Unlock()

	if c, _, raw := doR67Req(t, h, http.MethodPost, "/_fleet/secrets", `{"id":"overflow","value":"secret"}`, nil); c != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 4097th fleet secret, got %d: %s", c, raw)
	}
	if c, _, raw := doR67Req(t, h, http.MethodPut, "/_watcher/watch/w-overflow", `{"trigger":{"schedule":{"interval":"1m"}},"input":{"simple":{}},"actions":{"log":{"logging":{"text":"ok"}}}}`, nil); c != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 4097th watch, got %d: %s", c, raw)
	}
	if c, _, raw := doR67Req(t, h, http.MethodPut, "/_watcher/watch/w-0", `{"trigger":{"schedule":{"interval":"1m"}},"input":{"simple":{}},"actions":{"log":{"logging":{"text":"ok"}}}}`, nil); c != http.StatusOK {
		t.Fatalf("expected 200 updating existing watch at cap, got %d: %s", c, raw)
	}
	// connectorSyncJobs FIFO eviction keeps map len <= 4096.
	if c, _, raw := doR67Req(t, h, http.MethodPost, "/_connector/_sync_job", `{"connector_id":"conn-cap"}`, nil); c != http.StatusCreated {
		t.Fatalf("expected 201 on sync_job with FIFO eviction, got %d: %s", c, raw)
	}
	s.mu.RLock()
	syncLen := len(s.connectorSyncJobs)
	s.mu.RUnlock()
	if syncLen > maxAdminStoreEntriesR67 {
		t.Fatalf("expected connectorSyncJobs bounded <= %d, got %d", maxAdminStoreEntriesR67, syncLen)
	}

	// Ensure schema import stays used / verified for index schema compilation smoke check.
	_ = esast.MappingSpec{}
	_ = schema.IndexSchema{}
}
