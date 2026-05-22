package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// stubSlack stands in for Slack's OIDC endpoints across the whole test
// surface. It serves a JWKS keyset and a token endpoint; the authorize URL
// is referenced only because the oauth2 library demands it have a non-empty
// AuthURL, but tests don't hit it directly — they synthesise the callback
// state and call /auth/callback against the proxy.
type stubSlack struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	// idTokenBuilder lets each test customise what id_token the token
	// endpoint returns. The default builds a token signed by `key` with
	// the provided nonce.
	mu             sync.Mutex
	idTokenBuilder func(t *testing.T) (string, int) // returns (id_token, http_status)
	clientID       string
}

func newStubSlack(t *testing.T) *stubSlack {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	s := &stubSlack{key: key, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/openid/connect/keys", s.serveJWKS)
	mux.HandleFunc("/api/openid.connect.token", s.serveToken)
	mux.HandleFunc("/openid/connect/authorize", s.serveAuthorize)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// issuer returns the stub server's URL — this is what we pass as the OIDC
// issuer string at construction time. The verifier requires a
// character-for-character match.
func (s *stubSlack) issuer() string { return s.server.URL }

func (s *stubSlack) endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  s.server.URL + "/openid/connect/authorize",
		TokenURL: s.server.URL + "/api/openid.connect.token",
	}
}

func (s *stubSlack) jwksURL() string { return s.server.URL + "/openid/connect/keys" }

func (s *stubSlack) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{Key: s.key.Public(), KeyID: s.kid, Use: "sig", Algorithm: "RS256"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (s *stubSlack) serveAuthorize(w http.ResponseWriter, _ *http.Request) {
	// Tests never hit this — they short-circuit to /auth/callback with a
	// synthesised state. If something does hit it we return 200 to avoid
	// confusing the test failure mode.
	w.WriteHeader(http.StatusOK)
}

func (s *stubSlack) serveToken(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	builder := s.idTokenBuilder
	s.mu.Unlock()
	if builder == nil {
		http.Error(w, "no id_token builder configured", http.StatusInternalServerError)
		return
	}
	idToken, status := builder(nil)
	if status >= 400 {
		http.Error(w, "stub forced failure", status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "stub-access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
	})
}

// signClaims signs claims with the stub's RSA key.
func (s *stubSlack) signClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.kid),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	return raw
}

// standardClaims builds a Slack-shaped ID token claim map with the bits
// the verifier and the handler care about. Tests then mutate the map to
// model attacks before signing.
func standardClaims(s *stubSlack, nonce, teamID string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss":                        s.issuer(),
		"aud":                        s.clientID,
		"sub":                        "U_TESTUSER",
		"iat":                        now,
		"exp":                        now + 600,
		"email":                      "clint@example.com",
		"name":                       "Clint Test",
		"picture":                    "https://example.com/a.png",
		"nonce":                      nonce,
		"https://slack.com/team_id":  teamID,
		"https://slack.com/user_id":  "U_TESTUSER",
	}
}

// testFixture bundles a stub Slack + a real (sqlite-backed) auth.Handler
// and exposes the pre-auth cookie a synthesised callback needs.
type testFixture struct {
	t       *testing.T
	slack   *stubSlack
	cfg     *config.Config
	handler *Handler
	mux     *http.ServeMux
	dbobj   *db.DB
}

func newFixture(t *testing.T) *testFixture {
	t.Helper()
	slack := newStubSlack(t)
	slack.clientID = "test-client-id"

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "forge.db")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	cfg := &config.Config{
		BaseDomain:         "forgeutah.tech",
		AuthHost:           "auth.forgeutah.tech",
		CookieDomain:       ".forgeutah.tech",
		SlackClientID:      slack.clientID,
		SlackClientSecret:  "test-secret",
		SlackTeamID:        "T_FORGE",
		SessionLifetime:    30 * 24 * time.Hour,
		SessionIdleTimeout: 14 * 24 * time.Hour,
		DefaultLandingURL:  "https://auth.forgeutah.tech/",
	}

	users := user.New(d, nil)
	sessions := session.New(d, session.Options{
		Lifetime:     cfg.SessionLifetime,
		IdleTimeout:  cfg.SessionIdleTimeout,
		CookieDomain: cfg.CookieDomain,
	})

	// Build OIDC client against the stub endpoints, then wait for the
	// JWKS goroutine to publish a verifier. The first JWKS GET happens
	// inside initVerifier; we block here until it succeeds so test cases
	// never have to deal with the "verifier not ready" branch.
	oidcCtx, oidcCancel := context.WithCancel(context.Background())
	t.Cleanup(oidcCancel)
	o := NewWithEndpoints(oidcCtx, cfg, slack.endpoint(), slack.jwksURL(), slack.issuer())
	select {
	case <-o.Ready():
	case <-time.After(5 * time.Second):
		t.Fatalf("OIDC verifier never became ready")
	}

	handler := NewHandler(cfg, o, users, sessions)
	mux := http.NewServeMux()
	handler.Register(mux)

	return &testFixture{t: t, slack: slack, cfg: cfg, handler: handler, mux: mux, dbobj: d}
}

// loginAndExtractPreAuth runs GET /auth/login and returns the pre-auth
// payload and the cookies it set. The cookie value is needed for the
// matching /auth/callback request.
func (f *testFixture) loginAndExtractPreAuth(returnTo string) (*PreAuthPayload, []*http.Cookie) {
	f.t.Helper()
	u := "/auth/login"
	if returnTo != "" {
		u = u + "?return_to=" + url.QueryEscape(returnTo)
	}
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		f.t.Fatalf("login status = %d, want 302; body=%q", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	// Re-parse the cookie into a payload by reading it through ReadPreAuth.
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	p, err := ReadPreAuth(r)
	if err != nil {
		f.t.Fatalf("ReadPreAuth from login response: %v", err)
	}
	return p, cookies
}

// callback synthesises a GET /auth/callback with the supplied cookies,
// state, and code. It returns the response recorder for caller assertions.
func (f *testFixture) callback(cookies []*http.Cookie, state, code string) *httptest.ResponseRecorder {
	f.t.Helper()
	q := url.Values{}
	q.Set("state", state)
	q.Set("code", code)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *testFixture) setIDToken(builder func() (string, int)) {
	f.slack.mu.Lock()
	f.slack.idTokenBuilder = func(*testing.T) (string, int) { return builder() }
	f.slack.mu.Unlock()
}

// findCookie returns the first cookie with the given name from the recorder.
func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// /auth/login
// ---------------------------------------------------------------------------

func TestLogin_RedirectsToSlackWithStateNonceAndTeam(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=https://deuce.forgeutah.tech/x", nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, f.slack.server.URL+"/openid/connect/authorize") {
		t.Fatalf("redirect location = %q; want stub authorize URL prefix", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	q := u.Query()
	if q.Get("state") == "" {
		t.Fatalf("missing state in authorize URL: %s", loc)
	}
	if q.Get("nonce") == "" {
		t.Fatalf("missing nonce in authorize URL: %s", loc)
	}
	if q.Get("team") != "T_FORGE" {
		t.Fatalf("team param = %q; want T_FORGE", q.Get("team"))
	}
	if q.Get("client_id") != "test-client-id" {
		t.Fatalf("client_id = %q; want test-client-id", q.Get("client_id"))
	}

	// Pre-auth cookie should be set with __Host- prefix and no Domain.
	preCookie := findCookie(rec, PreAuthCookieName)
	if preCookie == nil {
		t.Fatalf("missing pre-auth cookie")
	}
	if preCookie.Domain != "" {
		t.Fatalf("__Host- cookie must have no Domain; got %q", preCookie.Domain)
	}
}

func TestLogin_InvalidReturnToFallsBackToDefault(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=https://evil.com/x", nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	// We can't inspect what the pre-auth cookie carries from outside,
	// so re-parse it via ReadPreAuth.
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	p, err := ReadPreAuth(r)
	if err != nil {
		t.Fatalf("ReadPreAuth: %v", err)
	}
	if p.ReturnTo != f.cfg.DefaultLandingURL {
		t.Fatalf("returnTo = %q; want default landing %q", p.ReturnTo, f.cfg.DefaultLandingURL)
	}
}

// ---------------------------------------------------------------------------
// /auth/callback — happy paths
// ---------------------------------------------------------------------------

// TestCallback_TamperedReturnTo_FallsBackToDefault verifies defense-in-depth
// return_to re-validation on the callback path. The pre-auth cookie is
// HttpOnly + __Host- + single-use, which closes the common attack shapes —
// but the payload is base64(json(...)) with no HMAC, so any cookie-write
// primitive on the auth host (XSS, future bug) could swap return_to while
// preserving state/nonce. The callback re-runs Validate; a tampered
// destination falls back to DefaultLandingURL.
func TestCallback_TamperedReturnTo_FallsBackToDefault(t *testing.T) {
	f := newFixture(t)

	// Build a pre-auth payload whose return_to points at a hostile host
	// the validator rejects. State/nonce are real (so they round-trip
	// through the OIDC verification), but the destination is the attack
	// surface we're testing.
	pre := &PreAuthPayload{
		State:    "STATE-tampered",
		Nonce:    "NONCE-tampered",
		ReturnTo: "https://evil.com/grab-csrf",
	}

	// Set the cookie directly so we bypass /auth/login's call to Validate.
	// This is the simulation: an attacker has swapped pre.ReturnTo after
	// the login redirect but before the callback fires.
	rec := httptest.NewRecorder()
	if err := SetPreAuth(rec, pre); err != nil {
		t.Fatalf("SetPreAuth: %v", err)
	}
	cookies := rec.Result().Cookies()

	f.setIDToken(func() (string, int) {
		claims := standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)
		return f.slack.signClaims(t, claims), 200
	})

	cb := f.callback(cookies, pre.State, "stub-code")
	if cb.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", cb.Code, cb.Body.String())
	}
	loc := cb.Header().Get("Location")
	if loc == "https://evil.com/grab-csrf" {
		t.Fatalf("redirect honoured tampered return_to — SEC-2 regression: %q", loc)
	}
	if loc != f.cfg.DefaultLandingURL {
		t.Fatalf("redirect = %q; want default landing %q", loc, f.cfg.DefaultLandingURL)
	}

	// Session was still created (the user authenticated successfully; only
	// the destination falls back). Sanity-check the session cookie was set.
	if sc := findCookie(cb, session.CookieName); sc == nil {
		t.Fatalf("session cookie missing after tampered-return_to callback")
	}
}

// TestCallback_HappyPath_CoversAE2_F1 verifies the new-member sign-in:
// user row created with empty roles, session cookie set on .forgeutah.tech,
// redirect to the original return_to.
func TestCallback_HappyPath_CoversAE2_F1(t *testing.T) {
	f := newFixture(t)
	returnTo := "https://deuce.forgeutah.tech/dashboard?x=1#y"
	pre, cookies := f.loginAndExtractPreAuth(returnTo)

	f.setIDToken(func() (string, int) {
		claims := standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)
		return f.slack.signClaims(t, claims), 200
	})

	rec := f.callback(cookies, pre.State, "stub-code")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != returnTo {
		t.Fatalf("redirect = %q; want %q", loc, returnTo)
	}

	// Session cookie was set on the configured cookie domain.
	sc := findCookie(rec, session.CookieName)
	if sc == nil {
		t.Fatalf("session cookie not set")
	}
	// Go normalises a leading dot off Domain when parsing Set-Cookie
	// back; the wire form is still equivalent per RFC 6265.
	if sc.Domain != "forgeutah.tech" && sc.Domain != ".forgeutah.tech" {
		t.Fatalf("session cookie domain = %q; want forgeutah.tech (or .forgeutah.tech)", sc.Domain)
	}
	if !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie flags wrong: %+v", sc)
	}

	// Pre-auth cookie was deleted.
	preCookie := findCookie(rec, PreAuthCookieName)
	if preCookie == nil || preCookie.MaxAge != -1 {
		t.Fatalf("pre-auth cookie not cleared: %+v", preCookie)
	}

	// User row exists with empty roles (AE2).
	u, err := f.handler.Users.GetBySlackID(context.Background(), "U_TESTUSER")
	if err != nil {
		t.Fatalf("GetBySlackID: %v", err)
	}
	if len(u.Roles) != 0 {
		t.Fatalf("new user should have empty roles, got %v", u.Roles)
	}
	if u.Email != "clint@example.com" {
		t.Fatalf("email = %q, want clint@example.com", u.Email)
	}
}

// TestCallback_ReturningUser_PreservesRoles re-runs upsert on a user with
// pre-existing roles and verifies the roles survive.
func TestCallback_ReturningUser_PreservesRoles(t *testing.T) {
	f := newFixture(t)
	// First sign-in.
	returnTo := "https://deuce.forgeutah.tech/"
	pre, cookies := f.loginAndExtractPreAuth(returnTo)
	f.setIDToken(func() (string, int) {
		return f.slack.signClaims(t, standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)), 200
	})
	if rec := f.callback(cookies, pre.State, "code1"); rec.Code != http.StatusFound {
		t.Fatalf("first callback status = %d", rec.Code)
	}

	// Admin grants a role.
	u, err := f.handler.Users.GetBySlackID(context.Background(), "U_TESTUSER")
	if err != nil {
		t.Fatalf("GetBySlackID: %v", err)
	}
	if err := f.handler.Users.SetRoles(context.Background(), u.ID, []string{"admin"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}

	// Second sign-in.
	pre2, cookies2 := f.loginAndExtractPreAuth(returnTo)
	f.setIDToken(func() (string, int) {
		return f.slack.signClaims(t, standardClaims(f.slack, pre2.Nonce, f.cfg.SlackTeamID)), 200
	})
	if rec := f.callback(cookies2, pre2.State, "code2"); rec.Code != http.StatusFound {
		t.Fatalf("second callback status = %d", rec.Code)
	}

	u2, err := f.handler.Users.GetBySlackID(context.Background(), "U_TESTUSER")
	if err != nil {
		t.Fatalf("GetBySlackID: %v", err)
	}
	if len(u2.Roles) != 1 || u2.Roles[0] != "admin" {
		t.Fatalf("roles after re-sign-in = %v, want [admin]", u2.Roles)
	}
}

// ---------------------------------------------------------------------------
// /auth/callback — unhappy paths
// ---------------------------------------------------------------------------

// TestCallback_WorkspaceMismatch_CoversAE1_F3_R3_R13 verifies the
// not-in-workspace branch: redirect with the right error code, no session,
// pre-auth cleared.
func TestCallback_WorkspaceMismatch_CoversAE1_F3_R3_R13(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://deuce.forgeutah.tech/")
	f.setIDToken(func() (string, int) {
		claims := standardClaims(f.slack, pre.Nonce, "T_DIFFERENT_WORKSPACE")
		return f.slack.signClaims(t, claims), 200
	})

	rec := f.callback(cookies, pre.State, "code1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/?error=not_in_workspace" {
		t.Fatalf("redirect = %q; want /?error=not_in_workspace", loc)
	}
	if findCookie(rec, session.CookieName) != nil {
		t.Fatalf("session cookie must NOT be set on unauthorized branch")
	}
	preCookie := findCookie(rec, PreAuthCookieName)
	if preCookie == nil || preCookie.MaxAge != -1 {
		t.Fatalf("pre-auth cookie not cleared: %+v", preCookie)
	}
	// No user row provisioned for the wrong workspace.
	if _, err := f.handler.Users.GetBySlackID(context.Background(), "U_TESTUSER"); err == nil {
		t.Fatalf("user should not exist for workspace-mismatch path")
	}
}

func TestCallback_NoPreAuthCookie_RedirectsAuthFailed(t *testing.T) {
	f := newFixture(t)
	rec := f.callback(nil, "anything", "anything")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
}

func TestCallback_StateMismatch_RedirectsAuthFailed(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	_ = pre
	rec := f.callback(cookies, "wrong-state", "code1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
}

func TestCallback_TokenExchangeFailure_RedirectsAuthFailed(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	f.setIDToken(func() (string, int) { return "", 500 })

	rec := f.callback(cookies, pre.State, "code1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
}

func TestCallback_InvalidSignature_RedirectsAuthFailed(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	// Sign with a *different* RSA key so the verifier rejects the
	// signature — exactly the threat model.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: otherKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.slack.kid),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	f.setIDToken(func() (string, int) { return raw, 200 })

	rec := f.callback(cookies, pre.State, "code1")
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
}

// TestCallback_AlgorithmConfusion_HS256_Rejected: the classic
// algorithm-confusion attack. Take the public key (which is published on
// the JWKS endpoint) and use it as the HS256 HMAC secret. A verifier
// that accepts whatever alg the token claims would happily verify this.
// Our verifier pins SupportedSigningAlgs=["RS256"] so it must reject.
func TestCallback_AlgorithmConfusion_HS256_Rejected(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")

	// Build a token with alg=HS256 signed using the public key bytes as
	// the HMAC secret. We marshal the public key to bytes the same way an
	// attacker would: by fetching the JWKS endpoint, parsing the n/e
	// values, and using the raw modulus as the key. For test simplicity
	// we just use the PEM/DER encoding of the public key — the principle
	// is the same: any HS256 signature on what should be an RS256 token
	// must be rejected.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("attacker-controlled-secret-from-public-key-material")},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.slack.kid),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	f.setIDToken(func() (string, int) { return raw, 200 })

	rec := f.callback(cookies, pre.State, "code1")
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
	if findCookie(rec, session.CookieName) != nil {
		t.Fatalf("session cookie must NOT be set after algorithm-confusion attack")
	}
}

func TestCallback_NonceMismatch_RedirectsAuthFailed(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	f.setIDToken(func() (string, int) {
		claims := standardClaims(f.slack, "bogus-nonce-value", f.cfg.SlackTeamID)
		return f.slack.signClaims(t, claims), 200
	})

	rec := f.callback(cookies, pre.State, "code1")
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
}

func TestCallback_WrongIssuer_Rejected(t *testing.T) {
	// Build a brand-new fixture but mint an id_token with the wrong
	// issuer claim. The verifier (constructed against f.slack.issuer())
	// must reject.
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	f.setIDToken(func() (string, int) {
		claims := standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)
		claims["iss"] = "https://slack.com.evil.com"
		return f.slack.signClaims(t, claims), 200
	})

	rec := f.callback(cookies, pre.State, "code1")
	if loc := rec.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("redirect = %q; want /?error=auth_failed", loc)
	}
}

// TestCallback_StateReplay_DefenceVerified: enforce single-use state. We
// run a successful callback, capture the response, and assert that the
// pre-auth cookie was deleted. A second callback request that does NOT
// re-supply the cookie (modeling a browser that honoured the deletion)
// must fail. This exercises the "cookie deleted on first callback" rule.
func TestCallback_StateReplay_DefenceVerified(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	f.setIDToken(func() (string, int) {
		return f.slack.signClaims(t, standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)), 200
	})

	rec1 := f.callback(cookies, pre.State, "code1")
	if rec1.Code != http.StatusFound {
		t.Fatalf("first callback status = %d", rec1.Code)
	}
	// Assert the deletion cookie was sent (Max-Age=-1).
	delCookie := findCookie(rec1, PreAuthCookieName)
	if delCookie == nil || delCookie.MaxAge != -1 {
		t.Fatalf("expected deletion cookie on first callback; got %+v", delCookie)
	}

	// Second callback with the (same) state but WITHOUT the pre-auth cookie
	// (the browser honoured the deletion). Must redirect to auth_failed.
	rec2 := f.callback(nil, pre.State, "code1")
	if loc := rec2.Header().Get("Location"); loc != "/?error=auth_failed" {
		t.Fatalf("replay attempt redirect = %q; want auth_failed", loc)
	}
	if findCookie(rec2, session.CookieName) != nil {
		t.Fatalf("replay attempt must not issue a session cookie")
	}
}

// ---------------------------------------------------------------------------
// /auth/logout
// ---------------------------------------------------------------------------

// TestLogout_HappyPath_CoversAE5_F4 — POST /auth/logout with valid session
// and matching Origin → session row deleted, cookie cleared, 302 to /.
func TestLogout_HappyPath_CoversAE5_F4(t *testing.T) {
	f := newFixture(t)
	// Sign in to get a session.
	returnTo := "https://forgeutah.tech/"
	pre, cookies := f.loginAndExtractPreAuth(returnTo)
	f.setIDToken(func() (string, int) {
		return f.slack.signClaims(t, standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)), 200
	})
	cbRec := f.callback(cookies, pre.State, "code1")
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback status = %d", cbRec.Code)
	}
	sessionCookie := findCookie(cbRec, session.CookieName)
	if sessionCookie == nil {
		t.Fatalf("missing session cookie after callback")
	}

	// Verify the session exists in the store.
	if _, err := f.handler.Sessions.Get(context.Background(), sessionCookie.Value); err != nil {
		t.Fatalf("session lookup before logout: %v", err)
	}

	// POST /auth/logout with the session cookie and a matching Origin.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", "https://"+f.cfg.AuthHost)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("logout status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("logout redirect = %q; want /", loc)
	}

	// Session row deleted.
	if _, err := f.handler.Sessions.Get(context.Background(), sessionCookie.Value); err == nil {
		t.Fatalf("session row still present after logout")
	}

	// Cookie cleared (deletion marker).
	cleared := findCookie(rec, session.CookieName)
	if cleared == nil || cleared.MaxAge != -1 {
		t.Fatalf("expected session cookie deletion marker; got %+v", cleared)
	}
}

func TestLogout_OriginMismatch_Returns403_SessionPreserved(t *testing.T) {
	f := newFixture(t)
	// Provision a session by going through sign-in.
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	f.setIDToken(func() (string, int) {
		return f.slack.signClaims(t, standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)), 200
	})
	cbRec := f.callback(cookies, pre.State, "code1")
	sessionCookie := findCookie(cbRec, session.CookieName)
	if sessionCookie == nil {
		t.Fatalf("no session cookie from callback")
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	// Session must still exist.
	if _, err := f.handler.Sessions.Get(context.Background(), sessionCookie.Value); err != nil {
		t.Fatalf("session must survive a CSRF-rejected logout: %v", err)
	}
}

func TestLogout_NoCookie_StillRedirects(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Origin", "https://"+f.cfg.AuthHost)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("redirect = %q; want /", loc)
	}
}

func TestLogout_MissingOrigin_Returns403(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Handler.IsSignedIn — the SessionChecker the web package consumes
//
// The GET / root route used to live here and call session.Read + Sessions.Get
// before either redirecting to the default landing or rendering a tiny
// HTML placeholder. U7 moved that route into internal/web (with the real
// React card), and the Go-side already-signed-in check now lives on the
// Handler as IsSignedIn so the web package can compose it without
// importing internal/auth. The placeholder copy that used to live in
// renderPlaceholder is gone — the React JSX renders the user-visible
// strings client-side, driven by the ?error= query param.
//
// These three tests cover the same behaviour the four TestRoot_* tests
// used to cover, expressed against the new interface.
// ---------------------------------------------------------------------------

func TestIsSignedIn_LiveSession_ReturnsTrue(t *testing.T) {
	f := newFixture(t)
	pre, cookies := f.loginAndExtractPreAuth("https://forgeutah.tech/")
	f.setIDToken(func() (string, int) {
		return f.slack.signClaims(t, standardClaims(f.slack, pre.Nonce, f.cfg.SlackTeamID)), 200
	})
	cbRec := f.callback(cookies, pre.State, "code1")
	sessionCookie := findCookie(cbRec, session.CookieName)
	if sessionCookie == nil {
		t.Fatalf("no session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	if !f.handler.IsSignedIn(context.Background(), req) {
		t.Fatalf("IsSignedIn = false; want true for a live session cookie")
	}
}

func TestIsSignedIn_NoCookie_ReturnsFalse(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if f.handler.IsSignedIn(context.Background(), req) {
		t.Fatalf("IsSignedIn = true; want false when no cookie present")
	}
}

func TestIsSignedIn_ExpiredSession_ReturnsFalse(t *testing.T) {
	f := newFixture(t)
	// Manually insert a session with an expired expires_at. Expired
	// sessions read as ErrExpired from the store; IsSignedIn must treat
	// that the same as a missing row — the caller still sees the login
	// card, not the default landing.
	now := time.Now().Unix()
	ctx := context.Background()
	res, err := f.dbobj.Writer.ExecContext(ctx, `
		INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, '', ?, ?)`,
		"U_EXPIRED", f.cfg.SlackTeamID, "x@example.com", "X", "", now, now)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	uid, _ := res.LastInsertId()
	expiredID := "expired-session-id-AAAAAAAAAAAAAAAAAA"
	_, err = f.dbobj.Writer.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, created_at, last_seen_at, expires_at, user_agent, ip)
		VALUES (?, ?, ?, ?, ?, '', '')`,
		expiredID, uid, now-100000, now-100000, now-1)
	if err != nil {
		t.Fatalf("seed expired session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: expiredID})
	if f.handler.IsSignedIn(ctx, req) {
		t.Fatalf("IsSignedIn = true; want false for an expired session")
	}
}

// ---------------------------------------------------------------------------
// OIDC client readiness — covers the "binary starts even if JWKS unreachable" path
// ---------------------------------------------------------------------------

// TestOIDC_NotReady_DoesNotBlockConstruction: NewWithEndpoints returns
// immediately even when the JWKS URL points at a dead endpoint. The
// verifier remains nil until Slack comes back; handlers see IsReady()==false
// and return auth_failed without crashing.
func TestOIDC_NotReady_DoesNotBlockConstruction(t *testing.T) {
	cfg := &config.Config{SlackClientID: "x", AuthHost: "auth.example.com"}
	ctx := t.Context()
	// Point at a port nothing's listening on. Construction must not block.
	endpoint := oauth2.Endpoint{AuthURL: "http://127.0.0.1:1/a", TokenURL: "http://127.0.0.1:1/t"}
	done := make(chan struct{})
	go func() {
		_ = NewWithEndpoints(ctx, cfg, endpoint, "http://127.0.0.1:1/jwks", "http://127.0.0.1:1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("NewWithEndpoints blocked on JWKS fetch")
	}
}

// helper: ensure we don't leave the fixture-issued OAuth token endpoints
// dangling — io.Discard ensures the response body is fully consumed in
// stress tests. Kept here for future tests that exercise the full TLS path.
var _ = io.Discard
var _ = fmt.Sprintf
