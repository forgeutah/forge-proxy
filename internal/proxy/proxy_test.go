package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// stubSession is an in-memory SessionStore for the proxy tests. The proxy's
// SessionStore interface is narrow (Get + Touch) so we don't need the full
// SQLite-backed store here — the proxy.go behaviour is what's under test,
// not the persistence layer.
type stubSession struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
	// touchErr, if non-nil, is returned by Touch — used by the disk-full
	// edge case to verify the proxy logs-and-continues.
	touchErr error
	// touched is incremented per Touch call so tests can assert behavior.
	touched int
}

func newStubSession() *stubSession {
	return &stubSession{sessions: make(map[string]*session.Session)}
}

func (s *stubSession) put(id string, sess *session.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = sess
}

func (s *stubSession) Get(_ context.Context, id string) (*session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, session.ErrNotFound
	}
	// Mirror the real store's expired-check semantics.
	if !time.Now().Before(sess.ExpiresAt) {
		return nil, session.ErrExpired
	}
	return sess, nil
}

func (s *stubSession) Touch(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touched++
	return s.touchErr
}

// stubUser is an in-memory UserStore for proxy tests. The roles slice can
// be mutated mid-test to exercise AE4 (live-roles-on-each-request).
type stubUser struct {
	mu    sync.Mutex
	users map[int64]*user.User
}

func newStubUser() *stubUser {
	return &stubUser{users: make(map[int64]*user.User)}
}

func (s *stubUser) put(u *user.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
}

func (s *stubUser) setRoles(id int64, roles []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		u.Roles = roles
	}
}

func (s *stubUser) remove(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
}

func (s *stubUser) Get(_ context.Context, id int64) (*user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, user.ErrNotFound
	}
	// Return a deep copy of the slice fields so tests that mutate roles
	// don't race with a request reading them.
	dup := *u
	dup.Roles = append([]string{}, u.Roles...)
	return &dup, nil
}

// receivedRequest captures what an upstream stub saw. Tests assert on these
// fields after a request completes.
type receivedRequest struct {
	Method  string
	Path    string
	Host    string
	Header  http.Header
	Trailer http.Header
	Body    []byte
}

// newUpstreamStub returns an httptest.Server that records every request and
// returns the supplied status + body. Tests inspect the recorded request
// to assert outbound headers.
func newUpstreamStub(t *testing.T, status int, body string) (*httptest.Server, *[]receivedRequest) {
	t.Helper()
	var (
		mu       sync.Mutex
		received []receivedRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		mu.Lock()
		// Copy header maps so test mutations after the fact don't poison
		// the snapshot.
		hdr := r.Header.Clone()
		var trailer http.Header
		if r.Trailer != nil {
			trailer = r.Trailer.Clone()
		}
		received = append(received, receivedRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Host:    r.Host,
			Header:  hdr,
			Trailer: trailer,
			Body:    buf,
		})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &received
}

// proxyFixture is the standard test rig: one upstream stub, one session,
// one user, one configured *Proxy.
type proxyFixture struct {
	cfg       *config.Config
	upstream  *httptest.Server
	received  *[]receivedRequest
	sessions  *stubSession
	users     *stubUser
	user      *user.User
	sessionID string
	proxy     *Proxy
}

// newProxyFixture builds the standard rig. Tests vary one or two values
// (session state, upstream behaviour) and otherwise rely on the defaults.
func newProxyFixture(t *testing.T) *proxyFixture {
	t.Helper()
	upstream, received := newUpstreamStub(t, http.StatusOK, "hello from upstream")
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("url.Parse(upstream): %v", err)
	}

	cfg := &config.Config{
		AuthHost:     "auth.forgeutah.tech",
		BaseDomain:   "forgeutah.tech",
		CookieDomain: ".forgeutah.tech",
		ProxySecret:  "test-proxy-secret-32chars-min-padding",
		// Ungated by default — the pre-gating shape, so every existing test
		// exercises the unrestricted path. Tests that care about the gate
		// call requireRoles.
		UpstreamMap: map[string]config.Upstream{
			"deuce.forgeutah.tech": {Target: upstreamURL},
		},
	}

	u := &user.User{
		ID:          42,
		SlackUserID: "U_ALICE",
		SlackTeamID: "T_FORGE",
		Email:       "alice@forgeutah.tech",
		Name:        "Alice",
		AvatarURL:   "https://example.com/a.png",
		Roles:       []string{"member"},
	}
	users := newStubUser()
	users.put(u)

	sess := &session.Session{
		ID:        "session-id-abcdefghijklmno",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	sessions := newStubSession()
	sessions.put(sess.ID, sess)

	return &proxyFixture{
		cfg:       cfg,
		upstream:  upstream,
		received:  received,
		sessions:  sessions,
		users:     users,
		user:      u,
		sessionID: sess.ID,
		proxy:     New(cfg, sessions, users),
	}
}

// requireRoles gates the fixture's upstream behind the given roles and
// rebuilds the proxy so the new host map takes effect. NewHostMap copies the
// config map at construction time, so mutating cfg alone would not reach the
// running proxy.
func (f *proxyFixture) requireRoles(roles ...string) {
	entry := f.cfg.UpstreamMap["deuce.forgeutah.tech"]
	entry.RequiredRoles = roles
	f.cfg.UpstreamMap["deuce.forgeutah.tech"] = entry
	f.proxy = New(f.cfg, f.sessions, f.users)
}

// setUpstreamTarget repoints the fixture's upstream and rebuilds the proxy,
// preserving whatever role gating is configured.
func (f *proxyFixture) setUpstreamTarget(target *url.URL) {
	entry := f.cfg.UpstreamMap["deuce.forgeutah.tech"]
	entry.Target = target
	f.cfg.UpstreamMap["deuce.forgeutah.tech"] = entry
	f.proxy = New(f.cfg, f.sessions, f.users)
}

// signedInRequest builds a request carrying the fixture's session cookie.
// Tests use this as the standard authenticated inbound request.
func (f *proxyFixture) signedInRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: f.sessionID})
	return r
}

// TestProxy_HappyPath_CoversAE3_F2 is the AE3 / F2 happy path: a signed-in
// user requests an upstream-app URL and the proxy forwards to the configured
// upstream with all nine X-Forge-* headers injected.
func TestProxy_HappyPath_CoversAE3_F2(t *testing.T) {
	f := newProxyFixture(t)
	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	w := httptest.NewRecorder()

	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "hello from upstream" {
		t.Fatalf("body = %q, want %q", got, "hello from upstream")
	}
	if len(*f.received) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(*f.received))
	}
	rec := (*f.received)[0]
	if rec.Path != "/foo" {
		t.Errorf("upstream path = %q, want %q", rec.Path, "/foo")
	}

	// Verify all nine X-Forge-* headers are present with the expected values.
	want := map[string]string{
		"X-Forge-Proxy-Secret":     f.cfg.ProxySecret,
		"X-Forge-Contract-Version": "1",
		"X-Forge-User-Id":          "42",
		"X-Forge-Email":            "alice@forgeutah.tech",
		"X-Forge-Name":             "Alice",
		"X-Forge-Avatar":           "https://example.com/a.png",
		"X-Forge-Roles":            "member",
		"X-Forge-Slack-User-Id":    "U_ALICE",
		"X-Forge-Slack-Team-Id":    "T_FORGE",
	}
	for name, expected := range want {
		if got := rec.Header.Get(name); got != expected {
			t.Errorf("upstream %s = %q, want %q", name, got, expected)
		}
	}

	// Touch was called.
	if f.sessions.touched != 1 {
		t.Errorf("session touch count = %d, want 1", f.sessions.touched)
	}
}

// TestProxy_Unauthenticated_RedirectsToLogin verifies the no-cookie path:
// the proxy 302s to the auth host's login endpoint with the original URL
// URL-encoded in return_to.
func TestProxy_Unauthenticated_RedirectsToLogin(t *testing.T) {
	f := newProxyFixture(t)
	r := httptest.NewRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo?bar=1", nil)
	w := httptest.NewRecorder()

	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://auth.forgeutah.tech/?return_to=") {
		t.Fatalf("Location = %q, want auth-host root prefix", loc)
	}
	// The return_to must be the full inbound URL, URL-encoded.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("url.Parse(Location): %v", err)
	}
	gotReturnTo := u.Query().Get("return_to")
	wantReturnTo := "https://deuce.forgeutah.tech/foo?bar=1"
	if gotReturnTo != wantReturnTo {
		t.Fatalf("return_to = %q, want %q", gotReturnTo, wantReturnTo)
	}
	// The upstream stub must never have been hit.
	if len(*f.received) != 0 {
		t.Fatalf("upstream saw %d requests, want 0", len(*f.received))
	}
}

// TestProxy_RolesUpdateMidSession_CoversAE4_F5_R6 verifies the live-roles
// promise (R6, F5): a roles edit between requests is reflected in the next
// request's X-Forge-Roles header, without re-issuing the session.
func TestProxy_RolesUpdateMidSession_CoversAE4_F5_R6(t *testing.T) {
	f := newProxyFixture(t)

	// First request — observes the initial roles.
	r1 := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/one")
	f.proxy.ServeHTTP(httptest.NewRecorder(), r1)

	// Admin mutates the roles list in the DB (simulated by the stub).
	f.users.setRoles(f.user.ID, []string{"admin", "member"})

	// Second request — observes the new roles, same session cookie.
	r2 := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/two")
	f.proxy.ServeHTTP(httptest.NewRecorder(), r2)

	if len(*f.received) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(*f.received))
	}
	if got := (*f.received)[0].Header.Get("X-Forge-Roles"); got != "member" {
		t.Errorf("first roles = %q, want %q", got, "member")
	}
	if got := (*f.received)[1].Header.Get("X-Forge-Roles"); got != "admin,member" {
		t.Errorf("second roles = %q, want %q", got, "admin,member")
	}
}

// TestProxy_UnknownHost_404 verifies the no-such-upstream branch: a host
// not in the upstream map yields 404 (not 502).
func TestProxy_UnknownHost_404(t *testing.T) {
	f := newProxyFixture(t)
	r := f.signedInRequest(http.MethodGet, "https://nope.forgeutah.tech/foo")
	w := httptest.NewRecorder()

	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	// Branded error page mentions the unknown host.
	body := w.Body.String()
	if !strings.Contains(body, "nope.forgeutah.tech") {
		t.Errorf("404 page does not mention unknown host; got: %s", body)
	}
	if !strings.Contains(body, "deuce.forgeutah.tech") {
		t.Errorf("404 page does not list known host; got: %s", body)
	}
}

// TestProxy_UpstreamReturns500_PassedThrough verifies the proxy is a
// transparent forwarder for application-layer 5xx — a 500 from upstream
// stays a 500 to the browser (not converted to 502).
func TestProxy_UpstreamReturns500_PassedThrough(t *testing.T) {
	upstream, _ := newUpstreamStub(t, http.StatusInternalServerError, "boom")
	upstreamURL, _ := url.Parse(upstream.URL)

	f := newProxyFixture(t)
	f.setUpstreamTarget(upstreamURL)

	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (upstream 500 must pass through)", w.Code, http.StatusInternalServerError)
	}
	if got := w.Body.String(); got != "boom" {
		t.Fatalf("body = %q, want %q", got, "boom")
	}
}

// TestProxy_UpstreamUnreachable_502 verifies the ErrorHandler path: a
// connection-refused upstream surfaces as 502 to the browser.
func TestProxy_UpstreamUnreachable_502(t *testing.T) {
	f := newProxyFixture(t)
	// Point the upstream at a guaranteed-closed port — we close a
	// listener and grab its address, so dial will fail immediately.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL, _ := url.Parse(deadSrv.URL)
	deadSrv.Close() // shut it down so dials fail.

	f.setUpstreamTarget(deadURL)

	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

// TestProxy_ExpiredSession_RedirectsToLogin verifies the ErrExpired path:
// a session whose row exists but whose expires_at is past returns the same
// 302 as ErrNotFound (both routes fold into "redirect to login").
func TestProxy_ExpiredSession_RedirectsToLogin(t *testing.T) {
	f := newProxyFixture(t)
	// Replace the session with one that's already expired.
	f.sessions.put(f.sessionID, &session.Session{
		ID:        f.sessionID,
		UserID:    f.user.ID,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://auth.forgeutah.tech/?return_to=") {
		t.Fatalf("Location = %q, want auth-host root redirect", loc)
	}
}

// TestProxy_MissingUser_ClearsCookieAndRedirects verifies the forced-logout
// race: a session referencing a deleted user clears the session cookie and
// redirects to login.
func TestProxy_MissingUser_ClearsCookieAndRedirects(t *testing.T) {
	f := newProxyFixture(t)
	f.users.remove(f.user.ID)

	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	// The Set-Cookie header should be present with MaxAge<0 (deletion cookie).
	cookies := w.Result().Cookies()
	var cleared bool
	for _, c := range cookies {
		if c.Name == session.CookieName && c.MaxAge < 0 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatalf("session cookie was not cleared; cookies = %v", cookies)
	}
}

// TestProxy_TouchFailure_Continues verifies that a Touch error is logged
// and does NOT block the request — the session is still valid for the
// remainder of its current window.
func TestProxy_TouchFailure_Continues(t *testing.T) {
	f := newProxyFixture(t)
	f.sessions.touchErr = errors.New("disk full")

	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (Touch failure must not block)", w.Code, http.StatusOK)
	}
	if len(*f.received) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(*f.received))
	}
}

// TestProxy_SmugglingDefenseAtRequestBoundary is the end-to-end smuggling
// test: a client supplies hostile X-Forge-* headers and the upstream
// observes only the trusted values. Complements the unit-level coverage
// in headers_test.go by going through the full ServeHTTP path.
func TestProxy_SmugglingDefenseAtRequestBoundary(t *testing.T) {
	f := newProxyFixture(t)
	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	r.Header.Set("X-Forge-Roles", "superadmin")
	r.Header.Set("X-Forge-Email", "attacker@evil.com")
	r.Header.Set("X-Forge-User-Id", "999")
	r.Header.Set("X-Forge-Proxy-Secret", "guessed-secret")

	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if len(*f.received) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(*f.received))
	}
	rec := (*f.received)[0]
	if got := rec.Header.Get("X-Forge-Roles"); got != "member" {
		t.Errorf("X-Forge-Roles = %q, want %q (client value must not survive)", got, "member")
	}
	if got := rec.Header.Get("X-Forge-Email"); got != f.user.Email {
		t.Errorf("X-Forge-Email = %q, want %q", got, f.user.Email)
	}
	if got := rec.Header.Get("X-Forge-User-Id"); got != "42" {
		t.Errorf("X-Forge-User-Id = %q, want %q", got, "42")
	}
	if got := rec.Header.Get("X-Forge-Proxy-Secret"); got != f.cfg.ProxySecret {
		t.Errorf("X-Forge-Proxy-Secret = %q, want config value", got)
	}
}

// TestProxy_ReplacesXForwardedFor verifies that an inbound X-Forwarded-For
// from the client is replaced (not appended). We don't trust client-supplied
// IP claims.
func TestProxy_ReplacesXForwardedFor(t *testing.T) {
	f := newProxyFixture(t)
	r := f.signedInRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo")
	r.RemoteAddr = "192.0.2.1:54321"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2") // hostile claim

	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)

	if len(*f.received) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(*f.received))
	}
	xff := (*f.received)[0].Header.Get("X-Forwarded-For")
	if strings.Contains(xff, "10.0.0.1") || strings.Contains(xff, "10.0.0.2") {
		t.Fatalf("X-Forwarded-For = %q, must not include client-supplied values", xff)
	}
	if !strings.Contains(xff, "192.0.2.1") {
		t.Fatalf("X-Forwarded-For = %q, expected to contain server-observed remote IP 192.0.2.1", xff)
	}
}
