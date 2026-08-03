package sshenroll

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// --- Stubs --------------------------------------------------------------

type stubSession struct {
	sess *session.Session
	err  error
}

func (s *stubSession) Get(_ context.Context, _ string) (*session.Session, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.sess, nil
}

type stubUser struct {
	u   *user.User
	err error
}

func (s *stubUser) Get(_ context.Context, _ int64) (*user.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.u, nil
}

type stubKeys struct {
	added       []*sshkey.Key
	addErr      error
	getResp     *sshkey.Key
	getErr      error
	addObserved int
}

func (s *stubKeys) Add(_ context.Context, userID int64, fingerprint, keyType string, publicKey []byte, label string) (*sshkey.Key, error) {
	s.addObserved++
	if s.addErr != nil {
		return nil, s.addErr
	}
	k := &sshkey.Key{
		ID:          int64(len(s.added) + 1),
		UserID:      userID,
		Fingerprint: fingerprint,
		KeyType:     keyType,
		PublicKey:   publicKey,
		Label:       label,
	}
	s.added = append(s.added, k)
	return k, nil
}

func (s *stubKeys) Get(_ context.Context, _ string) (*sshkey.Key, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.getResp, nil
}

// newHandlers returns a wired-up *Handlers + the underlying token store
// for tests to drive directly.
func newHandlers(t *testing.T, sess SessionLookup, users UserLookup, keys KeyStore) *Handlers {
	t.Helper()
	return New(NewStore(time.Now), sess, users, keys, "auth.forgeut.dev")
}

// --- Tests --------------------------------------------------------------

func TestHandleStart_RendersFingerprint(t *testing.T) {
	h := newHandlers(t, nil, nil, nil)
	token, err := h.Tokens.Mint("SHA256:abc-fp", "ssh-ed25519", []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token, nil)
	r.SetPathValue("token", token)
	w := httptest.NewRecorder()

	h.HandleStart(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "SHA256:abc-fp") {
		t.Errorf("body does not contain fingerprint:\n%s", body)
	}
	if !strings.Contains(body, "/auth/login?return_to=") {
		t.Errorf("body does not contain login link:\n%s", body)
	}
	if !strings.Contains(body, "ssh%2Fenroll%2F"+token+"%2Fcomplete") {
		t.Errorf("body does not encode complete URL:\n%s", body)
	}
}

func TestHandleStart_UnknownTokenRenders404Page(t *testing.T) {
	h := newHandlers(t, nil, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/does-not-exist", nil)
	r.SetPathValue("token", "does-not-exist")
	w := httptest.NewRecorder()

	h.HandleStart(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Invalid enrollment link") {
		t.Errorf("body missing invalid-link copy:\n%s", body)
	}
	// Must not leak whether the token ever existed.
	if strings.Contains(body, "expired") && !strings.Contains(body, "expired, already been used") {
		t.Errorf("body leaks token state:\n%s", body)
	}
}

func TestHandleComplete_HappyPathBindsKey(t *testing.T) {
	keys := &stubKeys{}
	sessStub := &stubSession{sess: &session.Session{ID: "sess-1", UserID: 7, ExpiresAt: time.Now().Add(time.Hour)}}
	userStub := &stubUser{u: &user.User{ID: 7, Email: "alice@example.com"}}
	h := newHandlers(t, sessStub, userStub, keys)

	token, err := h.Tokens.Mint("SHA256:abc", "ssh-ed25519", []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token+"/complete", nil)
	r.SetPathValue("token", token)
	r.Header.Set("User-Agent", "OpenSSH_9.6")
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "sess-1"})
	w := httptest.NewRecorder()

	h.HandleComplete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(keys.added) != 1 {
		t.Fatalf("keys.added len = %d, want 1", len(keys.added))
	}
	got := keys.added[0]
	if got.UserID != 7 || got.Fingerprint != "SHA256:abc" || got.KeyType != "ssh-ed25519" {
		t.Errorf("Add called with wrong row: %+v", got)
	}
	if !strings.Contains(got.Label, "OpenSSH_9.6") {
		t.Errorf("label = %q, want contains user agent", got.Label)
	}
	// Token must be consumed; second complete with same token must fail.
	r2 := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token+"/complete", nil)
	r2.SetPathValue("token", token)
	r2.AddCookie(&http.Cookie{Name: session.CookieName, Value: "sess-1"})
	w2 := httptest.NewRecorder()
	h.HandleComplete(w2, r2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("second complete status = %d, want 404", w2.Code)
	}
}

func TestHandleComplete_NoSessionCookieRedirectsToLogin(t *testing.T) {
	h := newHandlers(t, &stubSession{}, &stubUser{}, &stubKeys{})
	token, _ := h.Tokens.Mint("SHA256:abc", "ssh-ed25519", []byte{1})

	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token+"/complete", nil)
	r.SetPathValue("token", token)
	w := httptest.NewRecorder()

	h.HandleComplete(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/login?return_to=") {
		t.Errorf("Location = %q, want /auth/login redirect", loc)
	}
	if !strings.Contains(loc, token) {
		t.Errorf("Location does not preserve token: %q", loc)
	}
}

func TestHandleComplete_IdempotentReregisterForSameUser(t *testing.T) {
	keys := &stubKeys{
		addErr:  sshkey.ErrFingerprintTaken,
		getResp: &sshkey.Key{UserID: 7, Fingerprint: "SHA256:abc"},
	}
	sessStub := &stubSession{sess: &session.Session{ID: "sess-1", UserID: 7}}
	userStub := &stubUser{u: &user.User{ID: 7}}
	h := newHandlers(t, sessStub, userStub, keys)

	token, _ := h.Tokens.Mint("SHA256:abc", "ssh-ed25519", []byte{1})

	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token+"/complete", nil)
	r.SetPathValue("token", token)
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "sess-1"})
	w := httptest.NewRecorder()

	h.HandleComplete(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (idempotent success)", w.Code)
	}
}

func TestHandleComplete_KeyOwnedByDifferentUserRendersError(t *testing.T) {
	keys := &stubKeys{
		addErr:  sshkey.ErrFingerprintTaken,
		getResp: &sshkey.Key{UserID: 999, Fingerprint: "SHA256:abc"}, // different user
	}
	sessStub := &stubSession{sess: &session.Session{ID: "sess-1", UserID: 7}}
	userStub := &stubUser{u: &user.User{ID: 7}}
	h := newHandlers(t, sessStub, userStub, keys)

	token, _ := h.Tokens.Mint("SHA256:abc", "ssh-ed25519", []byte{1})

	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token+"/complete", nil)
	r.SetPathValue("token", token)
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "sess-1"})
	w := httptest.NewRecorder()

	h.HandleComplete(w, r)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "another Forge Utah user") {
		t.Errorf("body missing key-taken copy: %s", body)
	}
	// Must NOT leak the owning user's identity.
	if strings.Contains(body, "alice") || strings.Contains(body, "999") {
		t.Errorf("body leaks owner identity: %s", body)
	}
}

func TestHandleComplete_ExpiredTokenRenders404(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	clk := &t0
	store := NewStore(func() time.Time { return *clk })

	h := &Handlers{
		Tokens:   store,
		Sessions: &stubSession{sess: &session.Session{ID: "sess-1", UserID: 7}},
		Users:    &stubUser{u: &user.User{ID: 7}},
		Keys:     &stubKeys{},
		AuthHost: "auth.forgeut.dev",
	}
	token, _ := store.Mint("SHA256:abc", "ssh-ed25519", []byte{1})

	*clk = t0.Add(DefaultTTL + time.Second)

	r := httptest.NewRequest(http.MethodGet, "/ssh/enroll/"+token+"/complete", nil)
	r.SetPathValue("token", token)
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "sess-1"})
	w := httptest.NewRecorder()

	h.HandleComplete(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestEnrollURL_FormatMatchesPlan(t *testing.T) {
	h := New(NewStore(time.Now), nil, nil, nil, "auth.forgeut.dev")
	url := h.EnrollURL("abc-token")
	want := "https://auth.forgeut.dev/ssh/enroll/abc-token"
	if url != want {
		t.Errorf("EnrollURL = %q, want %q", url, want)
	}
}
