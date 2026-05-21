package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewPreAuth_TokenShape(t *testing.T) {
	p, err := NewPreAuth("https://deuce.forgeutah.tech/x")
	if err != nil {
		t.Fatalf("NewPreAuth: %v", err)
	}
	// 32 random bytes → 43 base64url no-padding characters.
	if len(p.State) != 43 {
		t.Fatalf("state length = %d, want 43", len(p.State))
	}
	if len(p.Nonce) != 43 {
		t.Fatalf("nonce length = %d, want 43", len(p.Nonce))
	}
	if p.State == p.Nonce {
		t.Fatalf("state and nonce must be independent random values")
	}
	if p.ReturnTo != "https://deuce.forgeutah.tech/x" {
		t.Fatalf("returnTo = %q, want preserved", p.ReturnTo)
	}
}

func TestSetPreAuth_HostPrefixAndFlags(t *testing.T) {
	// __Host- prefix forbids a Domain attribute and requires Secure +
	// Path=/. This test asserts the raw Set-Cookie header so a regression
	// (e.g. someone adding cfg.CookieDomain by mistake) is caught.
	rec := httptest.NewRecorder()
	p, err := NewPreAuth("https://forgeutah.tech/")
	if err != nil {
		t.Fatalf("NewPreAuth: %v", err)
	}
	if err := SetPreAuth(rec, p); err != nil {
		t.Fatalf("SetPreAuth: %v", err)
	}
	hdr := rec.Header().Get("Set-Cookie")
	if hdr == "" {
		t.Fatalf("Set-Cookie header missing")
	}
	if !strings.HasPrefix(hdr, "__Host-forge_pre_auth=") {
		t.Fatalf("cookie name = %q, want __Host-forge_pre_auth=...", hdr)
	}
	if strings.Contains(strings.ToLower(hdr), "domain=") {
		t.Fatalf("__Host- cookie must not have Domain= attribute, got: %s", hdr)
	}
	if !strings.Contains(hdr, "Path=/") {
		t.Fatalf("missing Path=/: %s", hdr)
	}
	if !strings.Contains(hdr, "HttpOnly") {
		t.Fatalf("missing HttpOnly: %s", hdr)
	}
	if !strings.Contains(hdr, "Secure") {
		t.Fatalf("missing Secure: %s", hdr)
	}
	if !strings.Contains(hdr, "SameSite=Lax") {
		t.Fatalf("missing SameSite=Lax: %s", hdr)
	}
	if !strings.Contains(hdr, "Max-Age=600") {
		t.Fatalf("missing Max-Age=600: %s", hdr)
	}
}

func TestReadPreAuth_Roundtrip(t *testing.T) {
	rec := httptest.NewRecorder()
	p := &PreAuthPayload{
		State:    "stateValueAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Nonce:    "nonceValueBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		ReturnTo: "https://deuce.forgeutah.tech/path?q=1#frag",
	}
	if err := SetPreAuth(rec, p); err != nil {
		t.Fatalf("SetPreAuth: %v", err)
	}

	// Build a request that carries the cookies the recorder just wrote.
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=x", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	got, err := ReadPreAuth(r)
	if err != nil {
		t.Fatalf("ReadPreAuth: %v", err)
	}
	if got.State != p.State || got.Nonce != p.Nonce || got.ReturnTo != p.ReturnTo {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, p)
	}
}

func TestReadPreAuth_Missing(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	_, err := ReadPreAuth(r)
	if !errors.Is(err, ErrMissingPreAuth) {
		t.Fatalf("ReadPreAuth err = %v; want ErrMissingPreAuth", err)
	}
}

func TestReadPreAuth_Corrupt(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	r.AddCookie(&http.Cookie{Name: PreAuthCookieName, Value: "not-base64$$$"})
	if _, err := ReadPreAuth(r); !errors.Is(err, ErrCorruptPreAuth) {
		t.Fatalf("ReadPreAuth(corrupt) err = %v; want ErrCorruptPreAuth", err)
	}
}

func TestClearPreAuth_DeletionMarker(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearPreAuth(rec)
	hdr := rec.Header().Get("Set-Cookie")
	if hdr == "" {
		t.Fatalf("Clear emitted no Set-Cookie")
	}
	if !strings.HasPrefix(hdr, "__Host-forge_pre_auth=;") {
		t.Fatalf("deletion cookie should have empty value: %s", hdr)
	}
	if !strings.Contains(hdr, "Max-Age=0") {
		t.Fatalf("deletion cookie should have Max-Age=0 (Go's representation of MaxAge=-1): %s", hdr)
	}
	if strings.Contains(strings.ToLower(hdr), "domain=") {
		t.Fatalf("__Host- deletion must not have Domain=: %s", hdr)
	}
}
