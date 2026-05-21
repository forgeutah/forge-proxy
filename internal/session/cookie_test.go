package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCookieName_IsForgeSession pins the wire-name. Changing this value is a
// breaking change that would log every Forge user out — the test exists
// specifically to make that change loud.
func TestCookieName_IsForgeSession(t *testing.T) {
	if CookieName != "forge_session" {
		t.Errorf("CookieName = %q, want %q", CookieName, "forge_session")
	}
}

// parseSetCookie pulls the Set-Cookie header off a ResponseRecorder and
// returns it as an *http.Cookie. We deliberately use net/http's parser
// (rather than ad-hoc string splitting) so the assertions exercise the same
// code the browser-facing test surface would.
func parseSetCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	resp := http.Response{Header: rr.Header()}
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			return c
		}
	}
	t.Fatalf("no Set-Cookie for %q in %v", CookieName, rr.Header())
	return nil
}

// TestSet_EmitsExpectedFlags is the security-critical assertion: the cookie
// MUST be HttpOnly, Secure, SameSite=Lax, scoped to the configured domain,
// and rooted at "/". A flag regression here is a vulnerability.
//
// Note on Domain: Go's net/http normalizes a leading dot away on the wire
// (RFC 6265 says `Domain=forgeutah.tech` and `Domain=.forgeutah.tech` are
// semantically equivalent — both scope to forgeutah.tech and all
// subdomains). We pass the configured `.forgeutah.tech` in and assert the
// stripped form is what the parser sees, matching what the browser will
// observe.
func TestSet_EmitsExpectedFlags(t *testing.T) {
	rr := httptest.NewRecorder()
	expires := time.Now().Add(14 * 24 * time.Hour)
	Set(rr, "sid-abc", expires, ".forgeutah.tech")

	c := parseSetCookie(t, rr)
	if c.Value != "sid-abc" {
		t.Errorf("Value = %q, want %q", c.Value, "sid-abc")
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	// Go strips the leading dot; the wire form is "forgeutah.tech".
	if c.Domain != "forgeutah.tech" {
		t.Errorf("Domain = %q, want %q", c.Domain, "forgeutah.tech")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	// Expires within a second of what we asked for. http.Cookie truncates to
	// whole seconds; we don't care about sub-second drift.
	if delta := c.Expires.Sub(expires); delta > time.Second || delta < -time.Second {
		t.Errorf("Expires = %v, want ~%v", c.Expires, expires)
	}
}

// TestClear_EmitsDeletionCookie verifies the Clear contract: same name,
// same domain, same path as Set, with MaxAge=-1 so browsers delete the
// cookie immediately.
func TestClear_EmitsDeletionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	Clear(rr, ".forgeutah.tech")

	c := parseSetCookie(t, rr)
	if c.Value != "" {
		t.Errorf("Value = %q, want empty", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", c.MaxAge)
	}
	if c.Domain != "forgeutah.tech" {
		t.Errorf("Domain = %q, want %q", c.Domain, "forgeutah.tech")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	if !c.HttpOnly {
		t.Error("Clear cookie should keep HttpOnly")
	}
	if !c.Secure {
		t.Error("Clear cookie should keep Secure")
	}
}

// TestRead_ExtractsSessionID is the happy-path read: a request carrying the
// session cookie returns its value.
func TestRead_ExtractsSessionID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://auth.forgeutah.tech/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-xyz"})

	id, ok := Read(req)
	if !ok {
		t.Fatal("Read returned ok=false for present cookie")
	}
	if id != "sid-xyz" {
		t.Errorf("Read = %q, want %q", id, "sid-xyz")
	}
}

// TestRead_MissingCookie returns the zero values, not an error. The plan
// makes this an "absent vs present" boolean so call sites can branch
// cleanly.
func TestRead_MissingCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://auth.forgeutah.tech/", nil)

	id, ok := Read(req)
	if ok {
		t.Errorf("Read returned ok=true for missing cookie, id=%q", id)
	}
	if id != "" {
		t.Errorf("Read id = %q, want empty", id)
	}
}

// TestSetThenRead_RoundTrips is the integration assertion the plan calls for:
// the value that Set writes can be parsed back off a fresh request whose
// Cookie header is built from the recorded Set-Cookie.
func TestSetThenRead_RoundTrips(t *testing.T) {
	rr := httptest.NewRecorder()
	expires := time.Now().Add(24 * time.Hour)
	Set(rr, "round-trip-sid", expires, ".forgeutah.tech")

	// Build a Request whose Cookie header echoes the Set-Cookie value.
	written := parseSetCookie(t, rr)
	req := httptest.NewRequest(http.MethodGet, "https://auth.forgeutah.tech/", nil)
	req.AddCookie(&http.Cookie{Name: written.Name, Value: written.Value})

	id, ok := Read(req)
	if !ok {
		t.Fatal("Read after Set: ok=false")
	}
	if id != "round-trip-sid" {
		t.Errorf("Read = %q, want %q", id, "round-trip-sid")
	}
}
