package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgeutah/forge-proxy/internal/user"
)

// testUser builds a User with predictable values for header-injection tests.
// Each field is distinct so a "wrong header read from wrong field" bug fails
// loudly.
func testUser() *user.User {
	return &user.User{
		ID:          42,
		SlackUserID: "U_REAL",
		SlackTeamID: "T_FORGE",
		Email:       "alice@forgeutah.tech",
		Name:        "Alice Real",
		AvatarURL:   "https://example.com/alice.png",
		Roles:       []string{"admin", "member"},
	}
}

// inboundReq builds a *http.Request shaped the way Go's net/http parsers
// would deliver it to the Rewrite hook — Header keys are canonical-cased.
// Tests add extra entries via the returned request's Header map.
func inboundReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://deuce.forgeutah.tech/foo", nil)
	return r
}

// TestSmugglingDefense_BaseCase_CoversAE6_R11 is the AE6 base-case test: a
// client supplying X-Forge-Roles: admin must NOT have that value reach the
// upstream. The outbound roles header reflects the DB-resolved user, not
// the client-supplied value. This is the core of R11's trust model.
func TestSmugglingDefense_BaseCase_CoversAE6_R11(t *testing.T) {
	r := inboundReq()
	r.Header.Set("X-Forge-Roles", "superadmin,owner")

	u := testUser()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", u)

	got := r.Header.Get("X-Forge-Roles")
	want := "admin,member"
	if got != want {
		t.Fatalf("X-Forge-Roles = %q, want %q (client value must not survive)", got, want)
	}
}

// TestSmugglingDefense_CaseFoldingStrip verifies that arbitrary case
// variations of the X-Forge-* prefix are still stripped. Go canonicalises
// header keys on entry so this is mostly belt-and-braces — but the test
// pins the behaviour against future regressions.
func TestSmugglingDefense_CaseFoldingStrip(t *testing.T) {
	cases := []string{
		"x-forge-roles",
		"X-FORGE-ROLES",
		"X-Forge-RoLeS",
		"x-FORGE-roles",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			r := inboundReq()
			r.Header.Set(key, "smuggled")
			stripForgeHeaders(r)
			injectForgeHeaders(r, "test-secret", testUser())

			got := r.Header.Get("X-Forge-Roles")
			if got != "admin,member" {
				t.Fatalf("X-Forge-Roles = %q, want %q (case variant %q must be stripped)", got, "admin,member", key)
			}
		})
	}
}

// TestSmugglingDefense_RelatedHeaders verifies that other identity headers
// from a client are also overwritten — not just roles. A client trying to
// claim X-Forge-Email and X-Forge-User-Id must fail.
func TestSmugglingDefense_RelatedHeaders(t *testing.T) {
	r := inboundReq()
	r.Header.Set("X-Forge-Email", "attacker@evil.com")
	r.Header.Set("X-Forge-User-Id", "999")
	r.Header.Set("X-Forge-Slack-User-Id", "U_FAKE")

	u := testUser()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", u)

	if got := r.Header.Get("X-Forge-Email"); got != u.Email {
		t.Fatalf("X-Forge-Email = %q, want %q", got, u.Email)
	}
	if got := r.Header.Get("X-Forge-User-Id"); got != "42" {
		t.Fatalf("X-Forge-User-Id = %q, want %q", got, "42")
	}
	if got := r.Header.Get("X-Forge-Slack-User-Id"); got != u.SlackUserID {
		t.Fatalf("X-Forge-Slack-User-Id = %q, want %q", got, u.SlackUserID)
	}
}

// TestSmugglingDefense_ProxySecretAttack verifies that a client supplying
// X-Forge-Proxy-Secret cannot influence what reaches the upstream. The
// outbound value is always the configured secret.
func TestSmugglingDefense_ProxySecretAttack(t *testing.T) {
	r := inboundReq()
	r.Header.Set("X-Forge-Proxy-Secret", "I-know-the-secret")

	stripForgeHeaders(r)
	injectForgeHeaders(r, "real-config-secret", testUser())

	got := r.Header.Get("X-Forge-Proxy-Secret")
	if got != "real-config-secret" {
		t.Fatalf("X-Forge-Proxy-Secret = %q, want %q", got, "real-config-secret")
	}
}

// TestSmugglingDefense_ContractVersion verifies the literal "1" emission —
// even if a client tries to claim a higher version, the outbound value is
// pinned.
func TestSmugglingDefense_ContractVersion(t *testing.T) {
	r := inboundReq()
	r.Header.Set("X-Forge-Contract-Version", "99")

	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", testUser())

	if got := r.Header.Get("X-Forge-Contract-Version"); got != "1" {
		t.Fatalf("X-Forge-Contract-Version = %q, want %q", got, "1")
	}
}

// TestSmugglingDefense_TrailerAnnouncement verifies Layer 2a of the strip:
// the comma-separated Trailer header announcement is filtered, removing any
// X-Forge-* names. When the list becomes empty, the Trailer header is
// deleted entirely.
func TestSmugglingDefense_TrailerAnnouncement(t *testing.T) {
	r := inboundReq()
	r.Header.Set("Trailer", "X-Forge-Roles, X-Forge-Email, Expires")

	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", testUser())

	got := r.Header.Get("Trailer")
	if strings.Contains(strings.ToLower(got), "x-forge") {
		t.Fatalf("Trailer header still mentions X-Forge-*: %q", got)
	}
	// The non-forge entry should survive.
	if got != "Expires" {
		t.Fatalf("Trailer = %q, want %q (non-Forge entries preserved)", got, "Expires")
	}
}

// TestSmugglingDefense_TrailerAnnouncement_AllForge verifies that when every
// entry in the Trailer announcement is an X-Forge-* name, the Trailer
// header is deleted entirely (not left as an empty string).
func TestSmugglingDefense_TrailerAnnouncement_AllForge(t *testing.T) {
	r := inboundReq()
	r.Header.Set("Trailer", "X-Forge-Roles, X-Forge-Email")

	stripForgeHeaders(r)

	if _, present := r.Header["Trailer"]; present {
		t.Fatalf("Trailer header still present after all-Forge strip: %v", r.Header["Trailer"])
	}
}

// TestSmugglingDefense_TrailerMap_CoversF5 verifies Layer 2b: the
// pr.Out.Trailer map (the actual trailer values that ride the chunked-
// transfer trailer section) is also scrubbed. This is the second axis of
// the F5 trailer fix.
func TestSmugglingDefense_TrailerMap_CoversF5(t *testing.T) {
	r := inboundReq()
	if r.Trailer == nil {
		r.Trailer = make(http.Header)
	}
	r.Trailer.Set("X-Forge-Roles", "admin")
	r.Trailer.Set("Expires", "0")

	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", testUser())

	if got := r.Trailer.Get("X-Forge-Roles"); got != "" {
		t.Fatalf("Trailer map still contains X-Forge-Roles = %q", got)
	}
	if got := r.Trailer.Get("Expires"); got != "0" {
		t.Fatalf("non-Forge trailer Expires = %q, want %q", got, "0")
	}
	// And the headers map carries the trusted value (not the trailer's).
	if got := r.Header.Get("X-Forge-Roles"); got != "admin,member" {
		t.Fatalf("X-Forge-Roles header = %q, want trusted %q", got, "admin,member")
	}
}

// TestSmugglingDefense_DuplicateValueAttack verifies Layer 3 (Del-before-Set).
// http.Header is a map of []string; if a sibling code path landed a slice
// of multiple values on the X-Forge-* key, a naïve Set would only overwrite
// the first index. The Del-before-Set guarantees a single trusted value.
func TestSmugglingDefense_DuplicateValueAttack(t *testing.T) {
	r := inboundReq()
	// Manually plant a multi-value slice under the canonical key, mimicking
	// what would happen if a Layer 1 / Layer 2 strip somehow missed an entry.
	r.Header["X-Forge-Roles"] = []string{"superadmin", "owner"}

	// Skip the strip layer to specifically exercise Layer 3 — even if
	// Layer 1 missed, Layer 3 must clean up.
	injectForgeHeaders(r, "test-secret", testUser())

	values := r.Header.Values("X-Forge-Roles")
	if len(values) != 1 {
		t.Fatalf("X-Forge-Roles has %d values %v, want exactly 1", len(values), values)
	}
	if values[0] != "admin,member" {
		t.Fatalf("X-Forge-Roles[0] = %q, want %q", values[0], "admin,member")
	}
}

// TestSmugglingDefense_CookieStrip verifies Layer 4: the forge_session
// cookie is removed from the outbound Cookie header before forwarding to the
// upstream. Upstreams authenticate via the X-Forge-* contract; the raw
// session ID is a bearer credential they have no need to log or replay.
//
// Catches the security finding where a curious or compromised upstream
// could lift the session ID from its access logs and replay it against any
// other *.forgeutah.tech app or against the auth host.
func TestSmugglingDefense_CookieStrip(t *testing.T) {
	r := inboundReq()
	r.Header.Set("Cookie", "forge_session=secret-bearer; preference=darkmode")
	u := testUser()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "the-real-secret", u)

	got := r.Header.Get("Cookie")
	if strings.Contains(got, "forge_session") {
		t.Fatalf("outbound Cookie still contains forge_session: %q", got)
	}
	if !strings.Contains(got, "preference=darkmode") {
		t.Fatalf("outbound Cookie dropped unrelated cookie: %q", got)
	}
}

// TestSmugglingDefense_CookieStrip_OnlyForgeSession verifies that when the
// inbound Cookie header contains ONLY the forge_session cookie, the entire
// header is removed (no empty Cookie header lingers on the outbound request).
func TestSmugglingDefense_CookieStrip_OnlyForgeSession(t *testing.T) {
	r := inboundReq()
	r.Header.Set("Cookie", "forge_session=only-cookie")
	u := testUser()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "the-real-secret", u)

	if got, ok := r.Header["Cookie"]; ok {
		t.Fatalf("outbound Cookie header should be absent; got %q", got)
	}
}

// TestSmugglingDefense_CookieStrip_MultipleHeaders covers the edge case where
// clients send Cookie as multiple header values rather than one
// "; "-separated string. Each value is processed independently.
func TestSmugglingDefense_CookieStrip_MultipleHeaders(t *testing.T) {
	r := inboundReq()
	r.Header["Cookie"] = []string{
		"forge_session=secret-bearer",
		"preference=darkmode; locale=en",
	}
	u := testUser()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "the-real-secret", u)

	values, _ := r.Header["Cookie"]
	for _, v := range values {
		if strings.Contains(v, "forge_session") {
			t.Fatalf("outbound Cookie value still contains forge_session: %q", v)
		}
	}
	joined := strings.Join(values, " ")
	if !strings.Contains(joined, "preference=darkmode") || !strings.Contains(joined, "locale=en") {
		t.Fatalf("unrelated cookies dropped; outbound = %q", values)
	}
}

// TestNonASCIIName_RFC8187Encoded verifies the X-Forge-Name encoding choice:
// non-ASCII display names (e.g. emoji-laden Slack profiles) round-trip as
// RFC 8187 percent-encoded UTF-8 prefixed with "UTF-8''".
func TestNonASCIIName_RFC8187Encoded(t *testing.T) {
	r := inboundReq()
	u := testUser()
	u.Name = "Clint 🔥"

	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", u)

	got := r.Header.Get("X-Forge-Name")
	// Validate the RFC 8187 shape: "UTF-8''" prefix followed by ASCII-only
	// percent-encoded form. The exact percent-encoding of "Clint 🔥" is
	// "Clint%20%F0%9F%94%A5".
	const want = "UTF-8''Clint%20%F0%9F%94%A5"
	if got != want {
		t.Fatalf("X-Forge-Name = %q, want %q", got, want)
	}

	// Belt-and-braces: confirm the value is pure ASCII so it travels safely
	// over HTTP/1.1 (which is technically ASCII-only for header values).
	for i := range len(got) {
		if got[i] >= 0x80 {
			t.Fatalf("X-Forge-Name contains non-ASCII byte 0x%02x at %d", got[i], i)
		}
	}
}

// TestASCIIName_PassThrough verifies that pure-ASCII display names pass
// through unchanged (no spurious encoding overhead).
func TestASCIIName_PassThrough(t *testing.T) {
	r := inboundReq()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", testUser()) // testUser().Name == "Alice Real"

	if got := r.Header.Get("X-Forge-Name"); got != "Alice Real" {
		t.Fatalf("X-Forge-Name = %q, want %q (pure ASCII should pass through)", got, "Alice Real")
	}
}

// TestEmptyRolesSlice verifies that a user with no roles emits an empty
// X-Forge-Roles header (present but empty). The Upstream-App Contract
// specifies "empty = no elevated roles", so a missing header would be a
// contract violation.
func TestEmptyRolesSlice(t *testing.T) {
	r := inboundReq()
	u := testUser()
	u.Roles = []string{}

	stripForgeHeaders(r)
	injectForgeHeaders(r, "test-secret", u)

	values := r.Header.Values("X-Forge-Roles")
	if len(values) != 1 {
		t.Fatalf("X-Forge-Roles has %d entries, want exactly 1 (present-but-empty)", len(values))
	}
	if values[0] != "" {
		t.Fatalf("X-Forge-Roles = %q, want \"\"", values[0])
	}
}

// TestAllNineHeadersInjected pins the public contract surface: every one of
// the nine documented headers is present on outbound, with values matching
// the user fields.
func TestAllNineHeadersInjected(t *testing.T) {
	r := inboundReq()
	u := testUser()
	stripForgeHeaders(r)
	injectForgeHeaders(r, "config-secret", u)

	want := map[string]string{
		"X-Forge-Proxy-Secret":     "config-secret",
		"X-Forge-Contract-Version": "1",
		"X-Forge-User-Id":          "42",
		"X-Forge-Email":            "alice@forgeutah.tech",
		"X-Forge-Name":             "Alice Real",
		"X-Forge-Avatar":           "https://example.com/alice.png",
		"X-Forge-Roles":            "admin,member",
		"X-Forge-Slack-User-Id":    "U_REAL",
		"X-Forge-Slack-Team-Id":    "T_FORGE",
	}
	for name, expected := range want {
		if got := r.Header.Get(name); got != expected {
			t.Errorf("%s = %q, want %q", name, got, expected)
		}
	}
}

// TestPercentEncode_Unreserved sanity-checks the percent-encoder: bytes in
// the RFC 3986 unreserved set pass through; everything else is encoded.
func TestPercentEncode_Unreserved(t *testing.T) {
	// Unreserved: A-Z a-z 0-9 - . _ ~
	pass := "ABC-abc_123.tilde~"
	got := percentEncodeUTF8(pass)
	if got != pass {
		t.Fatalf("percentEncodeUTF8(%q) = %q, want unchanged", pass, got)
	}
	// Space encodes as %20 (not '+').
	got = percentEncodeUTF8("a b")
	if got != "a%20b" {
		t.Fatalf("percentEncodeUTF8(%q) = %q, want %q", "a b", got, "a%20b")
	}
}
