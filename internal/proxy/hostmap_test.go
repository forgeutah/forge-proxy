package proxy

import (
	"net/url"
	"testing"
)

// mustParseURL is a test helper — fatals on a bad URL string so individual
// test cases stay one-liners.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// TestHostMap_Resolve_KnownHost covers the happy path: a host configured at
// startup resolves to its upstream URL.
func TestHostMap_Resolve_KnownHost(t *testing.T) {
	deuce := mustParseURL(t, "http://deuce-stub.internal:8080")
	platform := mustParseURL(t, "http://platform-stub.internal:8080")
	m := NewHostMap(map[string]*url.URL{
		"deuce.forgeutah.tech":    deuce,
		"platform.forgeutah.tech": platform,
	})

	got, ok := m.Resolve("deuce.forgeutah.tech")
	if !ok {
		t.Fatalf("Resolve(deuce): ok=false, want true")
	}
	if got.String() != deuce.String() {
		t.Fatalf("Resolve(deuce) = %q, want %q", got, deuce)
	}
}

// TestHostMap_Resolve_UnknownHost verifies the missing-host signal that the
// HTTP-layer 404 branch keys off.
func TestHostMap_Resolve_UnknownHost(t *testing.T) {
	m := NewHostMap(map[string]*url.URL{
		"deuce.forgeutah.tech": mustParseURL(t, "http://deuce-stub"),
	})

	got, ok := m.Resolve("nope.forgeutah.tech")
	if ok {
		t.Fatalf("Resolve(nope): ok=true with got=%q, want ok=false", got)
	}
	if got != nil {
		t.Fatalf("Resolve(nope): got=%v, want nil", got)
	}
}

// TestHostMap_Resolve_CaseInsensitive verifies the RFC 7230 §5.4
// case-insensitive comparison — a browser sending "Deuce.Forgeutah.Tech"
// must still find the lower-cased map entry.
func TestHostMap_Resolve_CaseInsensitive(t *testing.T) {
	deuce := mustParseURL(t, "http://deuce-stub")
	m := NewHostMap(map[string]*url.URL{
		"deuce.forgeutah.tech": deuce,
	})

	cases := []string{
		"DEUCE.FORGEUTAH.TECH",
		"Deuce.Forgeutah.Tech",
		"deuce.FORGEUTAH.tech",
	}
	for _, host := range cases {
		got, ok := m.Resolve(host)
		if !ok || got.String() != deuce.String() {
			t.Fatalf("Resolve(%q) = (%v, %v), want match", host, got, ok)
		}
	}
}

// TestHostMap_Resolve_StripsPort verifies that a Host header carrying an
// explicit port still finds the bare-hostname map entry.
func TestHostMap_Resolve_StripsPort(t *testing.T) {
	deuce := mustParseURL(t, "http://deuce-stub")
	m := NewHostMap(map[string]*url.URL{
		"deuce.forgeutah.tech": deuce,
	})

	got, ok := m.Resolve("deuce.forgeutah.tech:8080")
	if !ok {
		t.Fatalf("Resolve(deuce:8080): ok=false, want true")
	}
	if got.String() != deuce.String() {
		t.Fatalf("Resolve(deuce:8080) = %q, want %q", got, deuce)
	}
}

// TestHostMap_NormalisesEntryKeys verifies that uppercase keys in the
// supplied map are normalised at construction time — config could
// theoretically ship a mixed-case host string and the lookup should still
// hit.
func TestHostMap_NormalisesEntryKeys(t *testing.T) {
	deuce := mustParseURL(t, "http://deuce-stub")
	m := NewHostMap(map[string]*url.URL{
		"Deuce.Forgeutah.Tech": deuce,
	})

	got, ok := m.Resolve("deuce.forgeutah.tech")
	if !ok || got.String() != deuce.String() {
		t.Fatalf("Resolve(deuce) after mixed-case insert = (%v, %v), want match", got, ok)
	}
}

// TestHostMap_NilUpstreamMap verifies that a nil input map yields an empty
// (but usable) HostMap. Defends against a partially-loaded config.
func TestHostMap_NilUpstreamMap(t *testing.T) {
	m := NewHostMap(nil)
	if m == nil {
		t.Fatalf("NewHostMap(nil) = nil, want non-nil empty map")
	}
	if _, ok := m.Resolve("anything"); ok {
		t.Fatalf("Resolve on empty map returned ok=true")
	}
	if hosts := m.Hosts(); len(hosts) != 0 {
		t.Fatalf("Hosts on empty map = %v, want empty", hosts)
	}
}
