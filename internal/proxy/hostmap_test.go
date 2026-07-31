package proxy

import (
	"net/url"
	"slices"
	"testing"

	"github.com/forgeutah/forge-proxy/internal/config"
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

// ungated builds an upstream entry reachable by any authenticated member —
// the shape every entry had before role gating existed.
func ungated(t *testing.T, raw string) config.Upstream {
	t.Helper()
	return config.Upstream{Target: mustParseURL(t, raw)}
}

// TestHostMap_Resolve_KnownHost covers the happy path: a host configured at
// startup resolves to its upstream target.
func TestHostMap_Resolve_KnownHost(t *testing.T) {
	deuce := ungated(t, "http://deuce-stub.internal:8080")
	platform := ungated(t, "http://platform-stub.internal:8080")
	m := NewHostMap(map[string]config.Upstream{
		"deuce.forgeutah.tech":    deuce,
		"platform.forgeutah.tech": platform,
	})

	got, ok := m.Resolve("deuce.forgeutah.tech")
	if !ok {
		t.Fatalf("Resolve(deuce): ok=false, want true")
	}
	if got.Target.String() != deuce.Target.String() {
		t.Fatalf("Resolve(deuce) = %q, want %q", got.Target, deuce.Target)
	}
}

// TestHostMap_Resolve_CarriesRequiredRoles verifies the role allowlist
// survives construction and lookup — the gate reads it straight off the
// resolved entry, so a dropped list would silently serve a gated app to
// everyone.
func TestHostMap_Resolve_CarriesRequiredRoles(t *testing.T) {
	m := NewHostMap(map[string]config.Upstream{
		"deuce.forgeutah.tech": {
			Target:        mustParseURL(t, "http://deuce-stub"),
			RequiredRoles: []string{"ai-dev", "admin"},
		},
		"wiki.forgeutah.tech": ungated(t, "http://wiki-stub"),
	})

	gated, ok := m.Resolve("deuce.forgeutah.tech")
	if !ok {
		t.Fatal("Resolve(deuce): ok=false, want true")
	}
	if want := []string{"ai-dev", "admin"}; !slices.Equal(gated.RequiredRoles, want) {
		t.Errorf("deuce RequiredRoles = %v, want %v", gated.RequiredRoles, want)
	}
	if !gated.Gated() {
		t.Error("deuce should report gated")
	}

	open, ok := m.Resolve("wiki.forgeutah.tech")
	if !ok {
		t.Fatal("Resolve(wiki): ok=false, want true")
	}
	if len(open.RequiredRoles) != 0 {
		t.Errorf("wiki RequiredRoles = %v, want none", open.RequiredRoles)
	}
	if open.Gated() {
		t.Error("wiki should report ungated")
	}
}

// TestHostMap_Resolve_UnknownHost verifies the missing-host signal that the
// HTTP-layer 404 branch keys off.
func TestHostMap_Resolve_UnknownHost(t *testing.T) {
	m := NewHostMap(map[string]config.Upstream{
		"deuce.forgeutah.tech": ungated(t, "http://deuce-stub"),
	})

	got, ok := m.Resolve("nope.forgeutah.tech")
	if ok {
		t.Fatalf("Resolve(nope): ok=true with got=%v, want ok=false", got)
	}
	if got.Target != nil {
		t.Fatalf("Resolve(nope): got.Target=%v, want nil", got.Target)
	}
}

// TestHostMap_Resolve_CaseInsensitive verifies the RFC 7230 §5.4
// case-insensitive comparison — a browser sending "Deuce.Forgeutah.Tech"
// must still find the lower-cased map entry, roles included.
func TestHostMap_Resolve_CaseInsensitive(t *testing.T) {
	deuce := config.Upstream{
		Target:        mustParseURL(t, "http://deuce-stub"),
		RequiredRoles: []string{"ai-dev"},
	}
	m := NewHostMap(map[string]config.Upstream{
		"deuce.forgeutah.tech": deuce,
	})

	cases := []string{
		"DEUCE.FORGEUTAH.TECH",
		"Deuce.Forgeutah.Tech",
		"deuce.FORGEUTAH.tech",
	}
	for _, host := range cases {
		got, ok := m.Resolve(host)
		if !ok || got.Target.String() != deuce.Target.String() {
			t.Fatalf("Resolve(%q) = (%v, %v), want match", host, got.Target, ok)
		}
		if !slices.Equal(got.RequiredRoles, deuce.RequiredRoles) {
			t.Fatalf("Resolve(%q) roles = %v, want %v", host, got.RequiredRoles, deuce.RequiredRoles)
		}
	}
}

// TestHostMap_Resolve_StripsPort verifies that a Host header carrying an
// explicit port still finds the bare-hostname map entry.
func TestHostMap_Resolve_StripsPort(t *testing.T) {
	deuce := ungated(t, "http://deuce-stub")
	m := NewHostMap(map[string]config.Upstream{
		"deuce.forgeutah.tech": deuce,
	})

	got, ok := m.Resolve("deuce.forgeutah.tech:8080")
	if !ok {
		t.Fatalf("Resolve(deuce:8080): ok=false, want true")
	}
	if got.Target.String() != deuce.Target.String() {
		t.Fatalf("Resolve(deuce:8080) = %q, want %q", got.Target, deuce.Target)
	}
}

// TestHostMap_NormalisesEntryKeys verifies that uppercase keys in the
// supplied map are normalised at construction time — config could
// theoretically ship a mixed-case host string and the lookup should still
// hit.
func TestHostMap_NormalisesEntryKeys(t *testing.T) {
	deuce := ungated(t, "http://deuce-stub")
	m := NewHostMap(map[string]config.Upstream{
		"Deuce.Forgeutah.Tech": deuce,
	})

	got, ok := m.Resolve("deuce.forgeutah.tech")
	if !ok || got.Target.String() != deuce.Target.String() {
		t.Fatalf("Resolve(deuce) after mixed-case insert = (%v, %v), want match", got.Target, ok)
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
