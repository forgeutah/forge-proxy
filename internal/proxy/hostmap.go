package proxy

import (
	"strings"

	"github.com/forgeutah/forge-proxy/internal/config"
)

// HostMap resolves an inbound HTTP Host header to the configured upstream —
// both where to forward and which roles gate the forward. The map is built
// once at startup from the UPSTREAMS env var and is read-only thereafter, so
// no synchronisation is needed.
//
// Route and role requirement live in one entry rather than two parallel maps
// keyed on host: a second map could drift out of step with this one, and a
// host present in the route map but missing from the role map would silently
// serve ungated.
//
// Host header normalisation: per RFC 7230 §5.4, Host comparisons are
// case-insensitive. Browsers occasionally send a capitalised Host (e.g.
// after a redirect chain through a stripped-down intermediary), and the
// config map is keyed on lowercase entries. Resolve lowercases the lookup
// key so "Deuce.Forgeutah.Tech" still finds the "deuce.forgeutah.tech"
// upstream. Any port suffix on the inbound Host is stripped before lookup —
// the proxy listens on a single port and the upstream-map keys are bare
// hostnames.
type HostMap map[string]config.Upstream

// NewHostMap copies the supplied map (normalising keys to lowercase) so the
// caller can hand us the config-loaded map without worrying about us mutating
// it. nil input yields an empty (non-nil) HostMap so callers can always range
// or look up without a nil check.
func NewHostMap(upstreams map[string]config.Upstream) HostMap {
	m := make(HostMap, len(upstreams))
	for host, u := range upstreams {
		m[strings.ToLower(host)] = u
	}
	return m
}

// Resolve returns the upstream entry for the given inbound Host header value,
// or (zero, false) if no entry matches. The host is compared
// case-insensitively and any ":port" suffix is stripped before lookup (Host
// values commonly include a port; the upstream-map keys do not).
//
// Returning false for unknown hosts (rather than a sentinel error) is
// deliberate: the HTTP-layer caller renders a 404 with a branded "unknown
// Forge app" page, which is a different response shape than the 502 we'd
// emit for an upstream that exists but fails. Distinguishing the two at the
// boundary keeps the error-handling explicit.
func (m HostMap) Resolve(host string) (config.Upstream, bool) {
	u, ok := m[NormalizeHost(host)]
	return u, ok
}

// NormalizeHost applies the canonical Host header normalisation rule used
// throughout the proxy: lowercase the value and strip any ":port" suffix.
// Exported so the host-dispatching layer in cmd/forge-proxy/main.go can apply
// the same rule when comparing inbound Host against the configured auth host
// — one normalisation function, one place.
func NormalizeHost(host string) string {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// Hosts returns the configured inbound hosts in arbitrary order. Used by the
// 404 page so an operator typo'ing into the browser sees the list of known
// apps. Not exposed externally.
func (m HostMap) Hosts() []string {
	out := make([]string, 0, len(m))
	for h := range m {
		out = append(out, h)
	}
	return out
}
