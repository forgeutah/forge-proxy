package proxy

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/forgeutah/forge-proxy/internal/user"
)

// Header names emitted on every authenticated request to an upstream. These
// are public contract surface (the Upstream-App Contract in the plan): apps
// read them by name, and any rename or semantic change requires a bump to
// X-Forge-Contract-Version. Keep them in one place so a code search lands
// here.
//
// Future rotation hook: the proxy currently emits a single
// X-Forge-Proxy-Secret value from cfg.ProxySecret. To support coordinated
// rotation (apps temporarily accepting "current,previous" during a redeploy
// window), apps should parse the configured allowed-secret list on their
// side — the proxy's job is to emit the *new* secret, and the apps' job is
// to accept either during the rotation window. The single-string emission
// here keeps that contract simple on the proxy side.
const (
	headerProxySecret     = "X-Forge-Proxy-Secret"
	headerContractVersion = "X-Forge-Contract-Version"
	headerUserID          = "X-Forge-User-Id"
	headerEmail           = "X-Forge-Email"
	headerName            = "X-Forge-Name"
	headerAvatar          = "X-Forge-Avatar"
	headerRoles           = "X-Forge-Roles"
	headerSlackUserID     = "X-Forge-Slack-User-Id"
	headerSlackTeamID     = "X-Forge-Slack-Team-Id"

	// contractVersion is the literal value emitted in X-Forge-Contract-Version.
	// Bumps when the header shape changes incompatibly.
	contractVersion = "1"

	// forgeHeaderPrefix is the canonical-cased prefix every Forge-trusted
	// outbound header begins with. The strip loop matches case-insensitively
	// against this prefix.
	forgeHeaderPrefix = "X-Forge-"
)


// stripForgeHeaders is the three-layer strip described in the plan's U8
// approach. It runs BEFORE injectForgeHeaders so the trusted Set calls
// always land on a clean slate.
//
// Layer 1 — header prefix strip: iterate pr.Out.Header and Del any key
// whose canonical form starts with "X-Forge-" (case-insensitive). Go's
// http.Header keys are stored canonical-cased on entry, so this loop is
// case-insensitive in practice; we still HasPrefix-compare against
// the canonical mixed-case prefix for clarity. The trust anchor is Go's
// HTTP/1.1 and HTTP/2 parsers rejecting obs-fold and non-ASCII header
// names at parse time, so a smuggled "X-Forge-Roles\r" or similar never
// reaches this loop.
//
// Layer 2 — trailer strip: the "Trailer" request header announces which
// headers will appear in the chunked trailer section. Both the announcement
// (a comma-separated list of names in the Trailer header value) AND the
// actual trailer values (in the http.Header map pr.Out.Trailer) are
// attack vectors. We:
//
//   - Parse the "Trailer" header's comma-separated value and remove any
//     entries naming an X-Forge-* header. If the resulting list is empty,
//     delete the Trailer header entirely.
//   - Iterate pr.Out.Trailer (the map of actual trailer values) and Del
//     any key whose canonical form has the X-Forge-* prefix. Even if the
//     announcement layer missed something (parser quirks, multiple Trailer
//     headers), the actual trailer values still get scrubbed.
//
// Layer 3 — Del-before-Set: lives in injectForgeHeaders. http.Header is a
// map of []string; a bare Set replaces the slice, but if our prefix loop
// missed a variant the Set could coalesce with existing values. Doing a
// Del immediately before each Set is a third belt-and-braces layer.
func stripForgeHeaders(out *http.Request) {
	// Layer 1: prefix strip on the main header map.
	for k := range out.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), forgeHeaderPrefix) {
			out.Header.Del(k)
		}
	}

	// Layer 2a: filter the Trailer header's comma-separated announcement.
	// http.Header may carry multiple Trailer headers (rare but legal); we
	// process each value, rebuild the cleaned list, and re-Set the result.
	if trailers, ok := out.Header[http.CanonicalHeaderKey("Trailer")]; ok {
		cleaned := make([]string, 0, len(trailers))
		for _, t := range trailers {
			kept := make([]string, 0)
			for entry := range strings.SplitSeq(t, ",") {
				name := strings.TrimSpace(entry)
				if name == "" {
					continue
				}
				if strings.HasPrefix(http.CanonicalHeaderKey(name), forgeHeaderPrefix) {
					continue
				}
				kept = append(kept, name)
			}
			if len(kept) > 0 {
				cleaned = append(cleaned, strings.Join(kept, ", "))
			}
		}
		if len(cleaned) == 0 {
			out.Header.Del("Trailer")
		} else {
			out.Header["Trailer"] = cleaned
		}
	}

	// Layer 2b: scrub the actual trailer header map. ReverseProxy forwards
	// any entries in Request.Trailer through to the upstream's request
	// trailers, so a hostile client populating Request.Trailer with
	// "X-Forge-Roles: admin" would bypass Layer 1.
	for k := range out.Trailer {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), forgeHeaderPrefix) {
			out.Trailer.Del(k)
		}
	}
}

// injectForgeHeaders writes the nine trusted X-Forge-* headers, performing a
// Del-before-Set on each (Layer 3). The Set order matches the pairs slice
// declared below.
//
// The Name field is potentially non-ASCII (Slack display names can include
// emoji and other characters above 0x7f). HTTP/1.1 header values are
// technically constrained to ASCII printable bytes; Go's net/http will
// happily transmit non-ASCII over the wire but it's outside the protocol
// guarantees and confuses some HTTP libraries on the receiving end. We
// encode per RFC 8187 ("UTF-8''<percent-encoded>") so the wire value is
// always ASCII-safe and the upstream contract is portable. Pure-ASCII names
// pass through unchanged.
func injectForgeHeaders(out *http.Request, proxySecret string, u *user.User) {
	// Pairs are listed in the wire-order they're emitted. A single ordered
	// list (rather than a parallel slice+map) means a future header addition
	// is a one-line edit; the compiler still catches a typo'd header constant.
	pairs := [...]struct{ name, value string }{
		{headerProxySecret, proxySecret},
		{headerContractVersion, contractVersion},
		{headerUserID, strconv.FormatInt(u.ID, 10)},
		{headerEmail, u.Email},
		{headerName, encodeDisplayName(u.Name)},
		{headerAvatar, u.AvatarURL},
		{headerRoles, strings.Join(u.Roles, ",")},
		{headerSlackUserID, u.SlackUserID},
		{headerSlackTeamID, u.SlackTeamID},
	}

	for _, p := range pairs {
		// Layer 3 of the strip: defense-in-depth Del immediately before Set.
		// http.Header is map[string][]string; if a sibling code path ever
		// landed an X-Forge-* slice with multiple entries, a bare Set would
		// overwrite only the first index. Del clears the slice cleanly.
		out.Header.Del(p.name)
		out.Header.Set(p.name, p.value)
	}
}

// encodeDisplayName implements the X-Forge-Name encoding rule documented in
// the Upstream-App Contract:
//
//   - Pure-ASCII names pass through unchanged.
//   - Names containing any byte >= 0x80 are encoded per RFC 8187 as
//     "UTF-8''<percent-encoded>" so the wire value is ASCII-only and
//     unambiguous about the original UTF-8 bytes.
//
// We percent-encode every byte outside the unreserved set when in the
// non-ASCII branch (RFC 3986 §2.3) for predictable round-trip behaviour;
// upstream apps unwrap with a standard "percent-decode then UTF-8 decode"
// pipeline.
func encodeDisplayName(name string) string {
	for i := range len(name) {
		if name[i] >= 0x80 {
			return "UTF-8''" + percentEncodeUTF8(name)
		}
	}
	return name
}

// percentEncodeUTF8 percent-encodes every byte of s that is not in the
// RFC 3986 unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~"). We use a
// hand-rolled encoder rather than url.QueryEscape because the latter
// encodes ' ' to '+' (form-encoding semantics), which is the wrong shape
// for an RFC 8187 header value.
func percentEncodeUTF8(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}
