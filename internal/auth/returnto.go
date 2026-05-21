package auth

import (
	"errors"
	"net/url"
	"strings"
)

// ErrInvalidReturnTo is returned by Validate when the caller-supplied return
// target fails any rule in the strict validation set. Handlers treat this
// sentinel as "fall back to the configured default landing URL" rather than
// surfacing it to the user — open-redirect chances are exactly the wrong
// place to give the attacker a copy of our error wording.
var ErrInvalidReturnTo = errors.New("auth: invalid return_to")

// Validate parses raw and returns a safe reconstructed URL string if and only
// if it passes every rule in the strict allowlist. Callers MUST use the
// returned string (the parser-canonical form via url.URL.String) rather than
// the raw input — that's the defence against parser-differential attacks
// where the validator and the redirector disagree about what bytes mean.
//
// Rules (all must hold):
//
//  1. Scheme is exactly "https". No http, file, javascript, etc.
//  2. No userinfo component (https://attacker@deuce.forgeutah.tech/ is rejected).
//  3. Host is exactly baseDomain OR ends in "." + baseDomain (the leading dot
//     forbids the "notforgeutah.tech" suffix-attack).
//  4. Host is ASCII and does not begin with "xn--" (no IDN/punycode
//     homographs through a parser that accepted them as a Forge subdomain).
//  5. Port is empty or exactly "443" — anything else (1234, 80, etc.) is a
//     port-confusion attempt and is rejected.
//  6. Host does not contain control characters or whitespace (rejected by
//     url.Parse for any well-behaved input, but checked explicitly so we
//     don't depend on the parser's tolerance staying constant).
//
// Anything else — protocol-relative URLs like //evil.com/foo, urls with
// embedded \n/\r, schemes other than https, hosts outside the configured
// base domain — returns ErrInvalidReturnTo. The fragment and query are
// preserved verbatim through u.String().
func Validate(raw, baseDomain string) (string, error) {
	if raw == "" {
		return "", ErrInvalidReturnTo
	}
	// Reject protocol-relative URLs explicitly. url.Parse will happily
	// accept these and return Scheme="", Host="evil.com" — we want them
	// rejected by *this* code, not by an upstream redirect check that may
	// not be there.
	if strings.HasPrefix(raw, "//") {
		return "", ErrInvalidReturnTo
	}
	// Reject any control character or whitespace in the raw input.
	// url.Parse silently allows \n and \r in some positions; we don't want
	// to inherit that surface.
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", ErrInvalidReturnTo
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrInvalidReturnTo
	}

	if u.Scheme != "https" {
		return "", ErrInvalidReturnTo
	}
	if u.User != nil {
		return "", ErrInvalidReturnTo
	}
	if u.Host == "" {
		return "", ErrInvalidReturnTo
	}

	host := u.Hostname()
	if host == "" {
		return "", ErrInvalidReturnTo
	}
	// ASCII-only hostnames. Punycode (xn--) labels can disguise
	// homographs that resolve to attacker-controlled space; refuse them.
	for i := range len(host) {
		if host[i] > 0x7f {
			return "", ErrInvalidReturnTo
		}
	}
	// Block IDN/punycode at any label boundary. "xn--" is the ACE prefix.
	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "xn--") {
		return "", ErrInvalidReturnTo
	}
	for label := range strings.SplitSeq(lower, ".") {
		if strings.HasPrefix(label, "xn--") {
			return "", ErrInvalidReturnTo
		}
	}

	baseDomain = strings.ToLower(strings.TrimPrefix(baseDomain, "."))
	if baseDomain == "" {
		return "", ErrInvalidReturnTo
	}
	if lower != baseDomain && !strings.HasSuffix(lower, "."+baseDomain) {
		return "", ErrInvalidReturnTo
	}

	if port := u.Port(); port != "" && port != "443" {
		return "", ErrInvalidReturnTo
	}

	// Reconstruct via String() so the caller cannot smuggle a non-canonical
	// representation past us. This is the parser-differential defence.
	return u.String(), nil
}
