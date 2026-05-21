package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// PreAuthCookieName is the wire name for the pre-auth cookie that binds
// state, nonce, and return_to to a single browser session for the duration
// of an OAuth round-trip.
//
// The __Host- prefix is load-bearing: browsers reject any __Host- cookie
// that has a Domain attribute, that isn't Secure, or whose Path is not "/".
// That pins this cookie to exactly the auth host (auth.forgeutah.tech) and
// blocks a sibling subdomain like "deuce.forgeutah.tech" from being able to
// shadow it through a Set-Cookie of its own. See the plan's "CSRF, cookies,
// and redirects" section.
const PreAuthCookieName = "__Host-forge_pre_auth"

// preAuthMaxAge is the 10-minute lifetime of the pre-auth cookie. Long
// enough that a slow user can finish the Slack consent screen; short enough
// that an exfiltrated cookie has limited replay value. State is also
// single-use (deleted on first callback) — the cookie lifetime is the
// secondary defence against replay, not the primary one.
const preAuthMaxAge = 600

// ErrMissingPreAuth is returned by ReadPreAuth when the request has no
// pre-auth cookie or the cookie value is empty.
var ErrMissingPreAuth = errors.New("auth: pre-auth cookie missing")

// ErrCorruptPreAuth is returned by ReadPreAuth when the cookie value does
// not parse as the expected JSON payload.
var ErrCorruptPreAuth = errors.New("auth: pre-auth cookie corrupt")

// PreAuthPayload is the data we bind to the browser session for the OAuth
// round-trip. State and Nonce are 32 random bytes (base64url, no padding);
// ReturnTo is the already-validated post-sign-in landing URL.
type PreAuthPayload struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	ReturnTo string `json:"return_to"`
}

// randomToken returns 32 cryptographically-random bytes encoded as
// base64url with no padding — same shape as the session-store IDs.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// NewPreAuth creates a fresh state + nonce pair bound to the supplied
// returnTo. Both values are generated at the same point so the caller
// cannot accidentally use a stale state or nonce by mistake.
func NewPreAuth(returnTo string) (*PreAuthPayload, error) {
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &PreAuthPayload{State: state, Nonce: nonce, ReturnTo: returnTo}, nil
}

// SetPreAuth marshals p to JSON, base64url-encodes the result, and writes
// the __Host-forge_pre_auth cookie with the security flags the prefix
// requires. The cookie has no Domain attribute (forbidden by __Host-) and
// is therefore pinned to exactly the request's host (auth.forgeutah.tech in
// production).
//
// SameSite=Lax is correct here because Slack's 302 back to /auth/callback
// is a top-level cross-site navigation; Strict would silently drop the
// cookie and break the callback.
func SetPreAuth(w http.ResponseWriter, p *PreAuthPayload) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("auth: marshal pre-auth: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     PreAuthCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   preAuthMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// ClearPreAuth writes a deletion cookie for the pre-auth cookie. Same
// security flags as SetPreAuth (including the __Host- prefix constraints)
// so the browser accepts the deletion as targeting the same cookie.
//
// This is the single-use-state enforcement: /auth/callback calls
// ClearPreAuth before doing any verification work, so even if the rest of
// the handler somehow turns into a no-op the cookie is gone from the
// client's jar and cannot be replayed.
func ClearPreAuth(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     PreAuthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ReadPreAuth reads, decodes, and JSON-parses the pre-auth cookie from r.
// Returns ErrMissingPreAuth if the cookie is absent or empty, and
// ErrCorruptPreAuth if the cookie body cannot be decoded or parsed.
func ReadPreAuth(r *http.Request) (*PreAuthPayload, error) {
	c, err := r.Cookie(PreAuthCookieName)
	if err != nil || c.Value == "" {
		return nil, ErrMissingPreAuth
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, ErrCorruptPreAuth
	}
	var p PreAuthPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrCorruptPreAuth
	}
	if p.State == "" || p.Nonce == "" {
		return nil, ErrCorruptPreAuth
	}
	return &p, nil
}
