package session

import (
	"net/http"
	"time"
)

// CookieName is the wire name for the shared cross-subdomain session cookie.
// This package is the single source of truth — handlers and tests must
// import it rather than re-declaring the string. Changing this value logs
// every Forge user out on next request, so it lives behind a constant.
const CookieName = "forge_session"

// Set writes the session cookie to w with the security-critical flag set:
// HttpOnly (no JS access), Secure (HTTPS-only), SameSite=Lax (works for the
// OAuth callback's top-level navigation back from Slack while still
// blocking cross-site POST CSRF), Path=/ (visible to every app), and the
// configured Domain so the cookie is shared across every *.forgeutah.tech
// subdomain. The Expires field is the absolute deletion time browsers use
// to garbage-collect the cookie — supply the session's expires_at.
//
// SameSite=Strict would break the OAuth callback because Slack's 302 back
// to /auth/callback is a top-level cross-site navigation; Lax permits that
// while still rejecting cross-site sub-resource and form-POST requests.
// See plan §"CSRF, cookies, and redirects".
func Set(w http.ResponseWriter, sessionID string, expires time.Time, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionID,
		Path:     "/",
		Domain:   domain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear emits the deletion cookie: same name / domain / path / flags as
// Set, but with an empty Value and MaxAge=-1 so browsers delete it
// immediately. Used on sign-out and on callback failures.
//
// The domain MUST match the domain used when the cookie was set; otherwise
// the browser treats this as a different cookie and the original survives.
func Clear(w http.ResponseWriter, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Read returns the session ID from the request's session cookie, or
// ("", false) if the cookie is absent or empty. Returning a boolean rather
// than an error keeps call sites simple: missing cookie is the normal
// "logged-out" branch, not an exceptional case.
func Read(r *http.Request) (string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}
