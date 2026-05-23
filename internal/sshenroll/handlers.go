package sshenroll

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/forgeutah/forge-proxy/internal/httplog"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// SessionLookup is the minimal contract the enrollment handlers need from
// the session store. Declared as an interface so tests can stub without
// pulling in the full session machinery.
type SessionLookup interface {
	Get(ctx context.Context, id string) (*session.Session, error)
}

// UserLookup is the minimal contract for resolving a session.UserID to a
// concrete user row. The handlers only need Get; declaring an interface
// keeps test wiring small.
type UserLookup interface {
	Get(ctx context.Context, id int64) (*user.User, error)
}

// KeyStore is the subset of sshkey.Store the handlers need.
type KeyStore interface {
	Add(ctx context.Context, userID int64, fingerprint, keyType string, publicKey []byte, label string) (*sshkey.Key, error)
	Get(ctx context.Context, fingerprint string) (*sshkey.Key, error)
}

// Handlers wires the in-memory token store to the session/user/key stores
// and serves the two enrollment routes:
//
//	GET /ssh/enroll/<token>           — render fingerprint, link to /auth/login
//	GET /ssh/enroll/<token>/complete  — consume token after OIDC, bind key
//
// The handlers also expose the token store directly so the SSH server (U6)
// can mint tokens when a connection offers an unregistered key.
type Handlers struct {
	Tokens   *Store
	Sessions SessionLookup
	Users    UserLookup
	Keys     KeyStore
	AuthHost string // e.g. "auth.forgeut.dev" — used to build the return_to URL
}

// New constructs a Handlers ready to serve.
func New(tokens *Store, sessions SessionLookup, users UserLookup, keys KeyStore, authHost string) *Handlers {
	return &Handlers{
		Tokens:   tokens,
		Sessions: sessions,
		Users:    users,
		Keys:     keys,
		AuthHost: authHost,
	}
}

// Mount registers the enrollment routes on mux. Both are GET-only; the
// caller wires per-IP rate limiting via httplog.RateLimitMiddleware to
// match the /auth/callback policy.
func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.Handle("GET /ssh/enroll/{token}/complete", http.HandlerFunc(h.HandleComplete))
	mux.Handle("GET /ssh/enroll/{token}", http.HandlerFunc(h.HandleStart))
}

// HandleStart (GET /ssh/enroll/<token>) renders an inline HTML page showing
// the offered fingerprint and a "Sign in with Slack" button that links to
// the existing /auth/login flow with return_to set to the /complete URL.
//
// The token is NOT consumed here — Peek lets us look up the fingerprint
// while leaving the token live for the post-OIDC consume step. Unknown,
// missing, or expired tokens render an identical "this link is invalid"
// page; no info leak about whether the token ever existed.
//
// Cache-Control: no-store because the rendered fingerprint is bound to a
// single in-flight enrollment and intermediaries must not serve it to
// anyone else.
func (h *Handlers) HandleStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	token := r.PathValue("token")
	enroll, err := h.Tokens.Peek(token)
	if err != nil {
		h.writeInvalidLink(w, r)
		return
	}

	returnTo := h.completeURL(token)
	loginURL := "/auth/login?return_to=" + url.QueryEscape(returnTo)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body := fmt.Sprintf(enrollStartPage,
		html.EscapeString(enroll.Fingerprint),
		html.EscapeString(loginURL),
	)
	_, _ = w.Write([]byte(body))
}

// HandleComplete (GET /ssh/enroll/<token>/complete) is the post-OIDC
// landing handler. Order of operations:
//
//  1. Read forge_session cookie; reject if missing.
//  2. Look up session row; reject if missing or expired.
//  3. Look up user; reject if missing.
//  4. Consume the token (single-use); on miss, render the invalid-link
//     page (could be expired, could be already-used).
//  5. Register the key via sshkey.Add. On ErrFingerprintTaken, look up
//     the existing owner — if same user, treat as success (idempotent
//     retry); else render an error page.
func (h *Handlers) HandleComplete(w http.ResponseWriter, r *http.Request) {
	logger := httplog.FromContext(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	token := r.PathValue("token")

	sessID, ok := session.Read(r)
	if !ok {
		// Not signed in yet — bounce through /auth/login with the same
		// /complete URL as return_to so a refresh of this URL doesn't
		// strand the user.
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(h.completeURL(token)), http.StatusFound)
		return
	}
	sess, err := h.Sessions.Get(r.Context(), sessID)
	if err != nil || sess == nil {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(h.completeURL(token)), http.StatusFound)
		return
	}
	u, err := h.Users.Get(r.Context(), sess.UserID)
	if err != nil || u == nil {
		logger.Warn("ssh_enroll_complete_user_lookup_failed",
			"session_id", httplog.SessionID(sessID),
			"error", errString(err))
		h.writeInvalidLink(w, r)
		return
	}

	enroll, err := h.Tokens.Consume(token)
	if err != nil {
		logger.Info("ssh_enroll_token_consume_failed",
			"token", httplog.SSHEnrollmentToken(token),
			"user_id", u.ID,
			"error", err.Error())
		h.writeInvalidLink(w, r)
		return
	}

	label := "enrolled from " + shortUserAgent(r.UserAgent())
	if _, err := h.Keys.Add(r.Context(), u.ID, enroll.Fingerprint, enroll.KeyType, enroll.PublicKey, label); err != nil {
		if errors.Is(err, sshkey.ErrFingerprintTaken) {
			// Idempotent re-enrollment: if the key is already bound to
			// the signed-in user, render the success page. If it
			// belongs to someone else, surface a friendly error
			// without revealing who owns it.
			existing, lookupErr := h.Keys.Get(r.Context(), enroll.Fingerprint)
			if lookupErr == nil && existing != nil && existing.UserID == u.ID {
				logger.Info("ssh_enroll_idempotent_reregister",
					"user_id", u.ID,
					"fingerprint", enroll.Fingerprint)
				h.writeSuccess(w, r, enroll.Fingerprint)
				return
			}
			logger.Warn("ssh_enroll_key_owned_by_other_user",
				"user_id", u.ID,
				"fingerprint", enroll.Fingerprint)
			h.writeKeyTaken(w, r)
			return
		}
		logger.Error("ssh_enroll_key_add_failed",
			"user_id", u.ID,
			"fingerprint", enroll.Fingerprint,
			"error", err.Error())
		h.writeInvalidLink(w, r)
		return
	}

	logger.Info("ssh_enroll_completed",
		"user_id", u.ID,
		"fingerprint", enroll.Fingerprint,
		"key_type", enroll.KeyType)

	h.writeSuccess(w, r, enroll.Fingerprint)
}

// completeURL builds the absolute https URL the /auth/login flow returns
// to. Format matches the existing auth.Validate rules so the returnto
// validator accepts it without a special case.
func (h *Handlers) completeURL(token string) string {
	return "https://" + h.AuthHost + "/ssh/enroll/" + url.PathEscape(token) + "/complete"
}

// EnrollURL is the operator-facing helper used by the SSH server to build
// the URL it embeds in the keyboard-interactive challenge. Exposed as a
// method on Handlers so callers don't reinvent the path shape.
func (h *Handlers) EnrollURL(token string) string {
	return "https://" + h.AuthHost + "/ssh/enroll/" + url.PathEscape(token)
}

// Mint forwards to the underlying token store. Exposing it on Handlers
// (instead of asking callers to reach into Tokens directly) lets the SSH
// server depend on a single small interface rather than the full store.
func (h *Handlers) Mint(fingerprint, keyType string, publicKey []byte) (string, error) {
	return h.Tokens.Mint(fingerprint, keyType, publicKey)
}

func (h *Handlers) writeInvalidLink(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(enrollInvalidPage))
}

func (h *Handlers) writeKeyTaken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write([]byte(enrollKeyTakenPage))
}

func (h *Handlers) writeSuccess(w http.ResponseWriter, _ *http.Request, fingerprint string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body := fmt.Sprintf(enrollSuccessPage, html.EscapeString(fingerprint))
	_, _ = w.Write([]byte(body))
}

// shortUserAgent collapses the User-Agent header to a short identifier
// suitable for the SSH key's `label` column. We don't store the full UA
// string — that gets long and isn't useful in the admin CLI.
func shortUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "unknown"
	}
	if len(ua) > 64 {
		return ua[:64]
	}
	return ua
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// enrollStartPage is the first-page template. Format args:
//
//	%[1]s — escaped fingerprint
//	%[2]s — escaped login URL with return_to set
const enrollStartPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Register SSH key — Forge Utah</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
code { background: #f3f3f3; padding: 0.1em 0.3em; border-radius: 3px; word-break: break-all; }
.btn { display: inline-block; background: #4a154b; color: #fff; padding: 0.5em 1em; border-radius: 4px; text-decoration: none; }
.btn:hover { background: #611f64; }
</style>
</head>
<body>
<h1>Register your SSH key</h1>
<p>You're about to register this public key fingerprint to your Forge Utah Slack identity:</p>
<p><code>%[1]s</code></p>
<p>Verify the fingerprint matches the output of <code>ssh-keygen -lf ~/.ssh/id_ed25519.pub</code> on your laptop, then sign in:</p>
<p><a class="btn" href="%[2]s">Sign in with Slack</a></p>
<p>After sign-in, the key will be bound to your account and you can retry the SSH command.</p>
</body>
</html>
`

// enrollInvalidPage is the unknown/expired-token landing.
const enrollInvalidPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Invalid enrollment link — Forge Utah</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
code { background: #f3f3f3; padding: 0.1em 0.3em; border-radius: 3px; }
</style>
</head>
<body>
<h1>Invalid enrollment link</h1>
<p>This enrollment URL is no longer valid. It may have expired, already been used, or never existed.</p>
<p>Re-run your <code>ssh</code> command to get a fresh URL.</p>
</body>
</html>
`

// enrollKeyTakenPage is the "this fingerprint already belongs to a different
// user" landing. Deliberately does not reveal who owns it.
const enrollKeyTakenPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Key already registered — Forge Utah</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
</style>
</head>
<body>
<h1>Key already registered</h1>
<p>This SSH public key is registered to another Forge Utah user. If you didn't expect this, contact an administrator.</p>
</body>
</html>
`

// enrollSuccessPage. Format args:
//
//	%[1]s — escaped fingerprint
const enrollSuccessPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Key registered — Forge Utah</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
code { background: #f3f3f3; padding: 0.1em 0.3em; border-radius: 3px; word-break: break-all; }
</style>
</head>
<body>
<h1>Key registered</h1>
<p>This fingerprint is now bound to your account:</p>
<p><code>%[1]s</code></p>
<p>Retry your SSH command — subsequent connections will authenticate automatically.</p>
</body>
</html>
`
