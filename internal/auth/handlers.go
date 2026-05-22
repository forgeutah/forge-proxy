package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/httplog"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// errorQueryAuthFailed is the user-visible code for the generic "OAuth
// round-trip failed somewhere" terminal state. U7's login page reads this
// query parameter and renders the appropriate copy.
const errorQueryAuthFailed = "auth_failed"

// errorQueryNotInWorkspace is the F3 unauthorized branch — the user signed
// into Slack but with a workspace other than the configured Forge Utah one.
const errorQueryNotInWorkspace = "not_in_workspace"

// Handler bundles the U6 routes and their dependencies. The struct is
// created once at startup in cmd/forge-proxy/main.go and serves all four
// routes for the lifetime of the process. None of its fields are mutated
// after construction, so the zero-lock design is safe for concurrent use.
type Handler struct {
	Cfg      *config.Config
	OIDC     *OIDC
	Users    *user.Store
	Sessions *session.Store
}

// NewHandler is the convenience constructor. Keeping the dependencies on
// the struct (rather than threading them through every method) makes the
// route registration in main.go a one-liner per route.
func NewHandler(cfg *config.Config, o *OIDC, users *user.Store, sessions *session.Store) *Handler {
	return &Handler{Cfg: cfg, OIDC: o, Users: users, Sessions: sessions}
}

// Register wires the three /auth/* routes onto the supplied mux. The
// already-signed-in check at GET /{$} is owned by internal/web (U7) —
// keeping the root route there lets the web layer own asset serving and
// the session-redirect compose cleanly without circular imports.
//
// The proxy host routing (U8) will eventually differentiate auth-host
// paths from upstream-app paths, but for U6 every route serves regardless
// of host — the binary listens on a single port and the mux dispatches
// by path.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.HandleLogin)
	mux.HandleFunc("GET /auth/callback", h.HandleCallback)
	mux.HandleFunc("POST /auth/logout", h.HandleLogout)
}

// IsSignedIn satisfies the web.SessionChecker interface so the embedded
// asset handler can 302 already-signed-in callers to the default landing
// URL before serving the login card. The check is a session lookup
// against the store; an expired or missing row reports "not signed in".
func (h *Handler) IsSignedIn(ctx context.Context, r *http.Request) bool {
	id, ok := session.Read(r)
	if !ok {
		return false
	}
	sess, err := h.Sessions.Get(ctx, id)
	if err != nil || sess == nil {
		return false
	}
	return true
}

// HandleLogin (GET /auth/login) is the entry point for a sign-in. It
// validates the requested return_to, mints fresh state and nonce values,
// writes the pre-auth cookie, and 302s the user to Slack's authorize
// endpoint.
//
// The state/nonce/return_to triple is bound to *this* browser session
// through the __Host- pre-auth cookie — the Outline-CVE defence. Without
// the cookie, an attacker who intercepts the state cannot complete the
// callback because the cookie won't be in their jar.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := h.resolveReturnTo(r.URL.Query().Get("return_to"))

	logger := httplog.FromContext(r.Context())
	payload, err := NewPreAuth(returnTo)
	if err != nil {
		logger.Error("auth/login: generating pre-auth tokens", "error", err.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}
	if err := SetPreAuth(w, payload); err != nil {
		logger.Error("auth/login: setting pre-auth cookie", "error", err.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	authURL := h.OIDC.OAuth.AuthCodeURL(
		payload.State,
		oauth2.SetAuthURLParam("nonce", payload.Nonce),
		oauth2.SetAuthURLParam("team", h.Cfg.SlackTeamID),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// idTokenClaims is the struct go-oidc populates from the verified ID
// token. We declare the namespaced Slack claims with their exact JSON keys
// (the URLs) so the field can be populated by IDToken.Claims().
type idTokenClaims struct {
	Subject     string `json:"sub"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Picture     string `json:"picture"`
	Nonce       string `json:"nonce"`
	SlackTeamID string `json:"https://slack.com/team_id"`
	SlackUserID string `json:"https://slack.com/user_id"`
}

// HandleCallback (GET /auth/callback) finishes the OAuth round-trip. The
// canonical ordering is critical:
//
//  1. Read the pre-auth cookie, then immediately write a deletion cookie —
//     this enforces single-use state regardless of what happens next.
//  2. Validate state against the cookie via constant-time compare.
//  3. Check the OIDC verifier is ready; if not, bail early.
//  4. Exchange the code for a token.
//  5. Verify the ID token signature, issuer, audience, exp/iat (the go-oidc
//     verifier covers these). The SupportedSigningAlgs pin blocks the
//     HS256-with-public-key algorithm-confusion attack.
//  6. Parse claims; constant-time compare nonce and team_id.
//  7. Upsert the user row, create a session row, set the session cookie,
//     redirect to the validated return_to.
//
// Every failure path renders ?error=auth_failed (or
// ?error=not_in_workspace for the team mismatch) and stops. No partial
// state ever leaves the handler.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	logger := httplog.FromContext(r.Context())

	// Step 1: read pre-auth, then immediately delete. Delete-first
	// guarantees single-use even if the rest of the handler crashes.
	pre, preErr := ReadPreAuth(r)
	ClearPreAuth(w)
	if preErr != nil {
		logger.Warn("auth/callback: pre-auth read", "error", preErr.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	// Step 2: state constant-time compare.
	queryState := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(queryState), []byte(pre.State)) != 1 {
		logger.Warn("auth/callback: state mismatch")
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	// Step 3: verifier readiness.
	verifier := h.OIDC.Verifier()
	if verifier == nil {
		logger.Warn("auth/callback: OIDC verifier not ready")
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	// Step 4: code exchange. We use the request's context so a client
	// disconnect cancels the upstream Slack call instead of leaving it
	// dangling.
	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Warn("auth/callback: missing code")
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}
	token, err := h.OIDC.OAuth.Exchange(r.Context(), code)
	if err != nil {
		logger.Warn("auth/callback: token exchange", "error", err.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	// Step 5: extract and verify the ID token. The Extra field returns an
	// untyped any, so we type-assert to string.
	rawIDToken, _ := token.Extra(idTokenExtraField).(string)
	if rawIDToken == "" {
		logger.Warn("auth/callback: token response missing id_token")
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		logger.Warn("auth/callback: id_token verify", "error", err.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	// Step 6: parse claims and verify nonce + team.
	claims, err := parseClaims(idToken)
	if err != nil {
		logger.Warn("auth/callback: claims parse", "error", err.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(pre.Nonce)) != 1 {
		logger.Warn("auth/callback: nonce mismatch")
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.SlackTeamID), []byte(h.Cfg.SlackTeamID)) != 1 {
		// F3 / R3 / R13: user is signed into Slack but with the wrong
		// workspace. Render the "not in workspace" state — no session.
		logger.Info("auth/callback: workspace mismatch",
			"claim_team", claims.SlackTeamID,
			"want_team", h.Cfg.SlackTeamID)
		http.Redirect(w, r, h.errorURL(errorQueryNotInWorkspace), http.StatusFound)
		return
	}

	// Step 7: upsert + session. Slack OIDC puts the per-workspace user ID
	// in `sub` (the namespaced https://slack.com/user_id claim is also
	// present but the spec mandates sub).
	slackUserID := claims.SlackUserID
	if slackUserID == "" {
		slackUserID = claims.Subject
	}
	u, err := h.Users.UpsertFromOIDC(r.Context(), user.OIDCClaims{
		SlackUserID: slackUserID,
		SlackTeamID: claims.SlackTeamID,
		Email:       claims.Email,
		Name:        claims.Name,
		AvatarURL:   claims.Picture,
	})
	if err != nil {
		logger.Error("auth/callback: user upsert", "error", err.Error())
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}

	userAgent := r.Header.Get("User-Agent")
	ip := clientIP(r)
	sess, err := h.Sessions.Create(r.Context(), u.ID, userAgent, ip)
	if err != nil {
		logger.Error("auth/callback: session create", "error", err.Error(), "user_id", u.ID)
		http.Redirect(w, r, h.errorURL(errorQueryAuthFailed), http.StatusFound)
		return
	}
	logger.Info("auth/callback: sign-in succeeded",
		"user_id", u.ID,
		"session_id", httplog.SessionID(sess.ID))

	session.Set(w, sess.ID, sess.ExpiresAt, h.Cfg.CookieDomain)
	http.Redirect(w, r, pre.ReturnTo, http.StatusFound)
}

// HandleLogout (POST /auth/logout) ends the current session. CSRF defence
// is the Origin-header check; SameSite=Lax on the session cookie is
// belt-and-braces. We deliberately do NOT thread a per-session CSRF token
// through upstream apps — the cost (token plumbing per app) is bigger than
// the residual risk (sign-out CSRF is low-impact: annoyance, not
// compromise).
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	logger := httplog.FromContext(r.Context())
	origin := r.Header.Get("Origin")
	expected := "https://" + h.Cfg.AuthHost
	if origin == "" || origin != expected {
		logger.Warn("auth/logout: origin mismatch", "got", origin, "want", expected)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if id, ok := session.Read(r); ok {
		if err := h.Sessions.Delete(r.Context(), id); err != nil {
			// Failing to delete is logged but the user-visible behaviour is
			// still "you're signed out" — clear the cookie regardless.
			logger.Error("auth/logout: session delete",
				"error", err.Error(),
				"session_id", httplog.SessionID(id))
		}
	}
	session.Clear(w, h.Cfg.CookieDomain)
	http.Redirect(w, r, "/", http.StatusFound)
}

// errorURL builds the redirect URL for an error branch. Always relative to
// the auth host root so the user lands on the login page.
func (h *Handler) errorURL(code string) string {
	return "/?error=" + code
}

// resolveReturnTo runs the strict validator against the supplied raw value
// and falls back to the configured default landing URL on any failure.
// Callers never see the raw input again — only the validator's
// reconstructed string.
func (h *Handler) resolveReturnTo(raw string) string {
	if v, err := Validate(raw, h.Cfg.BaseDomain); err == nil {
		return v
	}
	if h.Cfg.DefaultLandingURL != "" {
		return h.Cfg.DefaultLandingURL
	}
	return "https://" + h.Cfg.AuthHost + "/"
}

// parseClaims runs idToken.Claims into our typed struct. We surface a
// distinct error so the handler can log it without leaking the underlying
// JSON structure.
func parseClaims(idToken *oidc.IDToken) (*idTokenClaims, error) {
	var c idTokenClaims
	if err := idToken.Claims(&c); err != nil {
		return nil, fmt.Errorf("claims decode: %w", err)
	}
	// Some providers serialise the namespaced claims into a separate map
	// rather than as siblings of the standard claims. Slack puts them at
	// the top level, so the json tags above pick them up; but to be robust
	// against changes we also fall back to a raw map lookup if the typed
	// fields came back empty.
	if c.SlackTeamID == "" || c.SlackUserID == "" {
		var raw map[string]any
		if err := idToken.Claims(&raw); err == nil {
			if c.SlackTeamID == "" {
				if v, ok := raw[slackTeamClaim].(string); ok {
					c.SlackTeamID = v
				}
			}
			if c.SlackUserID == "" {
				if v, ok := raw[slackUserClaim].(string); ok {
					c.SlackUserID = v
				}
			}
		}
	}
	return &c, nil
}

// clientIP returns a best-effort client IP for session-row recording. We
// don't rely on this for any security decision (sessions aren't IP-bound)
// — it's logged so admins can see "this session was created from this IP"
// when investigating an incident.
func clientIP(r *http.Request) string {
	// X-Forwarded-For is set by trusted upstream layers in production
	// (Cloudflare or the exe.dev load balancer) but is the user's input
	// otherwise. For a v1 single-VM deploy with public IP we don't trust
	// it — use the remote address.
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[:i]
	}
	return strings.Trim(addr, "[]")
}

