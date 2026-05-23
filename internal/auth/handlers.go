package auth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

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
	mux.HandleFunc("GET /auth/me", h.HandleMe)
}

// meResponse is the JSON shape returned by GET /auth/me. Consumed by the
// React app on mount to decide between the sign-in card and the
// signed-in portal. Field tags use snake_case to match the JS side.
type meResponse struct {
	SignedIn  bool          `json:"signed_in"`
	Name      string        `json:"name,omitempty"`
	Email     string        `json:"email,omitempty"`
	AvatarURL string        `json:"avatar_url,omitempty"`
	Apps      []meAppInfo   `json:"apps,omitempty"`
}

type meAppInfo struct {
	Host string `json:"host"`
	URL  string `json:"url"`
}

// HandleMe (GET /auth/me) reports the caller's session state plus the
// list of configured upstream apps. The React app at "/" fetches this
// once on mount and renders either the sign-in card (signed_in=false)
// or the portal view (signed_in=true). Replaces the old server-side 302
// from "/" to DefaultLandingURL, which produced a redirect loop when
// the landing URL pointed back at the auth host.
//
// On any session/user lookup failure we report signed_in=false rather
// than surfacing the error — the client treats the response as a clean
// "render the card" signal and the user reaches sign-in without seeing
// internal plumbing. Real errors are still logged for operators.
//
// Cache-Control: no-store because the response is per-session and
// CORS-style intermediaries would otherwise serve a stale answer to a
// freshly signed-in caller.
func (h *Handler) HandleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	resp := meResponse{SignedIn: false}

	id, ok := session.Read(r)
	if !ok {
		writeJSON(w, resp)
		return
	}
	sess, err := h.Sessions.Get(r.Context(), id)
	if err != nil || sess == nil {
		writeJSON(w, resp)
		return
	}
	u, err := h.Users.Get(r.Context(), sess.UserID)
	if err != nil || u == nil {
		writeJSON(w, resp)
		return
	}

	resp.SignedIn = true
	resp.Name = u.Name
	resp.Email = u.Email
	resp.AvatarURL = u.AvatarURL

	for host := range h.Cfg.UpstreamMap {
		resp.Apps = append(resp.Apps, meAppInfo{
			Host: host,
			URL:  "https://" + host + "/",
		})
	}
	// Sort for deterministic rendering — map iteration order would
	// otherwise reshuffle the portal on every refresh.
	sort.Slice(resp.Apps, func(i, j int) bool {
		return resp.Apps[i].Host < resp.Apps[j].Host
	})

	writeJSON(w, resp)
}

// writeJSON is a tiny helper so the handler stays readable. Any encode
// error here is a fully internal failure (the writer is in-process); we
// can't meaningfully recover and the partial response is the best the
// caller will see.
func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
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
	ip := httplog.ClientIP(r)
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
	// Defense-in-depth: re-validate the return_to read from the pre-auth
	// cookie. The cookie is __Host- + HttpOnly + single-use, which closes
	// the common attack shapes, but the payload itself is base64(json(...))
	// with no HMAC — any cookie-write primitive on the auth host (XSS,
	// future bug) could swap return_to while preserving state/nonce. The
	// validator is the same one /auth/login uses, so a tampered cookie
	// falls back to the default landing URL identically.
	destination := h.resolveReturnTo(pre.ReturnTo)
	http.Redirect(w, r, destination, http.StatusFound)
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

