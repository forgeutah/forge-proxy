package proxy

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/httplog"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// SessionStore is the narrow surface the proxy needs from internal/session.
// Defining a small interface here (rather than depending on the concrete
// *session.Store) keeps the proxy's unit tests light and decouples the
// package import graph.
type SessionStore interface {
	Get(ctx context.Context, id string) (*session.Session, error)
	Touch(ctx context.Context, id string) error
}

// UserStore is the narrow surface the proxy needs from internal/user. Same
// rationale as SessionStore.
type UserStore interface {
	Get(ctx context.Context, id int64) (*user.User, error)
}

// Proxy is the reverse-proxy hot path. One instance is constructed at
// startup and handles every authenticated request to a non-auth-host
// *.forgeutah.tech subdomain.
//
// Flow per request (the F2 silent-SSO path):
//
//  1. Read the session cookie. Missing → 302 to login.
//  2. Look up the session row. ErrNotFound / ErrExpired → 302 to login
//     (logged distinctly for capacity-planning visibility).
//  3. Look up the user row referenced by the session. Missing → clear
//     cookie + 302 to login (forced-logout race window).
//  4. Touch the session (60s-throttled in the store). Touch failure is
//     logged and the request continues — the session remains valid for
//     the rest of its current window per R11/U4 semantics.
//  5. Resolve the inbound Host to an upstream URL. Unknown → 404 with a
//     branded "unknown Forge app" page (NOT a 502 — 502 implies the
//     upstream exists but failed, which is the wrong shape for "no such
//     app").
//  6. Forward through httputil.ReverseProxy.Rewrite, strip + inject the
//     X-Forge-* contract headers, and stream the response.
type Proxy struct {
	cfg          *config.Config
	hosts        HostMap
	sessions     SessionStore
	users        UserStore
	reverseProxy *httputil.ReverseProxy

	// loginURLPrefix is the precomputed "https://<AuthHost>/?return_to="
	// prefix. The inbound URL is appended via url.QueryEscape on each unauth
	// request — most authenticated traffic doesn't hit this path, but the
	// computation is one-shot at startup either way.
	//
	// We redirect to the auth host root (the stylized React card) rather
	// than directly to /auth/login. The card preserves return_to in its
	// "Continue with Slack" button so the user gets a branded landing page
	// before the Slack OAuth handoff — important because OAuth consent
	// screens from a cold link look phishy without context. The card's
	// JS forwards return_to to /auth/login on click.
	loginURLPrefix string
}

// New constructs a Proxy with the supplied dependencies. The ReverseProxy
// transport is configured with timeouts on the dialer rather than a
// top-level Client.Timeout — the latter would kill long-lived streaming
// responses (SSE, WebSocket upgrades). FlushInterval=-1 makes streaming
// responses flush immediately on every Write.
func New(cfg *config.Config, sessions SessionStore, users UserStore) *Proxy {
	p := &Proxy{
		cfg:            cfg,
		hosts:          NewHostMap(cfg.UpstreamMap),
		sessions:       sessions,
		users:          users,
		loginURLPrefix: "https://" + cfg.AuthHost + "/?return_to=",
	}

	p.reverseProxy = &httputil.ReverseProxy{
		Rewrite: p.rewrite,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   16,
			ForceAttemptHTTP2:     true,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// ErrorHandler fires for transport-level failures (connection
			// refused, dial timeout, etc.). Application 5xx responses from
			// the upstream are forwarded unchanged — only network failures
			// arrive here.
			httplog.FromContext(r.Context()).Error("proxy: upstream error",
				"host", r.Host,
				"path", r.URL.RequestURI(),
				"error", err.Error())
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		// FlushInterval=-1 means "flush immediately after each Write" —
		// essential for SSE and chunked-streaming upstreams to deliver
		// data with low latency rather than buffering until the response
		// completes. Negative is the documented sentinel for "flush every
		// write".
		FlushInterval: -1,
	}

	return p
}

// ServeHTTP implements http.Handler. See Proxy doc for the per-request
// flow.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := httplog.FromContext(r.Context())

	// Step 0: resolve upstream up-front. If the inbound Host isn't in the
	// upstream map, there's nothing to protect — return the branded 404
	// immediately rather than bouncing the user through auth only to land
	// on this same page after sign-in. The previous order (auth, then
	// host) had a nasty local-dev failure mode: hitting `localhost:8083`
	// without a session would 302 to the configured AUTH_HOST (often the
	// production auth host), sucking the user into the wrong environment.
	entry, ok := p.hosts.Resolve(r.Host)
	if !ok {
		p.writeUnknownHost(w, r)
		return
	}

	// Step 1: read the session cookie.
	sessionID, ok := session.Read(r)
	if !ok {
		p.redirectToLogin(w, r, "no session cookie")
		return
	}

	// Step 2: look up the session row.
	sess, err := p.sessions.Get(r.Context(), sessionID)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrNotFound):
			logger.Info("proxy: session not found for cookie",
				"host", r.Host, "path", r.URL.RequestURI())
		case errors.Is(err, session.ErrExpired):
			logger.Info("proxy: session expired for cookie",
				"host", r.Host, "path", r.URL.RequestURI())
		default:
			logger.Error("proxy: session lookup error",
				"host", r.Host, "path", r.URL.RequestURI(), "error", err.Error())
		}
		p.redirectToLogin(w, r, "session lookup failed")
		return
	}

	// Step 3: look up the user row. A valid session referencing a missing
	// user row is a forced-logout race window (admin deleted the user
	// mid-session, ON DELETE CASCADE may not have run yet). Clear the
	// cookie so the browser doesn't keep presenting it.
	u, err := p.users.Get(r.Context(), sess.UserID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			logger.Warn("proxy: session references missing user; clearing cookie",
				"session_id", httplog.SessionID(sessionID),
				"user_id", sess.UserID)
			session.Clear(w, p.cfg.CookieDomain)
			p.redirectToLogin(w, r, "user missing")
			return
		}
		logger.Error("proxy: user lookup error",
			"user_id", sess.UserID, "error", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Step 4: Touch the session (60s-throttled). Failure is non-fatal —
	// log and continue per U4's documented contract.
	if err := p.sessions.Touch(r.Context(), sessionID); err != nil {
		logger.Warn("proxy: session touch failed; continuing",
			"user_id", sess.UserID, "error", err.Error())
	}

	// Stash the upstream and user on the request context so the Rewrite
	// callback can read them without closing over per-request state. Using
	// context for this means we keep the ReverseProxy a singleton (the
	// supported pattern) rather than building a fresh one per request.
	ctx := r.Context()
	ctx = context.WithValue(ctx, upstreamKey{}, entry.Target)
	ctx = context.WithValue(ctx, userKey{}, u)

	p.reverseProxy.ServeHTTP(w, r.WithContext(ctx))
}

// rewrite is the per-request ReverseProxy hook. It reads the upstream URL
// and the authenticated user from the request context, sets the outbound
// target, and runs the strip+inject pipeline from headers.go.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	upstream, _ := pr.In.Context().Value(upstreamKey{}).(*url.URL)
	u, _ := pr.In.Context().Value(userKey{}).(*user.User)

	// SetURL joins the inbound path with the upstream's base path correctly
	// (vs Director-era manual URL surgery, which is the historical
	// hop-by-hop footgun).
	pr.SetURL(upstream)
	// SetXForwarded discards inbound X-Forwarded-* and writes fresh values.
	pr.SetXForwarded()
	// Set Host header to the upstream's authority so name-based virtual
	// hosts on the upstream resolve correctly.
	pr.Out.Host = upstream.Host

	// Strip + inject the X-Forge-* contract. See headers.go for the
	// three-layer strip rationale and the nine-header inject contract.
	stripForgeHeaders(pr.Out)
	injectForgeHeaders(pr.Out, p.cfg.ProxySecret, u)
}

// redirectToLogin issues a 302 to the auth host's /auth/login with the
// inbound URL preserved in the return_to query parameter. We always
// reconstruct the inbound URL from r.Host + r.URL.RequestURI() — relying on
// r.URL.String() alone wouldn't include the scheme/host (the server-side
// request has them empty), and we want the return_to to round-trip back to
// the exact original URL.
func (p *Proxy) redirectToLogin(w http.ResponseWriter, r *http.Request, reason string) {
	inbound := "https://" + r.Host + r.URL.RequestURI()
	loginURL := p.loginURLPrefix + url.QueryEscape(inbound)
	httplog.FromContext(r.Context()).Info("proxy: redirecting to login",
		"reason", reason, "inbound", inbound, "login_url", loginURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// writeUnknownHost renders a minimal branded 404 page listing the known
// upstream hosts. 404 (not 502) is the right shape: the upstream-app
// doesn't exist as far as the proxy knows, which is closer to "not found"
// than "bad gateway" semantically.
//
// We render a tiny self-contained HTML page rather than calling into
// internal/web — keeping the dependency direction one-way (proxy doesn't
// import web) and avoiding the asset-tree wiring just for an error page.
// A future polish pass might unify these.
func (p *Proxy) writeUnknownHost(w http.ResponseWriter, r *http.Request) {
	httplog.FromContext(r.Context()).Warn("proxy: unknown host", "host", r.Host)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)

	hosts := p.hosts.Hosts()
	var hostList strings.Builder
	if len(hosts) == 0 {
		hostList.WriteString("<li>(none configured)</li>")
	} else {
		for _, h := range hosts {
			hostList.WriteString("<li><code>")
			hostList.WriteString(html.EscapeString(h))
			hostList.WriteString("</code></li>")
		}
	}

	body := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Unknown Forge app</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
code { background: #f3f3f3; padding: 0.1em 0.3em; border-radius: 3px; }
ul { line-height: 1.6; }
</style>
</head>
<body>
<h1>Unknown Forge app</h1>
<p>No upstream is configured for <code>%s</code>.</p>
<p>Available apps:</p>
<ul>%s</ul>
</body>
</html>
`, html.EscapeString(r.Host), hostList.String())

	_, _ = w.Write([]byte(body))
}

// upstreamKey and userKey are unexported context keys used to pass per-
// request state from ServeHTTP into the Rewrite callback without closing
// over per-request data on the singleton ReverseProxy.
type upstreamKey struct{}
type userKey struct{}
