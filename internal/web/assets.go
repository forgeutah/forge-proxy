package web

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
)

// FS embeds the login-page asset tree.
//
// The `all:` prefix is necessary so Go's embed machinery includes
// dotfiles or other non-default-included entries; in practice the tree is
// flat (index.html, three .jsx files, two style files, two images) and
// the prefix is belt-and-braces. Every request to this handler reads from
// memory — no disk I/O at request time, which is part of U7's
// "binary serves all assets from memory" verification.
//
//go:embed all:assets
var FS embed.FS

// AssetsFS returns the sub-filesystem rooted at the embedded `assets/`
// directory. Exposed for tests that want to inspect the embed contents
// (for example, to assert tweaks-panel.jsx is no longer present and that
// VariantTerminal/VariantSplit have been removed from auth-variants.jsx).
func AssetsFS() fs.FS {
	sub, err := fs.Sub(FS, "assets")
	if err != nil {
		// Sub on a static path can only fail if the embed itself is
		// malformed at build time — panicking here surfaces a build-time
		// problem as a startup-time problem rather than a 500 per request.
		panic("web: embed.FS missing assets/ root: " + err.Error())
	}
	return sub
}

// SessionChecker is the narrow surface the asset handler needs from the
// session store: given a request, is the caller already signed in? We
// pass an interface rather than the concrete *session.Store both to keep
// internal/web free of an upstream import on internal/session and to make
// the handler trivial to unit-test with a stub.
type SessionChecker interface {
	IsSignedIn(ctx context.Context, r *http.Request) bool
}

// Config carries the small set of values the handler needs from the
// process-wide config. Kept as a value type because it's read-only and
// the handler captures it in a closure at construction time.
type Config struct {
	// DefaultLandingURL is where an already-signed-in caller is redirected
	// when they hit the asset host root. Matches the U6 already-signed-in
	// contract — the React card is not rendered for live sessions.
	DefaultLandingURL string
}

// NewHandler composes the already-signed-in redirect with the embedded
// asset file server. The handler is intended to be mounted at the root
// of the auth host. Composition order is deliberate:
//
//  1. The /{$} root check runs first; a live session 302s to the default
//     landing URL (U6's R13 behaviour, ported into the web layer here).
//  2. Every other path is forwarded to http.FileServerFS over the
//     embedded sub-FS, wrapped with security headers.
//
// The session check is skipped for non-root paths because static assets
// (CSS / JS / images) should serve regardless of whether the caller is
// signed in — gating them would just produce a broken render on the
// already-signed-in 302 hop itself.
func NewHandler(checker SessionChecker, cfg Config) http.Handler {
	fileServer := http.FileServerFS(AssetsFS())
	secured := withSecurityHeaders(fileServer)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && checker != nil && checker.IsSignedIn(r.Context(), r) {
			http.Redirect(w, r, cfg.DefaultLandingURL, http.StatusFound)
			return
		}
		secured.ServeHTTP(w, r)
	})
}

// withSecurityHeaders applies the doc-review SEC headers to every
// response served from the embedded asset tree.
//
// CSP rationale:
//   - `default-src 'none'`: deny-by-default; every resource class must be
//     allow-listed explicitly below.
//   - `script-src 'self' https://unpkg.com 'unsafe-eval'`: the embedded
//     scripts are same-origin (auth-app.jsx, auth-core.jsx,
//     auth-variants.jsx); the React/ReactDOM/Babel runtimes load from
//     unpkg with SRI hashes pinned in index.html. The `'unsafe-eval'`
//     widening is the cost of the no-build-step decision recorded in
//     "Key Technical Decisions → Login page distribution": Babel-standalone
//     transpiles JSX at runtime via eval. The SRI hash on Babel and the
//     `'none'` connect-src below contain the blast radius — even if a
//     CDN were compromised, the integrity check fails closed and no XHR
//     escape hatch exists.
//   - `style-src 'self'`: only the bundled stylesheets.
//   - `img-src 'self' data:`: bundled images plus inline `data:` images
//     (the React SVGs in auth-core/auth-variants).
//   - `connect-src 'none'`: the login page makes NO fetch / XHR / WebSocket
//     calls. Sign-in proceeds through a top-level navigation to
//     /auth/login; the React app reads its state from the URL query.
//     Locking connect-src down is a meaningful narrowing.
//   - `frame-ancestors 'none'` + `X-Frame-Options: DENY`: clickjacking
//     defence on the auth origin.
//   - `base-uri 'self'`: defence against `<base>`-tag injection redirecting
//     relative URLs.
//
// We set the CSP on every response (HTML and non-HTML) so a mis-typed
// JSX served as text/html by some hostile intermediary still gets the
// same containment.
const cspPolicy = "default-src 'none'; " +
	"script-src 'self' https://unpkg.com 'unsafe-eval'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'"

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
