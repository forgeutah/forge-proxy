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
// CSP rationale — this policy is intentionally more permissive than a
// pre-bundled SPA would need. The cost is the no-build-step decision
// recorded in "Key Technical Decisions → Login page distribution":
// Babel-standalone runs at page load, XHRs the .jsx sources from the
// same origin, transpiles them, and injects the result as INLINE
// <script> blocks. Plus the React app uses style={{...}} props which
// React renders as inline style="..." attributes. Plus we pull Google
// Fonts. Each of those drives one widening below.
//
//   - `default-src 'none'`: deny-by-default; every resource class must be
//     allow-listed explicitly below.
//   - `script-src 'self' https://unpkg.com 'unsafe-eval' 'unsafe-inline'`:
//     same-origin scripts (auth-app.jsx etc.), the React/ReactDOM/Babel
//     runtimes from unpkg with SRI hashes pinned in index.html,
//     `'unsafe-eval'` for Babel's runtime JSX transform, and
//     `'unsafe-inline'` because Babel re-injects the transformed code as
//     an inline <script>. SRI on the unpkg scripts is the meaningful
//     containment that survives this widening.
//   - `style-src 'self' https://fonts.googleapis.com 'unsafe-inline'`:
//     bundled stylesheets, the Google Fonts stylesheet referenced by
//     index.html, and `'unsafe-inline'` for React's style={{...}} prop
//     output (rendered to DOM as `style="..."` attributes).
//   - `font-src 'self' https://fonts.gstatic.com`: the actual font files
//     fetched by the Google Fonts stylesheet.
//   - `img-src 'self' data:`: bundled images plus inline `data:` images
//     (the React SVGs in auth-core/auth-variants).
//   - `connect-src 'self'`: Babel XHRs `/auth-core.jsx`, `/auth-app.jsx`,
//     `/auth-variants.jsx` from the same origin to fetch their source
//     before transpiling. Same-origin only — no cross-origin escape.
//   - `frame-ancestors 'none'` + `X-Frame-Options: DENY`: clickjacking
//     defence on the auth origin.
//   - `base-uri 'self'`: defence against `<base>`-tag injection redirecting
//     relative URLs.
//
// Future work: an esbuild bundling step would let us drop
// `'unsafe-eval'`, `'unsafe-inline'` on script-src, and the broad
// connect-src, returning the policy to something closer to the
// pre-Babel target. That's deferred.
//
// We set the CSP on every response (HTML and non-HTML) so a mis-typed
// JSX served as text/html by some hostile intermediary still gets the
// same containment.
const cspPolicy = "default-src 'none'; " +
	"script-src 'self' https://unpkg.com 'unsafe-eval' 'unsafe-inline'; " +
	"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; " +
	"font-src 'self' https://fonts.gstatic.com; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
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
