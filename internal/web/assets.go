package web

import (
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

// NewHandler serves the embedded React asset tree from the auth host
// root. Signed-in state is intentionally NOT handled here as a redirect:
// the React app fetches /auth/me on mount and renders either the portal
// (signed-in) or the sign-in card (signed-out). Doing the branch
// client-side means a fresh hit to "/" always returns the same cacheable
// HTML and avoids the redirect loop that bit us when DefaultLandingURL
// pointed back at the auth host root.
func NewHandler() http.Handler {
	fileServer := http.FileServerFS(AssetsFS())
	return withSecurityHeaders(fileServer)
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
