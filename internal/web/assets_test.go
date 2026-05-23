package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServer builds the asset handler under test. The handler no longer
// consults session state — signed-in/out branching happens client-side
// via /auth/me — so the constructor takes no arguments.
func newServer() http.Handler {
	return NewHandler()
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

// TestRoot_NoSession_ServesIndexHTML covers the happy path: an unsigned
// request to / receives the React entry HTML with the correct content
// type and the doc-review CSP header attached.
func TestRoot_NoSession_ServesIndexHTML(t *testing.T) {
	h := newServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q; want text/html prefix", ct)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != cspPolicy {
		t.Fatalf("CSP = %q; want %q", got, cspPolicy)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q; want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q; want DENY", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q; want same-origin", got)
	}
	// Spot-check the index body to make sure the embedded file is really
	// what was served (not, say, a directory listing or a 404 HTML).
	body := rec.Body.String()
	if !strings.Contains(body, `<div id="root">`) {
		t.Fatalf("body missing React mount point; body=%q", body)
	}
}

// TestStyles_ServesCSS verifies a request for a bundled stylesheet
// returns the file with the right content type and the nosniff header
// — defence-in-depth even on non-HTML responses.
func TestStyles_ServesCSS(t *testing.T) {
	h := newServer()
	req := httptest.NewRequest(http.MethodGet, "/styles/auth.css", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type = %q; want text/css prefix", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q; want nosniff", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != cspPolicy {
		t.Fatalf("CSP = %q; want it set on static assets too", got)
	}
}

// TestJSX_ServedAsNonHTML — the JSX files are served verbatim as bytes;
// Go's MIME mapping may classify .jsx as application/octet-stream or
// text/javascript depending on the platform. The important security
// property is that they are NOT served as text/html — a mis-typed JSX
// response could otherwise be interpreted as an HTML document by a
// browser and trigger XSS via fragment scripts.
func TestJSX_ServedAsNonHTML(t *testing.T) {
	h := newServer()
	req := httptest.NewRequest(http.MethodGet, "/auth-app.jsx", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q; .jsx must not be served as text/html", ct)
	}
	// CSP must still be set on JSX responses.
	if got := rec.Header().Get("Content-Security-Policy"); got != cspPolicy {
		t.Fatalf("CSP = %q; want it set on JSX responses too", got)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

// TestPathTraversal_404 confirms http.FileServerFS's default behaviour
// rejects parent-traversal attempts. We never expose anything outside the
// embedded `assets/` subtree, but the test guards against a future
// refactor that swaps in a wrapper which forgets to clean paths.
func TestPathTraversal_404(t *testing.T) {
	h := newServer()
	req := httptest.NewRequest(http.MethodGet, "/styles/../../etc/passwd", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// FileServerFS resolves the cleaned path; anything outside the embed
	// returns 404. The exact status may also be 301 (a redirect to the
	// cleaned path) on certain Go versions — accept both as "did not leak
	// the file" so the test stays portable.
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d; want 404 or 301", rec.Code)
	}
	// Whatever the response, it must not contain the literal "root:" tag
	// that would indicate an actual passwd file slipped through.
	if strings.Contains(rec.Body.String(), "root:") {
		t.Fatalf("response leaked passwd-like content: %q", rec.Body.String())
	}
}

// TestVariantsJSX_ContainsCardOnly is a regression guard. The U7
// narrowing deleted VariantTerminal and VariantSplit; if a future change
// re-introduces either, this test should catch it before the embedded
// asset ships.
func TestVariantsJSX_ContainsCardOnly(t *testing.T) {
	data, err := fs.ReadFile(AssetsFS(), "auth-variants.jsx")
	if err != nil {
		t.Fatalf("read auth-variants.jsx: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "VariantCard") {
		t.Fatalf("auth-variants.jsx missing VariantCard export")
	}
	if strings.Contains(body, "VariantTerminal") {
		t.Fatalf("auth-variants.jsx still references VariantTerminal — U7 narrowing regressed")
	}
	if strings.Contains(body, "VariantSplit") {
		t.Fatalf("auth-variants.jsx still references VariantSplit — U7 narrowing regressed")
	}
}

// TestTweaksPanel_NotEmbedded confirms the dev-only tweaks-panel.jsx is
// no longer present in the embedded FS. The plan calls this out as an
// explicit verification: the file must not ship.
func TestTweaksPanel_NotEmbedded(t *testing.T) {
	if _, err := fs.Stat(AssetsFS(), "tweaks-panel.jsx"); err == nil {
		t.Fatalf("tweaks-panel.jsx must not be present in the embedded FS")
	}
	// Walk the entire tree to confirm no other variant of the file exists
	// in a subdirectory (e.g. styles/tweaks-panel.jsx).
	_ = fs.WalkDir(AssetsFS(), ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(path), "tweaks") {
			t.Fatalf("found tweaks-* file in embedded tree: %s", path)
		}
		return nil
	})
}

// TestIndexHTML_HasSRIOnBabel verifies the Subresource Integrity hash is
// present on the Babel-standalone script tag. SRI on Babel is SEC-001
// from the doc-review pass — without it a compromised CDN response
// would execute as code on every cold load.
func TestIndexHTML_HasSRIOnBabel(t *testing.T) {
	data, err := fs.ReadFile(AssetsFS(), "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	body := string(data)
	// Find the Babel <script> tag; assert it has a sha384- integrity
	// attribute and crossorigin=anonymous. We use string searches rather
	// than an HTML parser because the embedded file's shape is stable
	// and parser overhead is unnecessary.
	babelIdx := strings.Index(body, "@babel/standalone")
	if babelIdx < 0 {
		t.Fatalf("index.html missing @babel/standalone reference")
	}
	// Bound the lookahead to the next closing > of the script tag.
	tagEnd := strings.Index(body[babelIdx:], ">")
	if tagEnd < 0 {
		t.Fatalf("malformed @babel/standalone script tag")
	}
	tag := body[babelIdx : babelIdx+tagEnd]
	if !strings.Contains(tag, "integrity=\"sha384-") {
		t.Fatalf("Babel script tag missing SRI integrity attribute: %q", tag)
	}
	if !strings.Contains(tag, `crossorigin="anonymous"`) {
		t.Fatalf("Babel script tag missing crossorigin=anonymous: %q", tag)
	}
}

// TestRoot_ErrorQueryParam_ServesSameIndexHTML — the ?error=... query
// param is consumed client-side by the React app, not by the server.
// Every error variant returns the same bytes; the React app reads the
// query and renders the right copy. We assert byte-identity rather than
// just status to catch a future regression that adds server-side
// branching back in.
func TestRoot_ErrorQueryParam_ServesSameIndexHTML(t *testing.T) {
	h := newServer()

	get := func(path string) []byte {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status for %s = %d, want 200", path, rec.Code)
		}
		return rec.Body.Bytes()
	}

	plain := get("/")
	authFailed := get("/?error=auth_failed")
	notInWs := get("/?error=not_in_workspace")

	if string(plain) != string(authFailed) {
		t.Fatalf("?error=auth_failed body differs from plain — server is branching on query, should be client-side")
	}
	if string(plain) != string(notInWs) {
		t.Fatalf("?error=not_in_workspace body differs from plain — server is branching on query, should be client-side")
	}
}

