package httplog

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ctxKeyRequestID is the context key for the per-request ID. It is a
// zero-size struct so the key cannot collide with any other package's
// context key (only this package can construct a value of this type).
type ctxKeyRequestID struct{}

// ctxKeyLogger is the context key for the per-request *slog.Logger. The
// logger is pre-populated with request_id so handlers calling
// FromContext(r.Context()).Info(...) automatically emit correlated logs.
type ctxKeyLogger struct{}

// requestIDHeader is the canonical HTTP header carrying the request ID.
// We accept any incoming value (idempotent retries reuse the same ID) and
// echo it on the response so clients can correlate logs across hops.
const requestIDHeader = "X-Request-Id"

// RequestID extracts the request ID stashed in ctx, or "" if none. Useful
// for handlers that want to thread the ID into upstream calls.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID{}).(string); ok {
		return v
	}
	return ""
}

// FromContext returns the request-scoped logger, or slog.Default() if the
// context was not enriched (e.g. handlers reached without going through
// the middleware chain — typically tests or background goroutines).
func FromContext(ctx context.Context) *slog.Logger {
	if v, ok := ctx.Value(ctxKeyLogger{}).(*slog.Logger); ok && v != nil {
		return v
	}
	return slog.Default()
}

// newRequestID returns a base64url-encoded 128-bit random ID. Short enough
// to fit cleanly in log lines, long enough that collisions across the
// lifetime of any single VM are negligible.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure on Linux means the kernel RNG is broken;
		// fall back to a time-based ID so logging keeps working. Any
		// duplication risk is acceptable next to "logging silently drops".
		return "rng-fallback-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// RequestIDMiddleware injects a request ID into the request context and
// echoes it on the response header. If the inbound request already carries
// X-Request-Id, that value is propagated unchanged so callers (the LB, the
// retry layer, an upstream service) can correlate logs end-to-end.
//
// The middleware also stashes a request-scoped *slog.Logger on the context
// with the request_id pre-populated, so handler code can do
//
//	httplog.FromContext(ctx).Info("about to do thing", "thing", x)
//
// without remembering to add request_id manually.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(requestIDHeader, id)

		logger := slog.Default().With("request_id", id)

		ctx := r.Context()
		ctx = context.WithValue(ctx, ctxKeyRequestID{}, id)
		ctx = context.WithValue(ctx, ctxKeyLogger{}, logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// statusRecorder wraps http.ResponseWriter to capture the status code and
// byte count for the access log. WriteHeader is the only hook we need —
// Write implicitly writes 200 if WriteHeader hasn't been called yet, so we
// initialise status to 200 and let WriteHeader override.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// AccessLogMiddleware emits one structured log line per request at request
// end. Fields: method, path, status, duration_ms, bytes_out, remote_addr,
// request_id. The user_id field is intentionally absent at this layer — a
// future unit can stash a user ID on the context (similar to request_id)
// and the access log would pick it up automatically. The hook lives here
// but no setter is exposed yet; emit nothing rather than emit a wrong/zero
// value.
func AccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		dur := time.Since(start)

		FromContext(r.Context()).Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", dur.Milliseconds(),
			"bytes_out", rec.bytes,
			"remote_addr", clientIP(r),
		)
	})
}

// HSTSMiddleware sets Strict-Transport-Security on every response.
// max-age=63072000 (two years) with includeSubDomains is the value
// expected by the HSTS preload list; adding the proxy's apex domain to the
// preload list is a future operational step (see U10's runbook). The
// header is safe to set for HTTP responses too — browsers ignore it over
// plaintext per RFC 6797 §7.2.
func HSTSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// clientIP strips the port suffix from r.RemoteAddr and returns just the
// host portion. For a v1 single-VM deploy on exe.dev there is no trusted
// load balancer in front of the proxy, so X-Forwarded-For is not
// consulted here. If we ever move behind a trusted L7 LB, this is the
// function to revisit (and the rate-limiter that uses it).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without a port (rare; httptest does this) — use it
		// verbatim rather than dropping the field.
		return r.RemoteAddr
	}
	return host
}

// ClientIP is exported for the rate-limit middleware (same file's
// package) and any future caller that needs the same IP rule.
func ClientIP(r *http.Request) string { return clientIP(r) }
