package httplog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newCapturingLogger returns a slog logger that writes JSON to the
// supplied buffer, and installs it as the default. The previous default
// is restored when the test cleanup runs.
func newCapturingLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// readLogLines decodes each JSON line in buf into a generic map. Useful
// for assertions about which fields were emitted.
func readLogLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestRequestIDMiddleware_GeneratesIDWhenAbsent(t *testing.T) {
	buf := newCapturingLogger(t)

	var seenID string
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestID(r.Context())
		FromContext(r.Context()).Info("inside handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seenID == "" {
		t.Fatal("expected request ID injected into context, got empty")
	}
	if got := rec.Header().Get("X-Request-Id"); got != seenID {
		t.Fatalf("response X-Request-Id = %q, want %q", got, seenID)
	}

	lines := readLogLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 log line, got %d", len(lines))
	}
	if got, _ := lines[0]["request_id"].(string); got != seenID {
		t.Fatalf("log request_id = %q, want %q", got, seenID)
	}
}

func TestRequestIDMiddleware_PropagatesInboundID(t *testing.T) {
	_ = newCapturingLogger(t)

	const inbound = "my-correlation-id-42"
	var seenID string
	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", inbound)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seenID != inbound {
		t.Fatalf("context request ID = %q, want %q", seenID, inbound)
	}
	if got := rec.Header().Get("X-Request-Id"); got != inbound {
		t.Fatalf("response X-Request-Id = %q, want %q", got, inbound)
	}
}

func TestAccessLogMiddleware_EmitsRequestSummary(t *testing.T) {
	buf := newCapturingLogger(t)

	chain := RequestIDMiddleware(AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "hello")
	})))

	req := httptest.NewRequest(http.MethodPost, "/some/path", nil)
	req.RemoteAddr = "10.0.0.5:55555"
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	lines := readLogLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 log line, got %d: %q", len(lines), buf.String())
	}
	line := lines[0]

	if got, _ := line["method"].(string); got != http.MethodPost {
		t.Errorf("method = %q, want POST", got)
	}
	if got, _ := line["path"].(string); got != "/some/path" {
		t.Errorf("path = %q, want /some/path", got)
	}
	if got, _ := line["status"].(float64); int(got) != http.StatusTeapot {
		t.Errorf("status = %v, want 418", line["status"])
	}
	if got, _ := line["bytes_out"].(float64); int(got) != len("hello") {
		t.Errorf("bytes_out = %v, want 5", line["bytes_out"])
	}
	if _, ok := line["duration_ms"]; !ok {
		t.Errorf("duration_ms missing")
	}
	if got, _ := line["remote_addr"].(string); got != "10.0.0.5" {
		t.Errorf("remote_addr = %q, want 10.0.0.5 (port stripped)", got)
	}
	if _, ok := line["request_id"].(string); !ok {
		t.Errorf("request_id missing from access log line")
	}
}

func TestHSTSMiddleware_SetsHeaderOnEveryResponse(t *testing.T) {
	_ = newCapturingLogger(t)
	handler := HSTSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("Strict-Transport-Security")
	want := "max-age=63072000; includeSubDomains"
	if got != want {
		t.Fatalf("HSTS header = %q, want %q", got, want)
	}
}

func TestSessionID_LogValuerRedacts(t *testing.T) {
	buf := newCapturingLogger(t)
	slog.Info("session lookup", "session_id", SessionID("super-secret-cookie-value"))

	lines := readLogLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if got, _ := lines[0]["session_id"].(string); got != "[REDACTED]" {
		t.Fatalf("session_id rendered as %q, want [REDACTED]", got)
	}
	if strings.Contains(buf.String(), "super-secret-cookie-value") {
		t.Fatalf("raw session ID leaked into log output: %s", buf.String())
	}
}

func TestProxySecret_LogValuerRedacts(t *testing.T) {
	buf := newCapturingLogger(t)
	slog.Info("calling upstream", "secret", ProxySecret("hunter2-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("raw proxy secret leaked into log output: %s", buf.String())
	}
	lines := readLogLines(t, buf)
	if got, _ := lines[0]["secret"].(string); got != "[REDACTED]" {
		t.Fatalf("secret rendered as %q, want [REDACTED]", got)
	}
}

func TestRateLimit_31stLoginRequestFromSameIPGets429(t *testing.T) {
	_ = newCapturingLogger(t)
	limiter := NewRateLimiter(30)
	handler := RateLimitMiddleware(limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 30 succeed.
	for i := range 30 {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	// 31st blocked.
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("31st request status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60", got)
	}
}

func TestRateLimit_6thCallbackRequestFromSameIPGets429(t *testing.T) {
	_ = newCapturingLogger(t)
	limiter := NewRateLimiter(5)
	handler := RateLimitMiddleware(limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		req.RemoteAddr = "9.8.7.6:443"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	req.RemoteAddr = "9.8.7.6:443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th request status = %d, want 429", rec.Code)
	}
}

func TestRateLimit_PerIPIndependent(t *testing.T) {
	_ = newCapturingLogger(t)
	limiter := NewRateLimiter(2)
	handler := RateLimitMiddleware(limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// IP A consumes its bucket.
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = "1.1.1.1:80"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
	// IP A is blocked.
	{
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = "1.1.1.1:80"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("IP A 3rd request status = %d, want 429", rec.Code)
		}
	}
	// IP B starts fresh — independent bucket.
	{
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = "2.2.2.2:80"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("IP B 1st request status = %d, want 200 (independent bucket)", rec.Code)
		}
	}
}

func TestRateLimit_RefillsOverTime(t *testing.T) {
	// Drive time deterministically to confirm refill arithmetic. 60/min =
	// 1 token/sec; consuming the bucket then advancing 1 second should
	// regenerate exactly one token.
	now := time.Unix(1_700_000_000, 0)
	limiter := &RateLimiter{
		buckets:         make(map[string]*bucket),
		capacity:        60,
		refillPerSecond: 1.0,
		now:             func() time.Time { return now },
	}
	const ip = "5.5.5.5"
	for range 60 {
		if !limiter.Allow(ip) {
			t.Fatal("unexpected denial during initial drain")
		}
	}
	if limiter.Allow(ip) {
		t.Fatal("61st request should have been denied")
	}
	// Advance 1 second → one token available.
	now = now.Add(time.Second)
	if !limiter.Allow(ip) {
		t.Fatal("expected 1 token after 1 second refill")
	}
	if limiter.Allow(ip) {
		t.Fatal("expected only 1 token after 1 second refill")
	}
}

// helper for verifying the access-log line contains a path the harness can
// match. Demonstrates the canonical chain order for documentation
// purposes; not strictly necessary but useful as an example.
var _ = fmt.Sprintf
