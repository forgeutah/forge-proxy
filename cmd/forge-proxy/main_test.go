package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakePinger is a pinger stub for the /readyz tests.
type fakePinger struct{ err error }

func (f fakePinger) PingContext(_ context.Context) error { return f.err }

// fakeOIDC implements readinessOIDC.
type fakeOIDC struct{ ready bool }

func (f fakeOIDC) IsReady() bool { return f.ready }

// fakeSweeper implements readinessSweeper.
type fakeSweeper struct{ last time.Time }

func (f fakeSweeper) LastSuccess() time.Time { return f.last }

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	if got, want := string(body), "ok"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("content-type = %q, want text/plain", got)
	}
}

func TestReadyz_HealthyReturns200(t *testing.T) {
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Now()},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "ready") {
		t.Fatalf("body = %q, want to contain 'ready'", string(body))
	}
}

func TestReadyz_OIDCNotReadyReturns503(t *testing.T) {
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: false},
		fakeSweeper{},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "oidc") {
		t.Fatalf("body = %q, want to mention oidc", string(body))
	}
}

func TestReadyz_DBPingFailureReturns503(t *testing.T) {
	h := readyzHandler(
		fakePinger{err: errors.New("writer down")},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Now()},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "writer db") {
		t.Fatalf("body = %q, want to mention writer db", string(body))
	}
}

func TestReadyz_ColdStartSweeperZeroIsAcceptable(t *testing.T) {
	// LastSuccess().IsZero() means "sweeper has not yet completed a run."
	// The handler tolerates this so /readyz doesn't fail during the first
	// hour of life. Anything else returning healthy keeps the response 200.
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Time{}},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (cold-start carve-out)", rec.Code)
	}
}

func TestReadyz_StaleSweeperReturns503(t *testing.T) {
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Now().Add(-3 * time.Hour)},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (stale sweeper)", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "sweeper") {
		t.Fatalf("body = %q, want to mention sweeper", string(body))
	}
}

// TestHostMatches pins the dispatcher behaviour: case-insensitive Host
// comparison with port stripping. The auth host wins for matching inbound
// values; everything else falls through to the proxy.
func TestHostMatches(t *testing.T) {
	cases := []struct {
		inbound  string
		authHost string
		want     bool
	}{
		{"auth.forgeutah.tech", "auth.forgeutah.tech", true},
		{"AUTH.forgeutah.tech", "auth.forgeutah.tech", true},
		{"auth.forgeutah.tech:8080", "auth.forgeutah.tech", true},
		{"deuce.forgeutah.tech", "auth.forgeutah.tech", false},
		{"auth.forgeutah.tech.evil.com", "auth.forgeutah.tech", false},
		{"", "auth.forgeutah.tech", false},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.inbound, tc.authHost); got != tc.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tc.inbound, tc.authHost, got, tc.want)
		}
	}
}
