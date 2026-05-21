package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
