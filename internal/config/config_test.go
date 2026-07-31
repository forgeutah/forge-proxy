package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// validEnv returns a map of all required env vars set to valid values.
// Tests start from this baseline and mutate individual keys.
func validEnv(t *testing.T) map[string]string {
	t.Helper()
	tmp := t.TempDir()
	return map[string]string{
		"BASE_DOMAIN":         "forgeutah.tech",
		"AUTH_HOST":           "auth.forgeutah.tech",
		"SLACK_CLIENT_ID":     "1234.5678",
		"SLACK_CLIENT_SECRET": "abcdef0123456789abcdef0123456789",
		"SLACK_TEAM_ID":       "T0R7GR",
		"DB_PATH":             filepath.Join(tmp, "forge.db"),
		"PROXY_SECRET":        "this-is-a-test-secret-with-32+-chars",
		// One gated entry and one ungated, so the common fixture exercises
		// both shapes of the grammar.
		"UPSTREAMS": "deuce.forgeutah.tech=http://deuce:8080|ai-dev,admin;platform.forgeutah.tech=http://platform:8080",
	}
}

// setEnv installs env, clears anything not in env, returns Load() result.
func setEnv(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	// Set every key we care about, blanking ones absent from the map.
	all := []string{
		"LISTEN_ADDR", "LOG_LEVEL",
		"BASE_DOMAIN", "AUTH_HOST",
		"SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET", "SLACK_TEAM_ID",
		"DB_PATH", "PROXY_SECRET", "UPSTREAMS",
		"SESSION_LIFETIME", "SESSION_IDLE_TIMEOUT", "DEFAULT_LANDING_URL",
	}
	for _, k := range all {
		if v, ok := env[k]; ok {
			t.Setenv(k, v)
		} else {
			t.Setenv(k, "")
		}
	}
	return Load()
}

func TestLoad_HappyPath(t *testing.T) {
	cfg, err := setEnv(t, validEnv(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseDomain != "forgeutah.tech" {
		t.Errorf("BaseDomain = %q", cfg.BaseDomain)
	}
	if cfg.CookieDomain != ".forgeutah.tech" {
		t.Errorf("CookieDomain = %q, want leading-dot form", cfg.CookieDomain)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr default = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.SessionLifetime != 30*24*time.Hour {
		t.Errorf("SessionLifetime default = %s", cfg.SessionLifetime)
	}
	if cfg.SessionIdleTimeout != 14*24*time.Hour {
		t.Errorf("SessionIdleTimeout default = %s", cfg.SessionIdleTimeout)
	}
	if len(cfg.UpstreamMap) != 2 {
		t.Errorf("UpstreamMap size = %d, want 2", len(cfg.UpstreamMap))
	}
	if cfg.DefaultLandingURL != "https://auth.forgeutah.tech/" {
		t.Errorf("DefaultLandingURL = %q", cfg.DefaultLandingURL)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	cases := []string{
		"BASE_DOMAIN", "AUTH_HOST",
		"SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET", "SLACK_TEAM_ID",
		"DB_PATH", "PROXY_SECRET", "UPSTREAMS",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			env := validEnv(t)
			delete(env, key)
			_, err := setEnv(t, env)
			if err == nil {
				t.Fatalf("expected error when %s missing", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not mention missing key %q", err, key)
			}
		})
	}
}

func TestLoad_SlackTeamIDShape(t *testing.T) {
	env := validEnv(t)
	env["SLACK_TEAM_ID"] = "NotATeam"
	_, err := setEnv(t, env)
	if err == nil {
		t.Fatal("expected error for malformed SLACK_TEAM_ID")
	}
	if !strings.Contains(err.Error(), "SLACK_TEAM_ID") {
		t.Errorf("error does not mention SLACK_TEAM_ID: %v", err)
	}
}

func TestLoad_ProxySecretMinLength(t *testing.T) {
	env := validEnv(t)
	env["PROXY_SECRET"] = "short"
	_, err := setEnv(t, env)
	if err == nil {
		t.Fatal("expected error for short PROXY_SECRET")
	}
	if !strings.Contains(err.Error(), "PROXY_SECRET") || !strings.Contains(err.Error(), "32") {
		t.Errorf("error should mention PROXY_SECRET and 32-char minimum: %v", err)
	}
}

func TestLoad_UpstreamsParsing(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"empty", "", "UPSTREAMS is required"},
		{"missing equals", "deuce.forgeutah.tech-http://deuce:8080", "missing '='"},
		{"bad scheme", "deuce.forgeutah.tech=ftp://deuce:8080", "scheme must be http or https"},
		{"bad url", "deuce.forgeutah.tech=not-a-url", "scheme must be http or https"},
		{"duplicate host", "deuce.forgeutah.tech=http://a:1;deuce.forgeutah.tech=http://b:2", "duplicate inbound host"},
		{"empty host", "=http://deuce:8080", "empty host or url"},
		{"empty url", "deuce.forgeutah.tech=", "empty host or url"},
		{"empty role list", "deuce.forgeutah.tech=http://deuce:8080|", "empty role list"},
		{"blank role name", "deuce.forgeutah.tech=http://deuce:8080|ai-dev,,admin", "empty role name"},
		{"role with space", "deuce.forgeutah.tech=http://deuce:8080|ai dev", "invalid role name"},
		{"role with pipe", "deuce.forgeutah.tech=http://deuce:8080|ai|dev", "invalid role name"},

		// The migration guard. Each of these parses "successfully" as a URL
		// if allowed through — that is precisely why the guard exists.
		{"legacy comma form", "deuce.forgeutah.tech=http://deuce:8080,platform.forgeutah.tech=http://platform:8080", "old comma-separated format"},
		{"legacy comma form single trailing", "deuce.forgeutah.tech=http://deuce:8080,", "old comma-separated format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv(t)
			env["UPSTREAMS"] = tc.value
			_, err := setEnv(t, env)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoad_UpstreamsParsed(t *testing.T) {
	cfg, err := setEnv(t, validEnv(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	gated, ok := cfg.UpstreamMap["deuce.forgeutah.tech"]
	if !ok {
		t.Fatal("missing deuce.forgeutah.tech entry")
	}
	if gated.Target.String() != "http://deuce:8080" {
		t.Errorf("deuce url = %q", gated.Target.String())
	}
	if got, want := gated.RequiredRoles, []string{"ai-dev", "admin"}; !slices.Equal(got, want) {
		t.Errorf("deuce roles = %v, want %v (declaration order preserved)", got, want)
	}
	if !gated.Gated() {
		t.Error("deuce entry should report gated")
	}

	ungated, ok := cfg.UpstreamMap["platform.forgeutah.tech"]
	if !ok {
		t.Fatal("missing platform.forgeutah.tech entry")
	}
	if ungated.Target.String() != "http://platform:8080" {
		t.Errorf("platform url = %q", ungated.Target.String())
	}
	if len(ungated.RequiredRoles) != 0 {
		t.Errorf("platform roles = %v, want none (no '|' means ungated)", ungated.RequiredRoles)
	}
	if ungated.Gated() {
		t.Error("platform entry should report ungated")
	}
}

func TestUpstream_Permits(t *testing.T) {
	cases := []struct {
		name      string
		required  []string
		userRoles []string
		want      bool
	}{
		{"ungated permits roleless user", nil, nil, true},
		{"ungated permits any user", nil, []string{"admin"}, true},
		{"gated permits exact match", []string{"ai-dev"}, []string{"ai-dev"}, true},
		{"gated permits any one of several", []string{"ai-dev", "admin"}, []string{"admin"}, true},
		{"gated permits when user has extras", []string{"ai-dev"}, []string{"organizer", "ai-dev"}, true},
		{"gated denies roleless user", []string{"ai-dev"}, nil, false},
		{"gated denies non-matching role", []string{"ai-dev"}, []string{"admin"}, false},
		// admin is an ordinary role name, not a bypass.
		{"admin is not a bypass", []string{"ai-dev"}, []string{"admin"}, false},
		// Exact comparison, not prefix or substring.
		{"denies role with matching prefix", []string{"ai-dev"}, []string{"ai-dev-admin"}, false},
		{"denies role that contains requirement", []string{"dev"}, []string{"ai-dev"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := Upstream{RequiredRoles: tc.required}
			if got := u.Permits(tc.userRoles); got != tc.want {
				t.Errorf("Permits(%v) with required %v = %v, want %v",
					tc.userRoles, tc.required, got, tc.want)
			}
		})
	}
}

func TestLoad_AuthHostMustBeSubdomain(t *testing.T) {
	env := validEnv(t)
	env["AUTH_HOST"] = "auth.example.com"
	_, err := setEnv(t, env)
	if err == nil {
		t.Fatal("expected error when AUTH_HOST is not under BASE_DOMAIN")
	}
}

func TestLoad_DBPathDirMustExist(t *testing.T) {
	env := validEnv(t)
	env["DB_PATH"] = "/nonexistent-forgeutah-dir/forge.db"
	_, err := setEnv(t, env)
	if err == nil {
		t.Fatal("expected error for nonexistent DB_PATH dir")
	}
}

func TestLoad_IdleCannotExceedLifetime(t *testing.T) {
	env := validEnv(t)
	env["SESSION_LIFETIME"] = "24h"
	env["SESSION_IDLE_TIMEOUT"] = "48h"
	_, err := setEnv(t, env)
	if err == nil {
		t.Fatal("expected error when idle > lifetime")
	}
}

func TestLoad_DefaultLandingURLOverride(t *testing.T) {
	env := validEnv(t)
	env["DEFAULT_LANDING_URL"] = "https://platform.forgeutah.tech/"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultLandingURL != "https://platform.forgeutah.tech/" {
		t.Errorf("DefaultLandingURL = %q", cfg.DefaultLandingURL)
	}
}
