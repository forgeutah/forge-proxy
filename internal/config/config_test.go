package config

import (
	"fmt"
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
		"SSH_UPSTREAMS", "SSH_HOST_KEY_PATH", "SSH_CA_KEY_PATH",
		"SSH_KNOWN_HOSTS_PATH", "SSH_LISTEN_ADDR",
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
		{"empty url with role list", "deuce.forgeutah.tech=|ai-dev", "empty upstream url"},

		// Hosts are compared case-insensitively and the host map lowercases
		// its keys, so a case-differing duplicate would otherwise collapse
		// to one entry with a randomised winner.
		{"duplicate host differing in case", "Deuce.forgeutah.tech=http://a:1|ai-dev;deuce.forgeutah.tech=http://b:2", "duplicate inbound host"},

		// A comma anywhere in the target trips the legacy guard. Upstream
		// targets are origins, so this trade-off is deliberate: catching an
		// un-migrated config matters more than supporting a comma in a
		// query string. Pinned so the choice is revisited on purpose.
		{"comma inside a single target", "deuce.forgeutah.tech=http://deuce:8080/?a=1,2", "old comma-separated format"},
		{"empty role list", "deuce.forgeutah.tech=http://deuce:8080|", "empty role list"},
		{"blank role name", "deuce.forgeutah.tech=http://deuce:8080|ai-dev,,admin", "empty role name"},
		{"role with space", "deuce.forgeutah.tech=http://deuce:8080|ai dev", "invalid role name"},
		{"role with pipe", "deuce.forgeutah.tech=http://deuce:8080|ai|dev", "invalid role name"},

		// Covers AE5. The migration guard. Each of these parses
		// "successfully" as a URL if allowed through — that is precisely why
		// the guard exists, and why a parse-success check alone would let a
		// mangled upstream map boot.
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

	// Covers AE1. An entry with no '|' parses ungated — the backward-compatible
	// default that keeps every pre-gating entry working.
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

// TestLoad_UpstreamsHostLowercased pins that host keys are normalised at
// parse time. The proxy's host map lowercases its keys, so an entry stored
// under a mixed-case key here would be unreachable.
func TestLoad_UpstreamsHostLowercased(t *testing.T) {
	env := validEnv(t)
	env["UPSTREAMS"] = "Deuce.ForgeUtah.Tech=http://deuce:8080|ai-dev"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := cfg.UpstreamMap["deuce.forgeutah.tech"]; !ok {
		t.Fatalf("mixed-case host not normalised; keys present: %v", cfg.UpstreamMap)
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

// sshEnv overlays a minimal valid SSH configuration on top of a base env.
func sshEnv(t *testing.T, base map[string]string) map[string]string {
	t.Helper()
	tmp := t.TempDir()
	base["SSH_UPSTREAMS"] = "2222=deuce.tailnet:22|ai-dev;2223=platform.tailnet:22|admin,ops"
	base["SSH_HOST_KEY_PATH"] = filepath.Join(tmp, "host_key")
	base["SSH_CA_KEY_PATH"] = filepath.Join(tmp, "ca_key")
	base["SSH_KNOWN_HOSTS_PATH"] = filepath.Join(tmp, "known_hosts")
	return base
}

func TestLoad_SSHUpstreams_Disabled(t *testing.T) {
	// Empty SSH_UPSTREAMS means the SSH subsystem is disabled and none of
	// the SSH paths are required.
	cfg, err := setEnv(t, validEnv(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SSHUpstreams) != 0 {
		t.Errorf("SSHUpstreams = %v, want empty", cfg.SSHUpstreams)
	}
	if cfg.SSHListenAddr != "" {
		t.Errorf("SSHListenAddr = %q, want empty when disabled", cfg.SSHListenAddr)
	}
}

func TestLoad_SSHUpstreams_HappyPath(t *testing.T) {
	cfg, err := setEnv(t, sshEnv(t, validEnv(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SSHUpstreams) != 2 {
		t.Fatalf("SSHUpstreams size = %d, want 2", len(cfg.SSHUpstreams))
	}
	deuce, ok := cfg.SSHUpstreams[2222]
	if !ok {
		t.Fatal("missing port 2222 entry")
	}
	if deuce.Target.Host != "deuce.tailnet:22" {
		t.Errorf("port 2222 target = %q", deuce.Target.Host)
	}
	if len(deuce.AllowedRoles) != 1 || deuce.AllowedRoles[0] != "ai-dev" {
		t.Errorf("port 2222 roles = %v", deuce.AllowedRoles)
	}
	platform, ok := cfg.SSHUpstreams[2223]
	if !ok {
		t.Fatal("missing port 2223 entry")
	}
	if len(platform.AllowedRoles) != 2 || platform.AllowedRoles[0] != "admin" || platform.AllowedRoles[1] != "ops" {
		t.Errorf("port 2223 roles = %v", platform.AllowedRoles)
	}
	if cfg.SSHListenAddr != "0.0.0.0" {
		t.Errorf("SSHListenAddr default = %q, want 0.0.0.0", cfg.SSHListenAddr)
	}
}

func TestLoad_SSHRequiresKeyPathsWhenEnabled(t *testing.T) {
	cases := []string{
		"SSH_HOST_KEY_PATH",
		"SSH_CA_KEY_PATH",
		"SSH_KNOWN_HOSTS_PATH",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			env := sshEnv(t, validEnv(t))
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

func TestLoad_SSHUpstreams_Parsing(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"duplicate port", "2222=a:22|x;2222=b:22|y", "duplicate port"},
		{"port out of range", "70000=host:22|x", "out of range"},
		{"missing pipe", "2222=deuce.tailnet:22", "role list missing"},
		{"role with semicolon", "2222=deuce.tailnet:22|ad;min", "missing '='"},
		{"role with bad char", "2222=deuce.tailnet:22|ad min", "invalid role name"},
		{"missing port", "=deuce.tailnet:22|admin", "empty port"},
		{"missing target", "2222=|admin", "empty target"},
		{"empty role list", "2222=deuce.tailnet:22|", "empty role list"},
		{"target missing port", "2222=deuce.tailnet|admin", "target missing port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sshEnv(t, validEnv(t))
			env["SSH_UPSTREAMS"] = tc.value
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

// --- SSH_UPSTREAMS port ranges -------------------------------------------

// TestLoad_SSHUpstreams_RangeExpands covers the port-preserving range form:
// one entry exposes a contiguous block of proxy ports, each forwarding to
// the same host on the same port number. This is how a VM running one
// container sshd per port is reached.
func TestLoad_SSHUpstreams_RangeExpands(t *testing.T) {
	env := sshEnv(t, validEnv(t))
	env["SSH_UPSTREAMS"] = "2300-2302=deuce.tailnet|ai-dev"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.SSHUpstreams) != 3 {
		t.Fatalf("SSHUpstreams size = %d, want 3", len(cfg.SSHUpstreams))
	}
	for port := 2300; port <= 2302; port++ {
		up, ok := cfg.SSHUpstreams[port]
		if !ok {
			t.Fatalf("port %d missing from expansion", port)
		}
		if up.Port != port {
			t.Errorf("port %d: Port = %d", port, up.Port)
		}
		wantHost := fmt.Sprintf("deuce.tailnet:%d", port)
		if up.Target.Host != wantHost {
			t.Errorf("port %d: target = %q, want %q", port, up.Target.Host, wantHost)
		}
		if len(up.AllowedRoles) != 1 || up.AllowedRoles[0] != "ai-dev" {
			t.Errorf("port %d: roles = %v, want [ai-dev]", port, up.AllowedRoles)
		}
	}
}

// TestLoad_SSHUpstreams_RangeTargetsAreIndependent guards against sharing
// one *url.URL across every expanded entry -- a later mutation through any
// one of them would otherwise silently retarget the whole range.
func TestLoad_SSHUpstreams_RangeTargetsAreIndependent(t *testing.T) {
	env := sshEnv(t, validEnv(t))
	env["SSH_UPSTREAMS"] = "2300-2301=deuce.tailnet|ai-dev"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SSHUpstreams[2300].Target == cfg.SSHUpstreams[2301].Target {
		t.Error("expanded entries share one *url.URL; each port needs its own")
	}
}

func TestLoad_SSHUpstreams_RangeAndSingleTogether(t *testing.T) {
	env := sshEnv(t, validEnv(t))
	env["SSH_UPSTREAMS"] = "2222=box.tailnet:22|ops;2300-2302=deuce.tailnet|ai-dev"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SSHUpstreams) != 4 {
		t.Fatalf("SSHUpstreams size = %d, want 4 (1 single + 3 expanded)", len(cfg.SSHUpstreams))
	}
	single, ok := cfg.SSHUpstreams[2222]
	if !ok {
		t.Fatal("single-port entry missing")
	}
	if single.Target.Host != "box.tailnet:22" {
		t.Errorf("single target = %q, want box.tailnet:22", single.Target.Host)
	}
	if got := cfg.SSHUpstreams[2301].Target.Host; got != "deuce.tailnet:2301" {
		t.Errorf("range target = %q, want deuce.tailnet:2301", got)
	}
}

func TestLoad_SSHUpstreams_SinglePortRange(t *testing.T) {
	env := sshEnv(t, validEnv(t))
	env["SSH_UPSTREAMS"] = "2300-2300=deuce.tailnet|ai-dev"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SSHUpstreams) != 1 {
		t.Fatalf("SSHUpstreams size = %d, want 1", len(cfg.SSHUpstreams))
	}
	if got := cfg.SSHUpstreams[2300].Target.Host; got != "deuce.tailnet:2300" {
		t.Errorf("target = %q, want deuce.tailnet:2300", got)
	}
}

func TestLoad_SSHUpstreams_MultipleRangesDifferentHosts(t *testing.T) {
	env := sshEnv(t, validEnv(t))
	env["SSH_UPSTREAMS"] = "2300-2301=alpha.tailnet|ai-dev;2400-2401=beta.tailnet|ops"
	cfg, err := setEnv(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SSHUpstreams) != 4 {
		t.Fatalf("SSHUpstreams size = %d, want 4", len(cfg.SSHUpstreams))
	}
	if got := cfg.SSHUpstreams[2300].Target.Host; got != "alpha.tailnet:2300" {
		t.Errorf("2300 target = %q", got)
	}
	if got := cfg.SSHUpstreams[2401].Target.Host; got != "beta.tailnet:2401" {
		t.Errorf("2401 target = %q", got)
	}
	if got := cfg.SSHUpstreams[2401].AllowedRoles; len(got) != 1 || got[0] != "ops" {
		t.Errorf("2401 roles = %v, want [ops]", got)
	}
}

func TestLoad_SSHUpstreams_RangeErrors(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"reversed range", "2310-2300=host|role", "reversed"},
		{"range too wide", "2000-3000=host|role", "256"},
		{"range with explicit target port", "2300-2310=deuce.tailnet:22|ai-dev", "derives"},
		{"overlapping ranges", "2300-2310=a|r;2305-2315=b|r", "duplicate port"},
		{"range overlaps single", "2300-2310=a|r;2305=b:22|r", "duplicate port"},
		{"non-numeric low", "23a0-2310=host|role", "invalid"},
		{"non-numeric high", "2300-23z0=host|role", "invalid"},
		{"low out of range", "0-10=host|role", "out of range"},
		{"high out of range", "65530-65540=host|role", "out of range"},
		{"empty low", "-2310=host|role", "invalid"},
		{"empty high", "2300-=host|role", "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sshEnv(t, validEnv(t))
			env["SSH_UPSTREAMS"] = tc.value
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
