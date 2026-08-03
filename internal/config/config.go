// Package config loads and validates environment-driven configuration.
// Fails fast on missing or invalid values; never reads .env at runtime.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is the validated, immutable runtime configuration.
type Config struct {
	ListenAddr   string
	BaseDomain   string // e.g. "forgeutah.tech"
	AuthHost     string // e.g. "auth.forgeutah.tech"
	CookieDomain string // e.g. ".forgeutah.tech"

	SlackClientID     string
	SlackClientSecret string
	SlackTeamID       string

	DBPath string

	// UpstreamMap maps inbound Host header to its upstream target and the
	// roles a signed-in user must hold to reach it.
	//
	// Built from env var UPSTREAMS=host=url|role1,role2;host=url — see
	// parseUpstreams for the grammar. An entry with no role list is
	// reachable by any authenticated workspace member.
	UpstreamMap map[string]Upstream

	SessionLifetime    time.Duration
	SessionIdleTimeout time.Duration

	// ProxySecret is the shared secret injected as X-Forge-Proxy-Secret
	// on every outbound request. Upstream apps validate this header per
	// the Upstream-App Contract.
	ProxySecret string

	// DefaultLandingURL is where signed-in users are redirected when they
	// hit auth.forgeutah.tech/ without an explicit return_to.
	DefaultLandingURL string

	LogLevel string
}

// Upstream is one entry in UpstreamMap: where to forward, and which roles
// gate the forward.
//
// RequiredRoles is an allowlist intersected with the signed-in user's roles
// before anything is proxied. Empty means ungated — any authenticated
// workspace member reaches the app, which is the pre-gating behaviour and
// the default for an entry that omits the role list.
type Upstream struct {
	Target        *url.URL
	RequiredRoles []string
}

// Gated reports whether this upstream restricts access by role. An ungated
// upstream skips the role check entirely rather than intersecting against an
// empty allowlist (which would deny everyone).
func (u Upstream) Gated() bool { return len(u.RequiredRoles) > 0 }

// Permits reports whether any of the user's roles appears in this upstream's
// allowlist. Ungated upstreams permit everyone.
//
// The allowlist is "any of", not "all of": one matching role is sufficient.
// Comparison is exact — "ai-dev-admin" does not satisfy a requirement for
// "ai-dev".
func (u Upstream) Permits(userRoles []string) bool {
	if !u.Gated() {
		return true
	}
	for _, have := range userRoles {
		if slices.Contains(u.RequiredRoles, have) {
			return true
		}
	}
	return false
}

var slackTeamPattern = regexp.MustCompile(`^T[A-Z0-9]+$`)

// upstreamRoleNameRe mirrors the canonical role-name shape enforced by
// internal/user's roleNameRe. It is duplicated rather than exported because
// the config package must not depend on the user store, and the constraint
// is a two-token regex whose drift would be caught by the round-trip: a role
// name that parses here but not there can never match a stored role.
var upstreamRoleNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Load reads configuration from environment and returns a validated Config.
// Returns an error naming the specific environment variable on failure.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr: getenvDefault("LISTEN_ADDR", ":8080"),
		LogLevel:   getenvDefault("LOG_LEVEL", "info"),
	}

	var errs []string
	require := func(key string, dest *string) {
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			errs = append(errs, fmt.Sprintf("%s is required", key))
			return
		}
		*dest = val
	}

	require("BASE_DOMAIN", &cfg.BaseDomain)
	require("AUTH_HOST", &cfg.AuthHost)
	require("SLACK_CLIENT_ID", &cfg.SlackClientID)
	require("SLACK_CLIENT_SECRET", &cfg.SlackClientSecret)
	require("SLACK_TEAM_ID", &cfg.SlackTeamID)
	require("DB_PATH", &cfg.DBPath)
	require("PROXY_SECRET", &cfg.ProxySecret)

	if cfg.BaseDomain != "" {
		cfg.CookieDomain = "." + strings.TrimPrefix(cfg.BaseDomain, ".")
	}

	if cfg.AuthHost != "" && !strings.HasSuffix(cfg.AuthHost, cfg.BaseDomain) {
		errs = append(errs, fmt.Sprintf("AUTH_HOST %q must be a subdomain of BASE_DOMAIN %q", cfg.AuthHost, cfg.BaseDomain))
	}

	if cfg.SlackTeamID != "" && !slackTeamPattern.MatchString(cfg.SlackTeamID) {
		errs = append(errs, fmt.Sprintf("SLACK_TEAM_ID %q does not match Slack's T-prefix format (e.g. T0R7GR)", cfg.SlackTeamID))
	}

	// Proxy secret minimum entropy guard. Recommended: 32+ bytes random.
	// We accept anything >= 32 chars to allow base64 / hex / passphrase variants.
	if cfg.ProxySecret != "" && len(cfg.ProxySecret) < 32 {
		errs = append(errs, fmt.Sprintf("PROXY_SECRET must be at least 32 characters (got %d); use `openssl rand -hex 32` or similar", len(cfg.ProxySecret)))
	}

	if cfg.DBPath != "" {
		dir := filepath.Dir(cfg.DBPath)
		if info, err := os.Stat(dir); err != nil {
			errs = append(errs, fmt.Sprintf("DB_PATH directory %q: %v", dir, err))
		} else if !info.IsDir() {
			errs = append(errs, fmt.Sprintf("DB_PATH directory %q is not a directory", dir))
		}
	}

	upstreamsRaw := strings.TrimSpace(os.Getenv("UPSTREAMS"))
	if upstreamsRaw == "" {
		errs = append(errs, "UPSTREAMS is required (format: host=url;host=url|role1,role2)")
	} else {
		m, err := parseUpstreams(upstreamsRaw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("UPSTREAMS: %v", err))
		} else {
			cfg.UpstreamMap = m
		}
	}

	cfg.SessionLifetime = getenvDuration("SESSION_LIFETIME", 30*24*time.Hour)
	cfg.SessionIdleTimeout = getenvDuration("SESSION_IDLE_TIMEOUT", 14*24*time.Hour)

	if cfg.SessionIdleTimeout > cfg.SessionLifetime {
		errs = append(errs, fmt.Sprintf("SESSION_IDLE_TIMEOUT (%s) cannot exceed SESSION_LIFETIME (%s)", cfg.SessionIdleTimeout, cfg.SessionLifetime))
	}

	// DefaultLandingURL is where the OAuth callback lands a signed-in
	// caller when their pre-auth return_to is missing or fails validation.
	// Defaults to the auth host root — the asset handler renders the
	// portal view (signed-in status + apps list) for callers without a
	// destination, so this default is safe (no longer a redirect loop).
	// Operators can override to point at a specific upstream.
	if dl := strings.TrimSpace(os.Getenv("DEFAULT_LANDING_URL")); dl != "" {
		if _, err := url.Parse(dl); err != nil {
			errs = append(errs, fmt.Sprintf("DEFAULT_LANDING_URL %q is not a valid URL: %v", dl, err))
		} else {
			cfg.DefaultLandingURL = dl
		}
	} else if cfg.AuthHost != "" {
		cfg.DefaultLandingURL = "https://" + cfg.AuthHost + "/"
	}

	if len(errs) > 0 {
		return nil, errors.New("invalid configuration: " + strings.Join(errs, "; "))
	}
	return cfg, nil
}

// parseUpstreams parses "host=url|role1,role2;host=url" into a map keyed by
// inbound host.
//
// The entry separator is ';' (not ','), so role lists can use ','. The
// target-vs-role-list separator is '|' (not '='), so the host assignment
// `host=url` can use '='. The role list is optional: an entry with no '|' is
// ungated and reachable by any authenticated member, which is what every
// pre-gating entry means.
//
// The separator choice matches the grammar the SSH listener uses for its own
// per-upstream role lists. That listener is not on this branch yet, so the
// symmetry is intentional but not yet compile-enforced; when it lands, the
// two parsers should share one role-name pattern.
//
// The ';' separator is a breaking change from the original ','-separated
// form. See legacyEntryErr for why an un-migrated value cannot be allowed to
// fall through to url.Parse.
func parseUpstreams(raw string) (map[string]Upstream, error) {
	m := make(map[string]Upstream)
	for entry := range strings.SplitSeq(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, rest, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("entry %q is missing '='", entry)
		}
		// Lowercase here, not just at map-build time. Host comparison is
		// case-insensitive (RFC 7230 §5.4) and proxy.NewHostMap lowercases
		// its keys, so two entries differing only in case collapse to one
		// there. Without normalising before the duplicate check below, that
		// collapse is silent and its winner is decided by Go's randomised
		// map iteration order — a gated entry can lose its role list on an
		// unrelated restart.
		host = strings.ToLower(strings.TrimSpace(host))
		rest = strings.TrimSpace(rest)
		if host == "" || rest == "" {
			return nil, fmt.Errorf("entry %q has empty host or url", entry)
		}

		// The role list is optional; its absence means ungated.
		rawURL, rolesRaw, gated := strings.Cut(rest, "|")
		rawURL = strings.TrimSpace(rawURL)
		rolesRaw = strings.TrimSpace(rolesRaw)
		if rawURL == "" {
			return nil, fmt.Errorf("entry %q: empty upstream url", entry)
		}
		if err := legacyEntryErr(entry, rawURL); err != nil {
			return nil, err
		}

		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %v", entry, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("entry %q: scheme must be http or https, got %q", entry, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("entry %q: missing host in upstream url", entry)
		}
		if _, exists := m[host]; exists {
			return nil, fmt.Errorf("entry %q: duplicate inbound host", entry)
		}

		var roles []string
		if gated {
			if rolesRaw == "" {
				return nil, fmt.Errorf("entry %q: empty role list (omit the '|' entirely to leave the app ungated)", entry)
			}
			for r := range strings.SplitSeq(rolesRaw, ",") {
				r = strings.TrimSpace(r)
				if r == "" {
					return nil, fmt.Errorf("entry %q: empty role name", entry)
				}
				if !upstreamRoleNameRe.MatchString(r) {
					return nil, fmt.Errorf("entry %q: invalid role name %q (must match %s)", entry, r, upstreamRoleNameRe.String())
				}
				roles = append(roles, r)
			}
		}

		m[host] = Upstream{Target: u, RequiredRoles: roles}
	}
	if len(m) == 0 {
		return nil, errors.New("no valid entries")
	}
	return m, nil
}

// legacyEntryErr rejects an UPSTREAMS value still written in the original
// ','-separated entry form, naming the migration.
//
// This guard is load-bearing rather than defensive. Splitting the legacy form
// on ';' yields a single entry whose target is the entire remainder — e.g.
// "http://deuce:8080,platform.forgeut.dev=http://platform:8080". url.Parse
// accepts that as scheme "http" with host
// "deuce:8080,platform.forgeut.dev=http:", so it passes both the scheme and
// non-empty-host checks below. Without this guard the proxy boots
// "successfully" with one garbage upstream and every other app silently
// unrouted, which is far worse than refusing to start.
//
// The check is on ',' alone, not also '='. ',' was the legacy entry
// separator, so it is always present in an un-migrated multi-entry value; '='
// only ever shows up as a side effect of the same absorption and adds no
// detection power, while rejecting any upstream URL carrying a query string.
func legacyEntryErr(entry, rawURL string) error {
	if !strings.Contains(rawURL, ",") {
		return nil
	}
	return fmt.Errorf(
		"entry %q looks like the old comma-separated format; entries are now separated by ';' and an optional role list follows '|' "+
			"(old: host=url,host=url — new: host=url;host=url|role1,role2)",
		entry,
	)
}

func getenvDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	// Allow bare seconds as a convenience.
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return fallback
}
