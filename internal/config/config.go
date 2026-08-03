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

	// SSHUpstreams keyed by inbound listener port. Empty when the SSH
	// subsystem is disabled (no SSH_UPSTREAMS env var set). When populated,
	// each entry's port becomes a TCP listener and connections are
	// authenticated then forwarded to the entry's Target. AllowedRoles is
	// intersected with the connecting user's roles for authorization.
	SSHUpstreams map[int]SSHUpstream

	// SSHHostKeyPath is the on-disk path where the proxy's Ed25519 host
	// key is loaded or auto-generated. Required when SSHUpstreams is
	// non-empty.
	SSHHostKeyPath string

	// SSHCAKeyPath is the on-disk path where the proxy's Ed25519 user-CA
	// key is loaded or auto-generated. Required when SSHUpstreams is
	// non-empty.
	SSHCAKeyPath string

	// SSHKnownHostsPath is the path to a hand-curated OpenSSH known_hosts
	// file used to verify outbound proxy→upstream host keys. Required
	// when SSHUpstreams is non-empty.
	SSHKnownHostsPath string

	// SSHListenAddr is the network address each per-port listener binds.
	// Defaults to 0.0.0.0 (bind on all interfaces) — operators can pin to
	// a specific NIC.
	SSHListenAddr string

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

// SSHUpstream is one row in SSHUpstreams: the listening port (carried as the
// map key), the resolved upstream target, and the allowed-roles allowlist.
type SSHUpstream struct {
	Port         int
	Target       *url.URL
	AllowedRoles []string
}

var slackTeamPattern = regexp.MustCompile(`^T[A-Z0-9]+$`)

// roleNameRe is the canonical role-name shape for every role list this
// package parses — both the HTTP UPSTREAMS allowlist and the SSH_UPSTREAMS
// one. It mirrors internal/user's roleNameRe rather than importing it: config
// must not depend on the user store. Sharing one pattern across the two
// parsers is the point — a role name accepted by one listener but not the
// other would be a confusing way to be denied.
var roleNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

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

	sshRaw := strings.TrimSpace(os.Getenv("SSH_UPSTREAMS"))
	if sshRaw != "" {
		m, err := parseSSHUpstreams(sshRaw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("SSH_UPSTREAMS: %v", err))
		} else {
			cfg.SSHUpstreams = m
		}

		// The three key paths and listen addr are only required once the
		// subsystem is enabled. SSH_LISTEN_ADDR defaults to 0.0.0.0.
		cfg.SSHHostKeyPath = strings.TrimSpace(os.Getenv("SSH_HOST_KEY_PATH"))
		cfg.SSHCAKeyPath = strings.TrimSpace(os.Getenv("SSH_CA_KEY_PATH"))
		cfg.SSHKnownHostsPath = strings.TrimSpace(os.Getenv("SSH_KNOWN_HOSTS_PATH"))
		cfg.SSHListenAddr = getenvDefault("SSH_LISTEN_ADDR", "0.0.0.0")

		if cfg.SSHHostKeyPath == "" {
			errs = append(errs, "SSH_HOST_KEY_PATH is required when SSH_UPSTREAMS is set")
		}
		if cfg.SSHCAKeyPath == "" {
			errs = append(errs, "SSH_CA_KEY_PATH is required when SSH_UPSTREAMS is set")
		}
		if cfg.SSHKnownHostsPath == "" {
			errs = append(errs, "SSH_KNOWN_HOSTS_PATH is required when SSH_UPSTREAMS is set")
		}
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
// The separator choice matches parseSSHUpstreams, which applies the same
// grammar to its own per-upstream role lists. Both share roleNameRe, so a
// role name valid for one listener is valid for the other.
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
				if !roleNameRe.MatchString(r) {
					return nil, fmt.Errorf("entry %q: invalid role name %q (must match %s)", entry, r, roleNameRe.String())
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

// maxSSHPortRange caps how many ports one range entry may expand to. Every
// port becomes a bound TCP listener with its own accept-loop goroutine, so
// an unbounded range (say 1-65535) would exhaust file descriptors during
// startup rather than failing with a readable error.
const maxSSHPortRange = 256

// parsePortSpec parses the left side of an SSH_UPSTREAMS entry, which is
// either a single port ("2222") or an inclusive range ("2300-2310").
// Returns the low and high bounds — equal for a single port — and whether
// the range form was used, which determines how the target is interpreted.
func parsePortSpec(entry, portRaw string) (lo, hi int, isRange bool, err error) {
	parsePort := func(raw string) (int, error) {
		p, convErr := strconv.Atoi(strings.TrimSpace(raw))
		if convErr != nil {
			return 0, fmt.Errorf("entry %q: invalid port %q: %v", entry, raw, convErr)
		}
		if p < 1 || p > 65535 {
			return 0, fmt.Errorf("entry %q: port %d out of range (1-65535)", entry, p)
		}
		return p, nil
	}

	loRaw, hiRaw, isRange := strings.Cut(portRaw, "-")
	if !isRange {
		p, err := parsePort(portRaw)
		if err != nil {
			return 0, 0, false, err
		}
		return p, p, false, nil
	}

	if lo, err = parsePort(loRaw); err != nil {
		return 0, 0, true, err
	}
	if hi, err = parsePort(hiRaw); err != nil {
		return 0, 0, true, err
	}
	if hi < lo {
		return 0, 0, true, fmt.Errorf(
			"entry %q: reversed port range %d-%d (low bound must not exceed high bound)",
			entry, lo, hi)
	}
	if width := hi - lo + 1; width > maxSSHPortRange {
		return 0, 0, true, fmt.Errorf(
			"entry %q: port range spans %d ports, exceeding the %d-port limit "+
				"(each port binds its own listener)",
			entry, width, maxSSHPortRange)
	}
	return lo, hi, true, nil
}

// parseSSHUpstreams parses "port=host:port|role1,role2;port=host:port|role"
// into a map keyed by listening port.
//
// The entry separator is ';' (not ','), so role lists can use ','. The
// target-vs-role-list separator is '|' (not '='), so the port assignment
// `port=host:port` can use '='. The grammar is documented in the plan's Key
// Technical Decisions.
func parseSSHUpstreams(raw string) (map[int]SSHUpstream, error) {
	m := make(map[int]SSHUpstream)
	for entry := range strings.SplitSeq(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		portRaw, rest, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("entry %q is missing '='", entry)
		}
		portRaw = strings.TrimSpace(portRaw)
		rest = strings.TrimSpace(rest)
		if portRaw == "" {
			return nil, fmt.Errorf("entry %q has empty port", entry)
		}

		lo, hi, isRange, err := parsePortSpec(entry, portRaw)
		if err != nil {
			return nil, err
		}

		targetRaw, rolesRaw, ok := strings.Cut(rest, "|")
		if !ok {
			return nil, fmt.Errorf("entry %q: role list missing (use 'port=host:port|role1,role2')", entry)
		}
		targetRaw = strings.TrimSpace(targetRaw)
		rolesRaw = strings.TrimSpace(rolesRaw)
		if targetRaw == "" {
			return nil, fmt.Errorf("entry %q: empty target", entry)
		}
		if rolesRaw == "" {
			return nil, fmt.Errorf("entry %q: empty role list", entry)
		}

		// We accept bare "host:port" — the SSH dialer doesn't care about
		// scheme. We still parse via url.URL so port validation lives in
		// one place; the SSH scheme tag stays informational.
		u, err := url.Parse("ssh://" + targetRaw)
		if err != nil {
			return nil, fmt.Errorf("entry %q: parse target: %v", entry, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("entry %q: target missing host:port", entry)
		}
		if isRange {
			// The range form is port-preserving: inbound port N forwards to
			// host:N. An explicit target port would read as if every port in
			// the range funnels to that one port, which is the opposite of
			// what the range is for, so it is rejected rather than resolved
			// to one of the two possible meanings.
			if u.Port() != "" {
				return nil, fmt.Errorf(
					"entry %q: a port range derives the upstream port from the inbound port, "+
						"so the target must be a bare host (use %q, not %q)",
					entry, u.Hostname(), u.Host)
			}
		} else if u.Port() == "" {
			return nil, fmt.Errorf("entry %q: target missing port", entry)
		}

		roles := make([]string, 0)
		for r := range strings.SplitSeq(rolesRaw, ",") {
			r = strings.TrimSpace(r)
			if r == "" {
				return nil, fmt.Errorf("entry %q: empty role name", entry)
			}
			if !roleNameRe.MatchString(r) {
				return nil, fmt.Errorf("entry %q: invalid role name %q (must match %s)", entry, r, roleNameRe.String())
			}
			roles = append(roles, r)
		}
		if len(roles) == 0 {
			return nil, fmt.Errorf("entry %q: empty role list", entry)
		}

		// Expand the range here so nothing downstream needs to know ranges
		// exist: the server binds one listener per map entry either way.
		for port := lo; port <= hi; port++ {
			if _, exists := m[port]; exists {
				return nil, fmt.Errorf("entry %q: duplicate port %d", entry, port)
			}

			target := u
			if isRange {
				// Each entry gets its own *url.URL. Sharing one pointer
				// across the range would let a later mutation through any
				// single entry retarget every port in it.
				perPort, err := url.Parse(fmt.Sprintf("ssh://%s:%d", u.Hostname(), port))
				if err != nil {
					return nil, fmt.Errorf("entry %q: build target for port %d: %v", entry, port, err)
				}
				target = perPort
			}
			m[port] = SSHUpstream{Port: port, Target: target, AllowedRoles: roles}
		}
	}
	if len(m) == 0 {
		return nil, errors.New("no valid entries")
	}
	return m, nil
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
