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

	// UpstreamMap maps inbound Host header to upstream URL.
	// Built from env var UPSTREAMS=host=url,host=url
	UpstreamMap map[string]*url.URL

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

// SSHUpstream is one row in SSHUpstreams: the listening port (carried as the
// map key), the resolved upstream target, and the allowed-roles allowlist.
type SSHUpstream struct {
	Port         int
	Target       *url.URL
	AllowedRoles []string
}

var slackTeamPattern = regexp.MustCompile(`^T[A-Z0-9]+$`)

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
		errs = append(errs, "UPSTREAMS is required (format: host=url,host=url)")
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

// parseUpstreams parses "host1=url1,host2=url2" into a map.
func parseUpstreams(raw string) (map[string]*url.URL, error) {
	m := make(map[string]*url.URL)
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, rawURL, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("entry %q is missing '='", entry)
		}
		host = strings.TrimSpace(host)
		rawURL = strings.TrimSpace(rawURL)
		if host == "" || rawURL == "" {
			return nil, fmt.Errorf("entry %q has empty host or url", entry)
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
		m[host] = u
	}
	if len(m) == 0 {
		return nil, errors.New("no valid entries")
	}
	return m, nil
}

var sshRoleNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

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
			if !sshRoleNameRe.MatchString(r) {
				return nil, fmt.Errorf("entry %q: invalid role name %q (must match %s)", entry, r, sshRoleNameRe.String())
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
