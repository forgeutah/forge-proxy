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

	LogLevel string
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
