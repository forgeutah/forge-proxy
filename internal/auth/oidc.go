package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/forgeutah/forge-proxy/internal/config"
)

// Slack's published OIDC endpoints. We hard-code these rather than fetching
// the OpenID discovery document because (a) the URLs have been stable for
// years and Slack's docs treat them as the contract, and (b) requiring a
// successful discovery fetch at startup would couple the binary's
// liveness to Slack's reachability for no real benefit.
const (
	slackIssuer        = "https://slack.com"
	slackAuthorizeURL  = "https://slack.com/openid/connect/authorize"
	slackTokenURL      = "https://slack.com/api/openid.connect.token"
	slackJWKSURL       = "https://slack.com/openid/connect/keys"
	slackTeamClaim     = "https://slack.com/team_id"
	slackUserClaim     = "https://slack.com/user_id"
	idTokenExtraField  = "id_token"
	oidcScopeOpenID    = "openid"
	oidcScopeProfile   = "profile"
	oidcScopeEmail     = "email"
	jwksRetryInitial   = 1 * time.Second
	jwksRetryCap       = 60 * time.Second
)

// OIDC bundles together everything U6 needs to drive a Slack sign-in: the
// oauth2 client for the authorize/exchange round-trip, an atomically
// swappable ID-token verifier, and a "ready" signal for /readyz.
//
// The verifier is stored behind an atomic.Pointer because building it
// requires a live HTTP fetch against Slack's JWKS endpoint
// (oidc.NewRemoteKeySet pings the URL eagerly). We want the binary to come
// up even when Slack is unreachable — existing sessions should keep working
// during a Slack incident — so JWKS construction runs asynchronously in a
// goroutine and the handler-side code checks Verifier() == nil and returns
// auth_failed if the verifier hasn't arrived yet.
type OIDC struct {
	OAuth       *oauth2.Config
	verifier    atomic.Pointer[oidc.IDTokenVerifier]
	keysetReady chan struct{}
	clientID    string
	jwksURL     string
}

// New constructs an *OIDC for production wiring using Slack's hard-coded
// endpoint URLs. The returned value is usable immediately; the JWKS fetch
// happens asynchronously in a goroutine that retries with exponential
// backoff and never gives up.
func New(ctx context.Context, cfg *config.Config) *OIDC {
	endpoint := oauth2.Endpoint{
		AuthURL:  slackAuthorizeURL,
		TokenURL: slackTokenURL,
	}
	return NewWithEndpoints(ctx, cfg, endpoint, slackJWKSURL, slackIssuer)
}

// NewWithEndpoints is the test-and-prod constructor. The production caller
// passes Slack's URLs; tests pass an httptest stub server's URLs so the
// whole OAuth flow can run hermetically. Issuer is also injected because
// the verifier matches it character-for-character (the stub server has its
// own issuer string).
func NewWithEndpoints(ctx context.Context, cfg *config.Config, endpoint oauth2.Endpoint, jwksURL, issuer string) *OIDC {
	o := &OIDC{
		OAuth: &oauth2.Config{
			ClientID:     cfg.SlackClientID,
			ClientSecret: cfg.SlackClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  "https://" + cfg.AuthHost + "/auth/callback",
			Scopes:       []string{oidcScopeOpenID, oidcScopeProfile, oidcScopeEmail},
		},
		keysetReady: make(chan struct{}),
		clientID:    cfg.SlackClientID,
		jwksURL:     jwksURL,
	}
	// Build the verifier in the background; the JWKS endpoint may be
	// unreachable at boot and we don't want startup to fail.
	go o.initVerifier(ctx, issuer)
	return o
}

// initVerifier constructs a remote keyset against the JWKS URL and builds
// the ID-token verifier, retrying with exponential backoff until it
// succeeds. The verifier is published via atomic.Pointer once it's ready,
// and keysetReady is closed exactly once on first success.
//
// We intentionally never give up: a binary that starts during a Slack
// outage should self-heal when Slack comes back, without an operator
// restart.
func (o *OIDC) initVerifier(ctx context.Context, issuer string) {
	delay := jwksRetryInitial
	for {
		if ctx.Err() != nil {
			// The outer context (typically rooted at the OS signal handler)
			// is cancelled — abandon the retry loop so we don't leak this
			// goroutine through shutdown.
			return
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		keySet := oidc.NewRemoteKeySet(fetchCtx, o.jwksURL)
		verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
			ClientID:             o.clientID,
			SupportedSigningAlgs: []string{"RS256"},
		})
		// NewRemoteKeySet is lazy — it doesn't actually hit the network
		// until the first verification or until we force a fetch. We don't
		// have a token to verify here, so instead we wait for a token in
		// the request path. To make /readyz meaningful, do a synchronous
		// JWKS fetch by calling the keyset directly. The go-oidc library
		// exposes that through the unexported syncKeys; instead we just
		// publish the verifier and treat the first successful Verify call
		// as the ready signal. That's the operational reality anyway —
		// "ready" means "the next sign-in won't fail because of JWKS."
		//
		// To get a clean readiness signal we do one HTTP GET on the JWKS
		// URL via the same context. This proves the URL resolves and Slack
		// is serving keys, which is what /readyz callers want to know.
		err := pingJWKS(fetchCtx, o.jwksURL)
		cancel()
		if err == nil {
			o.verifier.Store(verifier)
			// Close keysetReady exactly once. Subsequent successful
			// initialisations (we never re-enter after the first close,
			// but defence-in-depth) would panic on a double-close.
			select {
			case <-o.keysetReady:
				// Already closed — shouldn't happen, but be safe.
			default:
				close(o.keysetReady)
			}
			slog.Info("auth: OIDC verifier ready", "issuer", issuer)
			return
		}

		slog.Warn("auth: OIDC verifier construction failed; retrying",
			"retry_in", delay.String(),
			"error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > jwksRetryCap {
			delay = jwksRetryCap
		}
	}
}

// pingJWKS does a single HTTP GET against the JWKS URL with the supplied
// context. A 200 response is treated as "Slack is serving keys"; anything
// else triggers a retry. We don't parse the response body — go-oidc's
// remote keyset will fetch and parse it on the next Verify call.
func pingJWKS(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks ping: status %d", resp.StatusCode)
	}
	return nil
}

// Verifier returns the current verifier, or nil if the JWKS goroutine has
// not yet succeeded. Handler-side callers MUST check for nil and treat that
// case as "not ready" — see /auth/callback for the response shape.
func (o *OIDC) Verifier() *oidc.IDTokenVerifier {
	return o.verifier.Load()
}

// Ready returns a channel that is closed once the JWKS fetch has succeeded
// at least once. /readyz waits on this with a non-blocking select to report
// OIDC readiness without coupling liveness to it.
func (o *OIDC) Ready() <-chan struct{} { return o.keysetReady }

// IsReady reports whether the verifier is currently usable. Handler code
// uses this in preference to comparing Verifier() to nil so the intent is
// readable at call sites.
func (o *OIDC) IsReady() bool { return o.verifier.Load() != nil }
