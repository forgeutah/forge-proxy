package sshproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forgeutah/forge-proxy/internal/sshenroll"
	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// extUserID and extFingerprint are the keys stored in
// ssh.Permissions.Extensions to thread the authenticated identity from the
// PublicKeyCallback to the post-handshake handler. Per CVE-2024-45337 the
// post-handshake permissions are the only source of truth for which key
// actually authenticated — the callback may be invoked for keys the client
// never proves possession of.
const (
	extUserID      = "forge_user_id"
	extFingerprint = "forge_fingerprint"
)

// KeyLookup is the minimal contract the server needs from sshkey.Store.
type KeyLookup interface {
	Get(ctx context.Context, fingerprint string) (*sshkey.Key, error)
	TouchLastUsed(ctx context.Context, fingerprint string) error
}

// UserLookup mirrors the same shape sshenroll uses.
type UserLookup interface {
	Get(ctx context.Context, id int64) (*user.User, error)
}

// TokenMinter is the interface the server uses to mint enrollment tokens
// when a connection offers an unknown public key.
type TokenMinter interface {
	Mint(fingerprint, keyType string, publicKey []byte) (string, error)
	EnrollURL(token string) string
}

// Forwarder is the contract U7's forward.go satisfies — receive the
// authenticated client connection + the role-checked upstream details and
// run the channel/request proxy loop. The server constructs this once at
// New and re-invokes it per connection.
type Forwarder interface {
	Handle(ctx context.Context, conn *AuthenticatedConn) error
}

// AuthenticatedConn bundles the post-handshake state the forwarder needs.
// Created by the server after authn + role-check; passed to the Forwarder.
type AuthenticatedConn struct {
	// ServerConn is the inbound SSH server connection.
	ServerConn *ssh.ServerConn
	// Chans is the channel of incoming channel-open requests from the client.
	Chans <-chan ssh.NewChannel
	// Reqs is the global request channel from the client.
	Reqs <-chan *ssh.Request

	// Port is the listener port the client connected to.
	Port int
	// Target is the upstream this listener forwards to.
	Target *Upstream
	// User is the authenticated Forge user.
	User *user.User
	// Fingerprint is the canonical SHA256 fingerprint of the key that
	// authenticated.
	Fingerprint string

	// ClientAddr is the raw client TCP address (for slog/audit).
	ClientAddr string
}

// pendingEnrollKey is the per-handshake record we hold between
// PublicKeyCallback observing an unknown fingerprint and the keyboard-
// interactive callback that emits the URL. We don't decide enrollment from
// inside PublicKeyCallback because we want to let the client try other
// keys first — only when the publickey method is exhausted does the
// server prompt for KBI, and at that point we mint a token for the LAST
// unknown key the client offered.
type pendingEnrollKey struct {
	fingerprint string
	keyType     string
	blob        []byte
	storedAt    time.Time
}

// pendingEnrollTTL bounds how long an unknown-fingerprint record sits in
// the per-conn map before we treat it as garbage. Handshakes that complete
// in under a second is the common case; ten seconds is comfortably above
// the noise floor and well below any human-scale handshake time.
const pendingEnrollTTL = 10 * time.Second

// Server is the SSH bastion's listener subsystem. Holds the long-lived
// configuration and dispatches per-connection goroutines.
type Server struct {
	cfg       Config
	keys      KeyLookup
	users     UserLookup
	tokens    TokenMinter
	forwarder Forwarder
	logger    *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
	conns     map[*ssh.ServerConn]struct{}
	wg        sync.WaitGroup
	closed    bool

	pending sync.Map // map[string]pendingEnrollKey, keyed by ssh.ConnMetadata.SessionID() bytes

	now func() time.Time
}

// New constructs a Server. forwarder may be nil during tests that only
// exercise the auth path (the server will return an error before invoking
// it). logger and now default to package fallbacks.
func New(cfg Config, keys KeyLookup, users UserLookup, tokens TokenMinter, forwarder Forwarder, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:       cfg,
		keys:      keys,
		users:     users,
		tokens:    tokens,
		forwarder: forwarder,
		logger:    logger,
		conns:     make(map[*ssh.ServerConn]struct{}),
		now:       time.Now,
	}
}

// registerConn adds c to the live-connection set. Caller invokes the
// returned function to remove the entry on disconnect.
func (s *Server) registerConn(c *ssh.ServerConn) func() {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}
}

// Run binds one TCP listener per configured upstream and runs the accept
// loop on each. Returns nil when Shutdown has been called and all listeners
// have stopped accepting, or the first hard listener error.
func (s *Server) Run(ctx context.Context) error {
	if len(s.cfg.Upstreams) == 0 {
		return nil
	}
	if s.cfg.HostKey == nil {
		return errors.New("sshproxy: nil HostKey")
	}

	listenAddr := s.cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	for port, up := range s.cfg.Upstreams {
		addr := net.JoinHostPort(listenAddr, strconv.Itoa(port))
		l, err := net.Listen("tcp", addr)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("sshproxy: listen %s: %w", addr, err)
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, l)
		s.mu.Unlock()
		s.logger.Info("ssh_listener_bound", "port", port, "addr", addr, "target", up.Target.Host)

		s.wg.Add(1)
		upstream := up
		go func() {
			defer s.wg.Done()
			s.acceptLoop(ctx, l, upstream)
		}()
	}

	<-ctx.Done()
	return nil
}

// acceptLoop runs the accept loop for one listener. Exits when the listener
// is closed (Shutdown) or ctx is cancelled.
func (s *Server) acceptLoop(ctx context.Context, l net.Listener, up Upstream) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Transient — short backoff, then continue.
				time.Sleep(50 * time.Millisecond)
				continue
			}
			s.logger.Warn("ssh_accept_error", "port", up.Port, "error", err.Error())
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn, up)
		}()
	}
}

// Shutdown closes every listener, then every live server connection, and
// waits for in-flight handlers to finish up to the supplied context's
// deadline. Listeners close first so no new connections enter; then live
// connections close so handler goroutines unblock from ServerConn.Wait.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	listeners := s.listeners
	s.listeners = nil
	conns := make([]*ssh.ServerConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, l := range listeners {
		_ = l.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handleConn runs the SSH handshake + post-authn dispatch for one
// accepted connection.
func (s *Server) handleConn(ctx context.Context, raw net.Conn, up Upstream) {
	defer raw.Close()

	cfg := s.serverConfig()
	serverConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		s.logger.Info("ssh_handshake_failed",
			"port", up.Port,
			"remote_addr", raw.RemoteAddr().String(),
			"error", err.Error())
		return
	}
	defer serverConn.Close()
	// Clear any pending enrollment record so the per-conn map doesn't
	// linger after the handshake resolves.
	s.pending.Delete(string(serverConn.SessionID()))
	unregister := s.registerConn(serverConn)
	defer unregister()

	if serverConn.Permissions == nil || serverConn.Permissions.Extensions == nil {
		// PublicKeyCallback never populated Permissions — shouldn't happen
		// once authn succeeds, but defence-in-depth against future API
		// changes.
		s.logger.Warn("ssh_missing_permissions", "port", up.Port)
		return
	}
	userIDRaw := serverConn.Permissions.Extensions[extUserID]
	fingerprint := serverConn.Permissions.Extensions[extFingerprint]
	if userIDRaw == "" || fingerprint == "" {
		s.logger.Warn("ssh_missing_identity_extensions", "port", up.Port)
		return
	}
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		s.logger.Warn("ssh_bad_user_id_extension", "port", up.Port, "raw", userIDRaw)
		return
	}

	u, err := s.users.Get(ctx, userID)
	if err != nil {
		s.logger.Error("ssh_user_lookup_failed",
			"port", up.Port, "user_id", userID, "error", err.Error())
		return
	}

	if !rolesIntersect(u.Roles, up.AllowedRoles) {
		s.logger.Warn("ssh_role_denied",
			"port", up.Port,
			"user_id", u.ID,
			"email", u.Email,
			"fingerprint", fingerprint,
			"user_roles", u.Roles,
			"allowed_roles", up.AllowedRoles)
		return
	}

	// Stamp last_used_at; never fatal on failure.
	if err := s.keys.TouchLastUsed(ctx, fingerprint); err != nil {
		s.logger.Warn("ssh_touch_last_used_failed",
			"port", up.Port, "fingerprint", fingerprint, "error", err.Error())
	}

	s.logger.Info("ssh_auth_success",
		"port", up.Port,
		"user_id", u.ID,
		"email", u.Email,
		"fingerprint", fingerprint,
		"remote_addr", raw.RemoteAddr().String())

	if s.forwarder == nil {
		// No forwarder configured (test scaffolding) — close.
		return
	}

	authConn := &AuthenticatedConn{
		ServerConn:  serverConn,
		Chans:       chans,
		Reqs:        reqs,
		Port:        up.Port,
		Target:      &up,
		User:        u,
		Fingerprint: fingerprint,
		ClientAddr:  raw.RemoteAddr().String(),
	}
	if err := s.forwarder.Handle(ctx, authConn); err != nil {
		s.logger.Warn("ssh_forward_error",
			"port", up.Port, "user_id", u.ID, "error", err.Error())
	}
	s.logger.Info("ssh_session_closed",
		"port", up.Port, "user_id", u.ID, "email", u.Email)
}

// serverConfig builds the ssh.ServerConfig for the listener with the
// hardened KEX/cipher/MAC allowlists from the plan.
func (s *Server) serverConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback:           s.publicKeyCallback,
		KeyboardInteractiveCallback: s.keyboardInteractiveCallback,
		PublicKeyAuthAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
		},
		BannerCallback: func(ssh.ConnMetadata) string {
			return "forge-proxy SSH bastion — auth required\n"
		},
		ServerVersion: "SSH-2.0-forge-proxy",
	}
	cfg.Config = ssh.Config{
		KeyExchanges: []string{
			"sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
		},
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
		},
		MACs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
		},
	}
	cfg.AddHostKey(s.cfg.HostKey)
	return cfg
}

// publicKeyCallback runs on every offered key. On a known fingerprint we
// stash the identity in Permissions.Extensions and return success.
//
// On an unknown fingerprint we DO NOT advance to KBI immediately —
// instead we record the offered key against the connection's SessionID
// and return a plain authn-failed error. That gives the client a chance
// to try additional keys (the multi-key fingering case). When the client
// exhausts publickey and falls through to keyboard-interactive,
// keyboardInteractiveCallback below reads the recorded key and mints an
// enrollment token for it.
//
// CRITICAL: authorization is read from Permissions.Extensions AFTER
// ssh.NewServerConn returns — see handleConn. This callback may be invoked
// for keys the client cannot prove possession of (CVE-2024-45337).
func (s *Server) publicKeyCallback(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp := ssh.FingerprintSHA256(key)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rec, err := s.keys.Get(ctx, fp)
	if err == nil {
		// Defence in depth: constant-time compare the lookup result's
		// fingerprint against the offered one before trusting the
		// Permissions. Same shape as the session-id compare in auth.
		if subtle.ConstantTimeCompare([]byte(rec.Fingerprint), []byte(fp)) != 1 {
			s.logger.Warn("ssh_fingerprint_mismatch_after_lookup",
				"got", rec.Fingerprint, "want", fp)
			return nil, errors.New("authn fingerprint mismatch")
		}
		// Clear any pending enrollment now that auth succeeded.
		s.pending.Delete(string(meta.SessionID()))
		return &ssh.Permissions{
			Extensions: map[string]string{
				extUserID:      strconv.FormatInt(rec.UserID, 10),
				extFingerprint: fp,
			},
		}, nil
	}
	if !errors.Is(err, sshkey.ErrNotFound) {
		s.logger.Error("ssh_key_lookup_failed",
			"fingerprint", fp, "error", err.Error())
		return nil, fmt.Errorf("sshproxy: key lookup: %w", err)
	}

	// Unknown fingerprint: remember it against this handshake so KBI can
	// mint a token for the *last* unknown key the client offered. Returning
	// a regular error lets the client try its next configured identity.
	s.pending.Store(string(meta.SessionID()), pendingEnrollKey{
		fingerprint: fp,
		keyType:     key.Type(),
		blob:        append([]byte(nil), key.Marshal()...),
		storedAt:    s.now(),
	})
	return nil, errors.New("publickey: unknown fingerprint")
}

// keyboardInteractiveCallback is reached after the client exhausts
// publickey (every offered key was unknown). It reads the pending-enroll
// record left by publicKeyCallback, mints an enrollment token for the
// LAST offered key, emits the URL in the instruction field, and returns
// an error so the connection terminates cleanly.
func (s *Server) keyboardInteractiveCallback(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	s.sweepPendingLocked()

	raw, ok := s.pending.LoadAndDelete(string(meta.SessionID()))
	if !ok {
		// Client offered keyboard-interactive without first trying
		// publickey. We don't support that — every legitimate auth
		// flow starts with publickey.
		return nil, errors.New("publickey authentication required — offer a key first")
	}
	pending := raw.(pendingEnrollKey)

	token, err := s.tokens.Mint(pending.fingerprint, pending.keyType, pending.blob)
	if err != nil {
		s.logger.Error("ssh_enroll_mint_failed",
			"fingerprint", pending.fingerprint, "error", err.Error())
		return nil, fmt.Errorf("sshproxy: mint token: %w", err)
	}

	url := s.tokens.EnrollURL(token)
	instruction := "Unknown SSH key " + pending.fingerprint + ".\nEnroll: " + url + "\nThen retry your SSH command.\n"

	s.logger.Info("ssh_enroll_url_issued",
		"fingerprint", pending.fingerprint,
		"key_type", pending.keyType)

	// Zero-question KBI: instruction only. The client renders the
	// instruction and we return an error to terminate cleanly. The
	// answer slice (if any) is ignored.
	_, _ = challenge("", instruction, nil, nil)
	return nil, errors.New("enrollment required — visit the URL above and retry SSH")
}

// sweepPendingLocked purges pending-enroll records older than the TTL.
// Called on each keyboardInteractiveCallback to bound the per-process map
// growth from clients that connect, offer one unknown key, and abandon
// the handshake before reaching KBI.
func (s *Server) sweepPendingLocked() {
	now := s.now()
	s.pending.Range(func(k, v any) bool {
		if entry, ok := v.(pendingEnrollKey); ok {
			if now.Sub(entry.storedAt) > pendingEnrollTTL {
				s.pending.Delete(k)
			}
		}
		return true
	})
}

// rolesIntersect reports whether userRoles and allowedRoles share at least
// one element. Comparison is case-sensitive (roles are stored verbatim);
// the user-side regex constrains the alphabet so case is well-defined.
func rolesIntersect(userRoles, allowedRoles []string) bool {
	if len(userRoles) == 0 || len(allowedRoles) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(allowedRoles))
	for _, r := range allowedRoles {
		set[r] = struct{}{}
	}
	for _, r := range userRoles {
		if _, ok := set[r]; ok {
			return true
		}
	}
	return false
}

var _ TokenMinter = (*sshenroll.Handlers)(nil)
