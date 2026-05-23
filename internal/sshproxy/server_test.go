package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// --- Fixtures -----------------------------------------------------------

// genHostSigner returns a fresh Ed25519 signer for use as the server's host
// key.
func genHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return s
}

// genClientSigner returns a fresh Ed25519 signer for use as a client's
// publickey.
func genClientSigner(t *testing.T) ssh.Signer {
	return genHostSigner(t)
}

// --- Stub stores --------------------------------------------------------

type stubKeyStore struct {
	byFingerprint map[string]*sshkey.Key
	getErr        error
	touched       []string
}

func (s *stubKeyStore) Get(_ context.Context, fp string) (*sshkey.Key, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	k, ok := s.byFingerprint[fp]
	if !ok {
		return nil, sshkey.ErrNotFound
	}
	return k, nil
}

func (s *stubKeyStore) TouchLastUsed(_ context.Context, fp string) error {
	s.touched = append(s.touched, fp)
	return nil
}

type stubUserStore struct {
	users map[int64]*user.User
}

func (s *stubUserStore) Get(_ context.Context, id int64) (*user.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

type stubTokenMinter struct {
	mu       sync.Mutex
	tokens   []string
	urls     []string
	mintArgs []struct {
		Fingerprint string
		KeyType     string
		KeyBlob     []byte
	}
}

func (s *stubTokenMinter) Mint(fp, kt string, blob []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := "tok-" + fp
	s.tokens = append(s.tokens, tok)
	s.mintArgs = append(s.mintArgs, struct {
		Fingerprint string
		KeyType     string
		KeyBlob     []byte
	}{fp, kt, append([]byte(nil), blob...)})
	return tok, nil
}

func (s *stubTokenMinter) EnrollURL(tok string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := "https://auth.test/ssh/enroll/" + tok
	s.urls = append(s.urls, u)
	return u
}

func (s *stubTokenMinter) lastMint() (string, string, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.mintArgs) == 0 {
		return "", "", nil
	}
	a := s.mintArgs[len(s.mintArgs)-1]
	return a.Fingerprint, a.KeyType, a.KeyBlob
}

// stubForwarder records every authenticated connection it sees and closes
// them without doing any actual forwarding.
type stubForwarder struct {
	mu     sync.Mutex
	calls  []*AuthenticatedConn
	closer func(*AuthenticatedConn)
}

func (f *stubForwarder) Handle(_ context.Context, conn *AuthenticatedConn) error {
	f.mu.Lock()
	f.calls = append(f.calls, conn)
	f.mu.Unlock()
	if f.closer != nil {
		f.closer(conn)
	}
	// Drain channels so the inbound conn closes cleanly.
	go func() {
		for nc := range conn.Chans {
			_ = nc.Reject(ssh.Prohibited, "test forwarder rejecting")
		}
	}()
	go func() {
		for r := range conn.Reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	_ = conn.ServerConn.Wait()
	return nil
}

func (f *stubForwarder) snapshot() []*AuthenticatedConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*AuthenticatedConn, len(f.calls))
	copy(out, f.calls)
	return out
}

// syncBuf is a goroutine-safe bytes.Buffer used to capture slog output
// from the server's background goroutines. The race detector flags any
// unguarded shared bytes.Buffer; this wrapper serializes Write and String.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// --- Server harness -----------------------------------------------------

type harness struct {
	server   *Server
	keys     *stubKeyStore
	users    *stubUserStore
	tokens   *stubTokenMinter
	forward  *stubForwarder
	listener net.Listener
	port     int
	upstream Upstream
	logBuf   *syncBuf
	cancel   context.CancelFunc
}

func startHarness(t *testing.T, opts ...func(*harness)) *harness {
	t.Helper()

	h := &harness{
		keys:    &stubKeyStore{byFingerprint: map[string]*sshkey.Key{}},
		users:   &stubUserStore{users: map[int64]*user.User{}},
		tokens:  &stubTokenMinter{},
		forward: &stubForwarder{},
		logBuf:  &syncBuf{},
	}

	hostKey := genHostSigner(t)
	upstreamURL, _ := url.Parse("ssh://upstream.test:22")
	h.upstream = Upstream{
		Port:         0, // assigned below
		Target:       upstreamURL,
		AllowedRoles: []string{"ai-dev"},
	}

	// Bind a localhost listener on an ephemeral port and substitute it
	// for what Run would have created — that lets the test target a
	// known port without racing with OS port assignment.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h.listener = ln
	h.port = ln.Addr().(*net.TCPAddr).Port
	h.upstream.Port = h.port

	for _, opt := range opts {
		opt(h)
	}

	logger := slog.New(slog.NewJSONHandler(h.logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := Config{
		ListenAddr: "127.0.0.1",
		Upstreams:  map[int]Upstream{h.port: h.upstream},
		HostKey:    hostKey,
		AuthHost:   "auth.test",
	}
	h.server = New(cfg, h.keys, h.users, h.tokens, h.forward, logger)

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	// Run accept loop directly on our pre-bound listener so we control
	// the port and lifecycle.
	h.server.mu.Lock()
	h.server.listeners = append(h.server.listeners, ln)
	h.server.mu.Unlock()
	h.server.wg.Add(1)
	go func() {
		defer h.server.wg.Done()
		h.server.acceptLoop(ctx, ln, h.upstream)
	}()

	t.Cleanup(func() {
		cancel()
		shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = h.server.Shutdown(shutdownCtx)
	})

	return h
}

// dialClient opens a connection through h's listener using the given
// authmethods.
func dialClient(t *testing.T, h *harness, user string, methods []ssh.AuthMethod, kbi ssh.KeyboardInteractiveChallenge) (*ssh.Client, error) {
	t.Helper()
	if kbi != nil {
		methods = append(methods, ssh.KeyboardInteractive(kbi))
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test only
		Timeout:         3 * time.Second,
	}
	return ssh.Dial("tcp", h.listener.Addr().String(), cfg)
}

// --- Tests --------------------------------------------------------------

// TestServer_KnownKey_AuthenticatesAndForwarderInvoked proves the happy
// path: a pre-registered key authenticates and the forwarder receives the
// AuthenticatedConn with the expected fields.
func TestServer_KnownKey_AuthenticatesAndForwarderInvoked(t *testing.T) {
	h := startHarness(t)

	clientSigner := genClientSigner(t)
	fp := ssh.FingerprintSHA256(clientSigner.PublicKey())
	h.keys.byFingerprint[fp] = &sshkey.Key{
		ID:          1,
		UserID:      42,
		Fingerprint: fp,
		KeyType:     clientSigner.PublicKey().Type(),
	}
	h.users.users[42] = &user.User{ID: 42, Email: "alice@example.com", Roles: []string{"ai-dev"}}

	client, err := dialClient(t, h, "alice", []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = client.Close()

	// Allow handleConn to finish recording the call.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(h.forward.snapshot()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	calls := h.forward.snapshot()
	if len(calls) != 1 {
		t.Fatalf("forwarder calls = %d, want 1", len(calls))
	}
	conn := calls[0]
	if conn.User == nil || conn.User.ID != 42 {
		t.Errorf("forwarder User = %+v, want id 42", conn.User)
	}
	if conn.Fingerprint != fp {
		t.Errorf("forwarder Fingerprint = %q, want %q", conn.Fingerprint, fp)
	}
	if conn.Port != h.port {
		t.Errorf("forwarder Port = %d, want %d", conn.Port, h.port)
	}
	// last_used_at touched.
	if len(h.keys.touched) != 1 || h.keys.touched[0] != fp {
		t.Errorf("TouchLastUsed = %v, want [%q]", h.keys.touched, fp)
	}
}

// TestServer_UnknownKey_TriggersEnrollmentChallenge fences the TOFU flow:
// an unregistered key receives a KBI challenge whose Instruction contains
// the enrollment URL, and the token store has a fresh entry.
func TestServer_UnknownKey_TriggersEnrollmentChallenge(t *testing.T) {
	h := startHarness(t)

	clientSigner := genClientSigner(t)
	fp := ssh.FingerprintSHA256(clientSigner.PublicKey())

	var (
		instructionSeen string
		challengeMu     sync.Mutex
	)
	kbi := func(_, instruction string, _ []string, _ []bool) ([]string, error) {
		challengeMu.Lock()
		instructionSeen = instruction
		challengeMu.Unlock()
		return nil, nil
	}

	_, err := dialClient(t, h, "alice", []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, kbi)
	if err == nil {
		t.Fatalf("expected dial error after enrollment-only challenge")
	}

	challengeMu.Lock()
	got := instructionSeen
	challengeMu.Unlock()

	if !strings.Contains(got, "Enroll") || !strings.Contains(got, "https://auth.test/ssh/enroll/") {
		t.Errorf("instruction = %q, want enrollment URL", got)
	}
	if !strings.Contains(got, fp) {
		t.Errorf("instruction = %q, want fingerprint", got)
	}

	mintedFP, mintedType, mintedBlob := h.tokens.lastMint()
	if mintedFP != fp {
		t.Errorf("token minted for fp %q, want %q", mintedFP, fp)
	}
	if mintedType != clientSigner.PublicKey().Type() {
		t.Errorf("token minted keyType = %q", mintedType)
	}
	if !bytes.Equal(mintedBlob, clientSigner.PublicKey().Marshal()) {
		t.Errorf("token minted blob mismatch")
	}

	// Forwarder must NOT have been invoked — enrollment denies authn.
	if calls := h.forward.snapshot(); len(calls) != 0 {
		t.Errorf("forwarder calls = %d after enrollment-only, want 0", len(calls))
	}
}

// TestServer_FirstKeyUnknown_SecondKeyKnown_AuthenticatesAsSecond is the
// CVE-2024-45337 regression fence. A client offering two keys (one unknown,
// one registered) must authenticate as the *second* key — the one it
// actually proved possession of — and the forwarder must see the second
// fingerprint, not the first.
func TestServer_FirstKeyUnknown_SecondKeyKnown_AuthenticatesAsSecond(t *testing.T) {
	h := startHarness(t)

	unknown := genClientSigner(t)
	known := genClientSigner(t)
	knownFP := ssh.FingerprintSHA256(known.PublicKey())

	h.keys.byFingerprint[knownFP] = &sshkey.Key{
		ID: 1, UserID: 7, Fingerprint: knownFP, KeyType: known.PublicKey().Type(),
	}
	h.users.users[7] = &user.User{ID: 7, Email: "bob@example.com", Roles: []string{"ai-dev"}}

	client, err := dialClient(t, h, "bob", []ssh.AuthMethod{ssh.PublicKeys(unknown, known)}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = client.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(h.forward.snapshot()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	calls := h.forward.snapshot()
	if len(calls) != 1 {
		t.Fatalf("forwarder calls = %d, want 1", len(calls))
	}
	if got := calls[0].Fingerprint; got != knownFP {
		t.Errorf("forwarder Fingerprint = %q, want %q (CVE-2024-45337 fence)", got, knownFP)
	}
}

// TestServer_KnownKeyButRoleDenied_ClosesWithoutForwarding fences the
// authorization step: even though the user authenticates, an empty role
// intersection must close the connection without invoking the forwarder.
func TestServer_KnownKeyButRoleDenied_ClosesWithoutForwarding(t *testing.T) {
	h := startHarness(t)

	clientSigner := genClientSigner(t)
	fp := ssh.FingerprintSHA256(clientSigner.PublicKey())
	h.keys.byFingerprint[fp] = &sshkey.Key{
		ID: 1, UserID: 9, Fingerprint: fp, KeyType: clientSigner.PublicKey().Type(),
	}
	// User exists but has roles disjoint from the listener's allowlist.
	h.users.users[9] = &user.User{ID: 9, Email: "intern@example.com", Roles: []string{"unrelated"}}

	client, err := dialClient(t, h, "intern", []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// The handshake succeeds (authn passed); the post-handshake role check
	// closes the inbound conn. A subsequent NewSession must fail.
	_, err = client.NewSession()
	if err == nil {
		t.Errorf("NewSession succeeded after role denial")
	}
	_ = client.Close()

	time.Sleep(100 * time.Millisecond)
	if calls := h.forward.snapshot(); len(calls) != 0 {
		t.Errorf("forwarder calls = %d, want 0 after role denial", len(calls))
	}
	logs := h.logBuf.String()
	if !strings.Contains(logs, "ssh_role_denied") {
		t.Errorf("role denial not logged:\n%s", logs)
	}
}

// TestServer_DBLookupFailureRejectsAuth proves the error path: when the
// key store returns a non-ErrNotFound error, the auth callback rejects and
// the forwarder is not invoked.
func TestServer_DBLookupFailureRejectsAuth(t *testing.T) {
	h := startHarness(t, func(h *harness) {
		h.keys.getErr = errors.New("simulated DB outage")
	})

	clientSigner := genClientSigner(t)
	_, err := dialClient(t, h, "alice", []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, nil)
	if err == nil {
		t.Fatalf("expected dial error on DB failure")
	}
	if calls := h.forward.snapshot(); len(calls) != 0 {
		t.Errorf("forwarder calls = %d, want 0 after DB outage", len(calls))
	}
	if !strings.Contains(h.logBuf.String(), "ssh_key_lookup_failed") {
		t.Errorf("lookup failure not logged: %s", h.logBuf.String())
	}
}

// TestServer_Shutdown_ClosesListenerAndReturnsWithinDeadline covers the
// orderly-shutdown contract used by main.go's signal handler.
func TestServer_Shutdown_ClosesListenerAndReturnsWithinDeadline(t *testing.T) {
	h := startHarness(t)

	// Open a connection so there's a goroutine in flight.
	signer := genClientSigner(t)
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	h.keys.byFingerprint[fp] = &sshkey.Key{ID: 1, UserID: 5, Fingerprint: fp, KeyType: signer.PublicKey().Type()}
	h.users.users[5] = &user.User{ID: 5, Email: "ops@example.com", Roles: []string{"ai-dev"}}

	client, err := dialClient(t, h, "ops", []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := h.server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Shutdown took %s, want <3s", elapsed)
	}

	// Listener must be closed: any new connection attempts fail.
	_, err = net.DialTimeout("tcp", h.listener.Addr().String(), 200*time.Millisecond)
	if err == nil {
		t.Errorf("listener still accepting after Shutdown")
	}
	_ = io.Discard // keep imports tidy
}

// TestRolesIntersect_TableDriven covers the pure helper.
func TestRolesIntersect_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		user    []string
		allowed []string
		want    bool
	}{
		{"both empty", nil, nil, false},
		{"user empty", nil, []string{"a"}, false},
		{"allowed empty", []string{"a"}, nil, false},
		{"overlap", []string{"a", "b"}, []string{"b", "c"}, true},
		{"disjoint", []string{"a"}, []string{"b"}, false},
		{"case-sensitive", []string{"Admin"}, []string{"admin"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rolesIntersect(tc.user, tc.allowed); got != tc.want {
				t.Errorf("rolesIntersect = %v, want %v", got, tc.want)
			}
		})
	}
}
