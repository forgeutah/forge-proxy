package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// --- in-process upstream sshd ------------------------------------------

// testUpstream is a minimal in-process sshd used by the forwarder tests.
// It accepts any client (no authn — the tests dial directly without going
// through the forge bastion's authn). Each session channel runs a
// configurable handler.
type testUpstream struct {
	t        *testing.T
	listener net.Listener
	hostKey  ssh.Signer
	caKey    ssh.Signer

	mu             sync.Mutex
	sessionHandler func(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request)
	directHandler  func(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request, extra []byte)
	observedReqs   []string

	closed chan struct{}
}

func newTestUpstream(t *testing.T) *testUpstream {
	t.Helper()
	hostKey := genHostSigner(t)
	caKey := genHostSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &testUpstream{
		t:        t,
		listener: ln,
		hostKey:  hostKey,
		caKey:    caKey,
		closed:   make(chan struct{}),
	}
	go u.acceptLoop()
	t.Cleanup(func() { _ = ln.Close(); close(u.closed) })
	return u
}

func (u *testUpstream) addr() string { return u.listener.Addr().String() }

func (u *testUpstream) acceptLoop() {
	for {
		conn, err := u.listener.Accept()
		if err != nil {
			return
		}
		go u.handleConn(conn)
	}
}

func (u *testUpstream) handleConn(conn net.Conn) {
	defer conn.Close()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			// Accept any key — the tests use ed25519 cert signers.
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(u.hostKey)
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		u.mu.Lock()
		u.observedReqs = append(u.observedReqs, "channel:"+newCh.ChannelType())
		u.mu.Unlock()
		switch newCh.ChannelType() {
		case "session":
			ch, sreqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			u.mu.Lock()
			h := u.sessionHandler
			u.mu.Unlock()
			if h == nil {
				h = defaultSessionHandler
			}
			go h(u.t, ch, sreqs)
		case "direct-tcpip":
			ch, _, err := newCh.Accept()
			if err != nil {
				continue
			}
			u.mu.Lock()
			h := u.directHandler
			u.mu.Unlock()
			if h == nil {
				_ = ch.Close()
				continue
			}
			go h(u.t, ch, nil, newCh.ExtraData())
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
	_ = serverConn.Close()
}

func (u *testUpstream) setSessionHandler(h func(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request)) {
	u.mu.Lock()
	u.sessionHandler = h
	u.mu.Unlock()
}

func (u *testUpstream) setDirectHandler(h func(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request, extra []byte)) {
	u.mu.Lock()
	u.directHandler = h
	u.mu.Unlock()
}

// observed returns a snapshot of the channel types the upstream has seen.
func (u *testUpstream) observed() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.observedReqs...)
}

// defaultSessionHandler reads exec/shell requests and exits with success.
func defaultSessionHandler(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(true, nil)
		}
		if r.Type == "exec" || r.Type == "shell" {
			_, _ = ch.Write([]byte("hello\n"))
			break
		}
	}
	sendExitStatus(ch, 0)
	_ = ch.Close()
}

// sendExitStatus sends the exit-status request. payload is a uint32 in
// SSH wire format.
func sendExitStatus(ch ssh.Channel, code uint32) {
	payload := []byte{
		byte(code >> 24),
		byte(code >> 16),
		byte(code >> 8),
		byte(code),
	}
	_, _ = ch.SendRequest("exit-status", false, payload)
}

// --- forwarder harness --------------------------------------------------

// startForwarderBastion stands up the forge bastion configured to route
// to the supplied upstream. Returns the listener address clients dial.
func startForwarderBastion(t *testing.T, upstream *testUpstream) (string, *Server) {
	t.Helper()
	return startForwarderBastionOpts(t, upstream, ssh.InsecureIgnoreHostKey())
}

// startForwarderBastionOpts is startForwarderBastion with control over the
// outbound host-key callback, so a test can prove the proxy refuses an
// upstream whose key it does not trust.
func startForwarderBastionOpts(t *testing.T, upstream *testUpstream, hostKeyCB ssh.HostKeyCallback) (string, *Server) {
	t.Helper()

	// Capture server- and forwarder-side events. These were previously
	// discarded, which made every failure here blind: both sides log the
	// reason a connection drops, and none of it reached the test output.
	var serverLog bytes.Buffer
	var serverLogMu sync.Mutex

	hostKey := genHostSigner(t)
	upstreamURL, _ := url.Parse("ssh://" + upstream.addr())
	target := Upstream{Port: 0, Target: upstreamURL, AllowedRoles: []string{"ai-dev"}}

	keys := &stubKeyStore{byFingerprint: map[string]*sshkey.Key{}}
	users := &stubUserStore{users: map[int64]*user.User{}}
	tokens := &stubTokenMinter{}

	// Register the process-global client signer so dialBastion can
	// authenticate. We re-use the same signer across forwarder tests so
	// each test doesn't have to thread one through its harness.
	fp := ssh.FingerprintSHA256(_bastionClientSigner.PublicKey())
	keys.byFingerprint[fp] = &sshkey.Key{ID: 1, UserID: 5, Fingerprint: fp, KeyType: _bastionClientSigner.PublicKey().Type()}
	users.users[5] = &user.User{ID: 5, Email: "alice@example.com", Roles: []string{"ai-dev"}}

	// Build the real forwarder pointed at the upstream with permissive
	// host-key verification (tests only). Drop debug logs to stderr so
	// failures surface useful traces.
	fwdLogger := slog.New(slog.NewTextHandler(
		&lockedWriter{w: &serverLog, mu: &serverLogMu},
		&slog.HandlerOptions{Level: slog.LevelDebug}))
	forwarder := NewForwarder(upstream.caKey, hostKeyCB, fwdLogger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	target.Port = port

	logger := slog.New(slog.NewTextHandler(&lockedWriter{w: &serverLog, mu: &serverLogMu}, nil))
	cfg := Config{
		ListenAddr: "127.0.0.1",
		Upstreams:  map[int]Upstream{port: target},
		HostKey:    hostKey,
		AuthHost:   "auth.test",
	}
	server := New(cfg, keys, users, tokens, forwarder, logger)

	server.mu.Lock()
	server.listeners = append(server.listeners, ln)
	server.mu.Unlock()
	server.wg.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer server.wg.Done()
		server.acceptLoop(ctx, ln, target)
	}()

	t.Cleanup(func() {
		cancel()
		shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = server.Shutdown(shutdownCtx)
	})

	// Registered after the shutdown cleanup above so LIFO runs this first:
	// the dump must capture what happened during the test, not the
	// teardown that cleanup itself causes.
	t.Cleanup(func() {
		if t.Failed() {
			serverLogMu.Lock()
			defer serverLogMu.Unlock()
			t.Logf("server events during test:\n%s", serverLog.String())
		}
	})

	t.Setenv("FORGE_TEST_CLIENT_FP", fp)
	return ln.Addr().String(), server
}

// dialBastion is the client-side helper used by every forwarder test.
func dialBastion(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	clientSigner := dialBastionSigner(t)
	cfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("Dial bastion: %v", err)
	}
	return client
}

// dialBastionSigner generates an Ed25519 signer that matches the
// fingerprint pre-registered by startForwarderBastion. Since the harness
// inserts the *just-generated* signer's fingerprint into the stub store,
// the caller must use the same signer — exposed via the harness instead.
// (For simplicity we re-derive here by reading the env-stored fingerprint
// and ed25519-generating until match — that's pathological. So instead we
// expose a different helper that returns the signer used at setup.)
func dialBastionSigner(_ *testing.T) ssh.Signer {
	// Pulled from a process-global so the test isn't burdened with
	// threading the signer through.
	return _bastionClientSigner
}

var _bastionClientSigner ssh.Signer

func init() {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	_bastionClientSigner = s
}

// To make the registered fingerprint match _bastionClientSigner, override
// startForwarderBastion's local client key with the global. We rewrite
// the helper to use it directly.
func init() {
	// Override happens at test fixture build time — see
	// startForwarderBastion below uses _bastionClientSigner.
}

// --- tests --------------------------------------------------------------

// TestForward_SessionExecRunsEndToEnd is the AE3 happy path: a client
// connects through the bastion, runs `echo hello`, and observes the
// upstream's stdout + exit-status 0.
func TestForward_SessionExecRunsEndToEnd(t *testing.T) {
	upstream := newTestUpstream(t)
	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("echo hello")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("stdout = %q, want %q", got, "hello")
	}
}

// TestForward_NonZeroExitStatusPropagates fences the golang/go#29733
// exit-status ordering race — a non-zero exit must surface as an
// *ssh.ExitError with the matching code, not as a confusing transport
// error.
func TestForward_NonZeroExitStatusPropagates(t *testing.T) {
	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "exec" {
				_, _ = ch.Write([]byte("partial\n"))
				break
			}
		}
		sendExitStatus(ch, 7)
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if _, err := sess.Output("exit 7"); err == nil {
		t.Fatalf("expected exit error")
	} else {
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("err type = %T, want *ssh.ExitError: %v", err, err)
		}
		if exitErr.ExitStatus() != 7 {
			t.Errorf("ExitStatus = %d, want 7", exitErr.ExitStatus())
		}
	}
}

// TestForward_StderrIsPropagated proves the stderr stream is wired —
// missing it would break rsync, scp -v, and other diagnostic-rich tools.
func TestForward_StderrIsPropagated(t *testing.T) {
	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "exec" {
				_, _ = ch.Stderr().Write([]byte("warning: example\n"))
				break
			}
		}
		sendExitStatus(ch, 0)
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	var stderr strings.Builder
	sess.Stderr = &stderr

	if err := sess.Run("anything"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(stderr.String()); got != "warning: example" {
		t.Errorf("stderr = %q, want %q", got, "warning: example")
	}
}

// TestForward_PTYRequestForwardedVerbatim fences the verbatim-passthrough
// promise. The upstream observes the pty-req payload bytes the client
// sent, with no re-serialization (the plan's "never parse channel
// ExtraData or request Payload" invariant).
func TestForward_PTYRequestForwardedVerbatim(t *testing.T) {
	upstream := newTestUpstream(t)
	var seenPayload []byte
	var pmu sync.Mutex
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			pmu.Lock()
			if r.Type == "pty-req" {
				seenPayload = append([]byte(nil), r.Payload...)
			}
			pmu.Unlock()
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "shell" {
				break
			}
		}
		sendExitStatus(ch, 0)
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	_ = sess.Wait()

	pmu.Lock()
	got := seenPayload
	pmu.Unlock()
	if len(got) == 0 {
		t.Fatalf("upstream never observed pty-req")
	}
	// First field of pty-req payload is the term name length-prefix-string;
	// we check the term name is embedded literally.
	if !strings.Contains(string(got), "xterm-256color") {
		t.Errorf("pty-req payload did not contain term name: %q", got)
	}
}

// TestForward_UpstreamDialFailureClosesCleanly covers the error path: an
// unreachable upstream surfaces as a clean close on the inbound side and
// a logged ssh_upstream_dial_failed event.
func TestForward_UpstreamDialFailureClosesCleanly(t *testing.T) {
	// Build a forwarder pointed at a closed port. We don't need a real
	// upstream; just synthesize one whose listener we close immediately.
	upstream := newTestUpstream(t)
	_ = upstream.listener.Close()

	addr, _ := startForwarderBastion(t, upstream)
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(_bastionClientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		// Dial itself may fail if the bastion closes before handshake completes — acceptable.
		return
	}
	defer client.Close()

	// Any session attempt should fail since the upstream is unreachable.
	if _, err := client.NewSession(); err == nil {
		t.Errorf("NewSession succeeded against dead upstream")
	}
}

// TestForward_AgentForwardingDeclined proves the auth-agent-req channel
// request is rejected with a logged warning, while the rest of the
// session continues normally.
func TestForward_AgentForwardingDeclined(t *testing.T) {
	upstream := newTestUpstream(t)
	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	ok, err := sess.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if ok {
		t.Errorf("auth-agent-req reply = true, want false")
	}
}

// TestRolesIntersect_Reaffirmation is intentionally a duplicate of
// server_test.go's coverage — kept here so a future split of forward.go
// into its own subpackage doesn't accidentally lose the symbol.
// (Removed; covered by server_test.go.)

// --- U1 lifecycle regressions -------------------------------------------

// runWithin fails the test if fn does not return within d. Every forwarder
// test depends on proxyChannel actually returning; when it does not, the
// failure mode is a hung package that only the go-test timeout kills, which
// loses the signal about which test wedged. This turns that into a fast,
// named failure.
//
// fn runs on a separate goroutine, so it must report with t.Errorf, never
// t.Fatalf.
func runWithin(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not complete within %s — proxyChannel lifecycle regression: "+
			"closing the channel pair must happen between the stream wait and the "+
			"request/stderr drain (see the two-stage wait in forward.go)", d)
	}
}

// TestForward_SessionCompletesPromptly is the structural fence for the
// deadlock this package shipped with: proxyChannel waited on all six of its
// goroutines before closing the channel pair, but four of those six only
// unblock *on* that close. The result was a permanent hang. A session that
// takes seconds instead of milliseconds means that cycle is back.
func TestForward_SessionCompletesPromptly(t *testing.T) {
	upstream := newTestUpstream(t)
	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	runWithin(t, 5*time.Second, func() {
		sess, err := client.NewSession()
		if err != nil {
			t.Errorf("NewSession: %v", err)
			return
		}
		defer sess.Close()

		out, err := sess.Output("echo hello")
		if err != nil {
			t.Errorf("Output: %v", err)
			return
		}
		if got := strings.TrimSpace(string(out)); got != "hello" {
			t.Errorf("stdout = %q, want %q", got, "hello")
		}
	})
}

// TestForward_UpstreamWithoutExitStatusStillCloses covers the drain stage's
// termination when there is no trailing exit-status to wait for. The client
// legitimately errors (a session closed without exit-status is an error to
// x/crypto/ssh), but it must error *promptly* rather than block until the
// exit-status grace window elapses or, worse, forever.
func TestForward_UpstreamWithoutExitStatusStillCloses(t *testing.T) {
	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "exec" || r.Type == "shell" {
				_, _ = ch.Write([]byte("no-status\n"))
				break
			}
		}
		// Deliberately no sendExitStatus — close straight away.
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	runWithin(t, 5*time.Second, func() {
		sess, err := client.NewSession()
		if err != nil {
			t.Errorf("NewSession: %v", err)
			return
		}
		defer sess.Close()

		// The error is expected; the point is that Output returns at all.
		if _, err := sess.Output("echo no-status"); err == nil {
			t.Log("Output returned without error — acceptable; the assertion here is that it returned")
		}
	})
}

// TestForward_RepeatedSessionsDoNotLeakGoroutines runs several sequential
// sessions and confirms the goroutine population settles. Each session
// spawns six proxy goroutines plus the per-channel tracker; if the close
// ordering regresses so that only some of them exit, the count climbs
// instead of returning to baseline.
func TestForward_RepeatedSessionsDoNotLeakGoroutines(t *testing.T) {
	upstream := newTestUpstream(t)
	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	// One warm-up session so connection-scoped goroutines are already up
	// and don't count as growth.
	runWithin(t, 5*time.Second, func() {
		sess, err := client.NewSession()
		if err != nil {
			t.Errorf("warm-up NewSession: %v", err)
			return
		}
		defer sess.Close()
		if _, err := sess.Output("echo warm"); err != nil {
			t.Errorf("warm-up Output: %v", err)
		}
	})

	base := runtime.NumGoroutine()

	const rounds = 8
	for i := range rounds {
		runWithin(t, 5*time.Second, func() {
			sess, err := client.NewSession()
			if err != nil {
				t.Errorf("round %d NewSession: %v", i, err)
				return
			}
			defer sess.Close()
			if _, err := sess.Output("echo hello"); err != nil {
				t.Errorf("round %d Output: %v", i, err)
			}
		})
	}

	// Teardown is asynchronous — let the population settle before judging.
	const slack = 8
	var final int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		final = runtime.NumGoroutine()
		if final <= base+slack {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("goroutines after %d sessions = %d, baseline %d (slack %d) — "+
		"per-channel goroutines are not being released", rounds, final, base, slack)
}

// --- U2 channel-type and request coverage --------------------------------

// exitSignalMsg is the RFC 4254 exit-signal payload.
type exitSignalMsg struct {
	Signal     string
	CoreDumped bool
	Msg        string
	Lang       string
}

// ptyWindow is the window-change payload (and the tail of pty-req).
type ptyWindow struct {
	Columns uint32
	Rows    uint32
	WidthPx uint32
	HeighPx uint32
}

// TestForward_SFTPSubsystemRoundTrips is the highest-value gap: SFTP is how
// VSCode Remote SSH moves files, and it exercises subsystem requests plus
// sustained bidirectional streaming rather than a one-shot exec. pkg/sftp
// is a test-only dependency -- the bastion itself must never import it.
func TestForward_SFTPSubsystemRoundTrips(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("from upstream\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.Type == "subsystem" && len(r.Payload) > 4 && string(r.Payload[4:]) == "sftp" {
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				srv, err := sftp.NewServer(ch)
				if err != nil {
					_ = ch.Close()
					return
				}
				_ = srv.Serve()
				_ = ch.Close()
				return
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	runWithin(t, 10*time.Second, func() {
		sc, err := sftp.NewClient(client)
		if err != nil {
			t.Errorf("sftp.NewClient through bastion: %v", err)
			return
		}
		defer sc.Close()

		entries, err := sc.ReadDir(dir)
		if err != nil {
			t.Errorf("ReadDir: %v", err)
			return
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if len(names) != 1 || names[0] != "existing.txt" {
			t.Errorf("ReadDir = %v, want [existing.txt]", names)
		}

		// Read the seeded file back through the proxy.
		rf, err := sc.Open(filepath.Join(dir, "existing.txt"))
		if err != nil {
			t.Errorf("Open: %v", err)
			return
		}
		got, err := io.ReadAll(rf)
		_ = rf.Close()
		if err != nil {
			t.Errorf("ReadAll: %v", err)
			return
		}
		if strings.TrimSpace(string(got)) != "from upstream" {
			t.Errorf("file contents = %q, want %q", got, "from upstream")
		}

		// And write a new one -- proves the client->upstream direction.
		wf, err := sc.Create(filepath.Join(dir, "uploaded.txt"))
		if err != nil {
			t.Errorf("Create: %v", err)
			return
		}
		if _, err := wf.Write([]byte("from client\n")); err != nil {
			t.Errorf("Write: %v", err)
		}
		_ = wf.Close()
	})

	// Verify the upload landed on the upstream's real filesystem.
	got, err := os.ReadFile(filepath.Join(dir, "uploaded.txt"))
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if strings.TrimSpace(string(got)) != "from client" {
		t.Errorf("uploaded contents = %q, want %q", got, "from client")
	}
}

// TestForward_ShutdownClosesLiveSession proves the teardown path the session
// registry (U3) and the binary's shutdown ordering (U5) both depend on: a
// session held open is torn down promptly when the server shuts down, rather
// than surviving until the client happens to disconnect.
func TestForward_ShutdownClosesLiveSession(t *testing.T) {
	upstream := newTestUpstream(t)
	// Hold the session open until the channel is torn down under us.
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		}
		_ = ch.Close()
	})

	addr, server := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()

	// The session is live; nothing should have returned yet.
	select {
	case err := <-waitErr:
		t.Fatalf("session ended before shutdown: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case <-waitErr: // any error is fine -- the transport went away
	case <-time.After(3 * time.Second):
		t.Error("session still live 3s after Shutdown returned")
	}
}

// TestForward_WindowChangeForwarded covers the mid-session request path that
// keeps an interactive VSCode/tmux terminal correctly sized.
func TestForward_WindowChangeForwarded(t *testing.T) {
	type observation struct {
		typ string
		win ptyWindow
	}
	seen := make(chan observation, 8)

	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.Type == "window-change" {
				var w ptyWindow
				if err := ssh.Unmarshal(r.Payload, &w); err == nil {
					select {
					case seen <- observation{typ: r.Type, win: w}:
					default:
					}
				}
			}
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		}
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := sess.WindowChange(40, 100); err != nil {
		t.Fatalf("WindowChange: %v", err)
	}

	select {
	case got := <-seen:
		if got.win.Rows != 40 || got.win.Columns != 100 {
			t.Errorf("upstream saw %dx%d (rows x cols), want 40x100", got.win.Rows, got.win.Columns)
		}
	case <-time.After(3 * time.Second):
		t.Error("upstream never observed window-change")
	}
}

// TestForward_DirectTCPIPChannelForwarded covers `ssh -L` local forwarding:
// the direct-tcpip channel must reach the upstream with its open payload
// byte-identical, since that payload carries the target host and port.
func TestForward_DirectTCPIPChannelForwarded(t *testing.T) {
	gotExtra := make(chan []byte, 1)

	upstream := newTestUpstream(t)
	upstream.setDirectHandler(func(_ *testing.T, ch ssh.Channel, _ <-chan *ssh.Request, extra []byte) {
		select {
		case gotExtra <- extra:
		default:
		}
		_, _ = ch.Write([]byte("forwarded\n"))
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	// Build the direct-tcpip payload the way x/crypto does for -L.
	payload := ssh.Marshal(&struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}{"example.internal", 80, "127.0.0.1", 12345})

	ch, reqs, err := client.OpenChannel("direct-tcpip", payload)
	if err != nil {
		t.Fatalf("OpenChannel(direct-tcpip): %v", err)
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	select {
	case extra := <-gotExtra:
		if !bytes.Equal(extra, payload) {
			t.Errorf("upstream ExtraData = %x, want %x", extra, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received the direct-tcpip channel")
	}

	out, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if strings.TrimSpace(string(out)) != "forwarded" {
		t.Errorf("channel payload = %q, want %q", out, "forwarded")
	}
}

// TestForward_UpstreamHostKeyMismatchRefused proves the proxy will not
// forward to an upstream whose host key it cannot verify. Without this the
// outbound leg would be trust-on-first-use against the tailnet.
func TestForward_UpstreamHostKeyMismatchRefused(t *testing.T) {
	upstream := newTestUpstream(t)

	reject := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return errors.New("host key mismatch (test)")
	}
	addr, _ := startForwarderBastionOpts(t, upstream, reject)

	// The bastion accepts the client, then fails on the outbound leg and
	// drops the connection. Either the session or the dial fails; both are
	// correct, and neither may hang.
	runWithin(t, 8*time.Second, func() {
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            "alice",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(dialBastionSigner(t))},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		})
		if err != nil {
			return // refused at connect -- acceptable
		}
		defer client.Close()

		sess, err := client.NewSession()
		if err != nil {
			return // refused when the channel is opened -- acceptable
		}
		defer sess.Close()
		if _, err := sess.Output("echo hello"); err == nil {
			t.Error("session succeeded despite upstream host-key rejection")
		}
	})

	if got := upstream.observed(); len(got) != 0 {
		t.Errorf("upstream saw %v, want no channels -- the proxy should never have connected", got)
	}
}

// TestForward_GlobalTCPIPForwardDeclined covers reverse port forwarding,
// which v1 refuses. The refusal must be an explicit "no" that leaves the
// connection usable, not a dropped request or a broken session.
func TestForward_GlobalTCPIPForwardDeclined(t *testing.T) {
	upstream := newTestUpstream(t)
	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	payload := ssh.Marshal(&struct {
		Addr string
		Port uint32
	}{"0.0.0.0", 8080})

	ok, _, err := client.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		t.Fatalf("SendRequest(tcpip-forward): %v", err)
	}
	if ok {
		t.Error("tcpip-forward was accepted; v1 must decline reverse forwarding")
	}

	// The connection must still work after the refusal.
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession after declined forward: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo hello")
	if err != nil {
		t.Fatalf("Output after declined forward: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("stdout = %q, want %q", out, "hello")
	}
}

// TestForward_SignalAndExitSignalForwarded covers Ctrl-C: the client's
// signal request must reach the upstream, and the upstream's exit-signal
// must come back so the client learns how the command died.
func TestForward_SignalAndExitSignalForwarded(t *testing.T) {
	sawSignal := make(chan string, 1)

	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "signal" {
				var sig struct{ Name string }
				if err := ssh.Unmarshal(r.Payload, &sig); err == nil {
					select {
					case sawSignal <- sig.Name:
					default:
					}
				}
				_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(&exitSignalMsg{
					Signal: "INT",
					Msg:    "interrupted",
				}))
				_ = ch.Close()
				return
			}
		}
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sess.Signal(ssh.SIGINT); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	select {
	case name := <-sawSignal:
		if name != "INT" {
			t.Errorf("upstream saw signal %q, want INT", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never observed the signal request")
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()
	select {
	case err := <-waitErr:
		if err == nil {
			t.Error("Wait returned nil; want a signal-carrying error")
			return
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			if got := exitErr.Waitmsg.Signal(); got != "INT" {
				t.Errorf("Waitmsg.Signal() = %q, want INT", got)
			}
		}
	case <-time.After(3 * time.Second):
		t.Error("Wait never returned after exit-signal")
	}
}

// TestForward_LargeStderrIsNotTruncatedAtClose exercises a large stderr
// payload written immediately before the upstream closes, end to end
// through a real SSH client and server.
//
// This is coverage, not a fence: whether a premature close truncates the
// tail depends on goroutine scheduling, so this passes under the broken
// ordering more often than not. The deterministic guard for that invariant
// is TestProxyChannel_WaitsForUpstreamStderrBeforeClosing, which controls
// the timing instead of racing for it.
func TestForward_LargeStderrIsNotTruncatedAtClose(t *testing.T) {
	const lines = 2000
	var want strings.Builder
	for i := range lines {
		fmt.Fprintf(&want, "diagnostic line %04d: the quick brown fox jumps over the lazy dog\n", i)
	}
	payload := want.String()

	upstream := newTestUpstream(t)
	upstream.setSessionHandler(func(_ *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "exec" {
				_, _ = io.WriteString(ch.Stderr(), payload)
				break
			}
		}
		// Exit and close with no pause: stderr is still in flight.
		sendExitStatus(ch, 0)
		_ = ch.Close()
	})

	addr, _ := startForwarderBastion(t, upstream)
	client := dialBastion(t, addr)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	var stderr strings.Builder
	sess.Stderr = &stderr

	runWithin(t, 10*time.Second, func() {
		if err := sess.Run("noisy-command"); err != nil {
			t.Errorf("Run: %v", err)
		}
	})

	if got := stderr.String(); got != payload {
		t.Errorf("stderr truncated: got %d bytes, want %d "+
			"(the channel pair must not close until the upstream's stderr copy has drained)",
			len(got), len(payload))
	}
}

// lockedWriter serialises writes from the server's goroutines into a
// buffer the test can dump on failure.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// TestForward_FastCommandsGetTheirRequestReply fences a race that only
// showed up on *quick* commands. The client blocks on the reply to its exec
// request; the upstream can finish the command, send exit-status, and close
// the channel in well under a millisecond. If teardown closes the client
// channel while that reply is still in flight, the client's Start fails
// with a bare EOF and the command silently never runs.
//
// One round reproduces it only sometimes, so this runs enough rounds to
// make the window very likely to be hit at least once.
func TestForward_FastCommandsGetTheirRequestReply(t *testing.T) {
	upstream := newTestUpstream(t)
	addr, _ := startForwarderBastion(t, upstream)

	client := dialBastion(t, addr)
	defer client.Close()

	const rounds = 60
	for i := range rounds {
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("round %d: NewSession: %v", i, err)
		}

		// Start and Wait are checked separately: the race kills the exec
		// request specifically, and Output would blur which one failed.
		if err := sess.Start("echo hello"); err != nil {
			_ = sess.Close()
			t.Fatalf("round %d: exec request failed: %v\n"+
				"the reply to an in-flight client request was dropped by teardown", i, err)
		}
		if err := sess.Wait(); err != nil {
			_ = sess.Close()
			t.Fatalf("round %d: Wait: %v", i, err)
		}
		_ = sess.Close()
	}
}
