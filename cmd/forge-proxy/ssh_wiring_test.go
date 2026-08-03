package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// sshWiringStores opens a temp DB and returns the stores buildSSHSubsystem
// needs.
func sshWiringStores(t *testing.T) (*sshkey.Store, *user.Store, *session.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "forge.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	return sshkey.New(database, nil),
		user.New(database, nil),
		session.New(database, session.Options{
			Lifetime:    30 * 24 * time.Hour,
			IdleTimeout: 14 * 24 * time.Hour,
		})
}

// writeKnownHosts creates a known_hosts file with one syntactically valid
// entry, which is all knownhosts.New requires to load.
func writeKnownHosts(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	line := "[deuce.tailnet]:22 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

// sshEnabledConfig returns a config with one upstream and all SSH paths
// pointed inside a temp dir.
func sshEnabledConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	target, _ := url.Parse("ssh://deuce.tailnet:22")
	return &config.Config{
		AuthHost:          "auth.test",
		SSHListenAddr:     "127.0.0.1",
		SSHHostKeyPath:    filepath.Join(dir, "host_key"),
		SSHCAKeyPath:      filepath.Join(dir, "ca_key"),
		SSHKnownHostsPath: writeKnownHosts(t, dir),
		SSHUpstreams: map[int]config.SSHUpstream{
			0: {Port: 0, Target: target, AllowedRoles: []string{"ai-dev"}},
		},
	}
}

// TestBuildSSHSubsystem_DisabledIsANoOp is the regression that matters most
// for existing deployments: with SSH_UPSTREAMS empty, nothing is
// constructed, no keys are generated, and no routes are mounted.
func TestBuildSSHSubsystem_DisabledIsANoOp(t *testing.T) {
	keys, users, sessions := sshWiringStores(t)
	dir := t.TempDir()
	cfg := &config.Config{
		AuthHost: "auth.test",
		// Paths are set but must never be touched.
		SSHHostKeyPath: filepath.Join(dir, "host_key"),
		SSHCAKeyPath:   filepath.Join(dir, "ca_key"),
	}

	srv, enrollH, err := buildSSHSubsystem(cfg, keys, users, sessions)
	if err != nil {
		t.Fatalf("buildSSHSubsystem: %v", err)
	}
	if srv != nil {
		t.Error("server was constructed with no upstreams configured")
	}
	if enrollH != nil {
		t.Error("enrollment handlers were constructed with no upstreams configured")
	}
	for _, p := range []string{cfg.SSHHostKeyPath, cfg.SSHCAKeyPath} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was created; the disabled path must not generate keys", p)
		}
	}
}

func TestBuildSSHSubsystem_EnabledConstructsAndGeneratesKeys(t *testing.T) {
	keys, users, sessions := sshWiringStores(t)
	cfg := sshEnabledConfig(t)

	srv, enrollH, err := buildSSHSubsystem(cfg, keys, users, sessions)
	if err != nil {
		t.Fatalf("buildSSHSubsystem: %v", err)
	}
	if srv == nil || enrollH == nil {
		t.Fatalf("want a server and enrollment handlers, got srv=%v enrollH=%v", srv, enrollH)
	}

	// Host and CA keys are generated on first start.
	for _, p := range []string{cfg.SSHHostKeyPath, cfg.SSHCAKeyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s was not created: %v", p, err)
			continue
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s mode = %v, want no group/other access", p, mode)
		}
	}
}

// TestBuildSSHSubsystem_MissingKnownHostsIsFatal pins the security-relevant
// choice: without known_hosts the outbound leg would be trust-on-first-use,
// so the binary must refuse to start rather than run unverified.
func TestBuildSSHSubsystem_MissingKnownHostsIsFatal(t *testing.T) {
	keys, users, sessions := sshWiringStores(t)
	cfg := sshEnabledConfig(t)
	cfg.SSHKnownHostsPath = filepath.Join(t.TempDir(), "does-not-exist")

	srv, _, err := buildSSHSubsystem(cfg, keys, users, sessions)
	if err == nil {
		t.Fatal("expected an error when known_hosts is missing; starting without it " +
			"would mean forwarding to unverified upstreams")
	}
	if srv != nil {
		t.Error("a server was returned alongside the error")
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("error should tell the operator how to fix it, got: %v", err)
	}
}

// TestBuildSSHSubsystem_EnrollmentRoutesMount proves the enrollment handler
// registers on the auth mux, which is how an unknown key becomes a
// registered one.
func TestBuildSSHSubsystem_EnrollmentRoutesMount(t *testing.T) {
	keys, users, sessions := sshWiringStores(t)
	cfg := sshEnabledConfig(t)

	_, enrollH, err := buildSSHSubsystem(cfg, keys, users, sessions)
	if err != nil {
		t.Fatalf("buildSSHSubsystem: %v", err)
	}

	mux := http.NewServeMux()
	enrollH.Mount(mux)

	req := httptest.NewRequest(http.MethodGet, "http://auth.test/ssh/enroll/sometoken", nil)
	_, pattern := mux.Handler(req)
	if pattern == "" {
		t.Error("no route matched /ssh/enroll/<token>; enrollment would 404")
	}
}

// TestSSHServerRunAndShutdown exercises the lifecycle main.go drives: the
// listeners bind, then Shutdown releases them. A port left bound would make
// a restart fail.
func TestSSHServerRunAndShutdown(t *testing.T) {
	keys, users, sessions := sshWiringStores(t)
	cfg := sshEnabledConfig(t)

	// Claim a free port, then hand it to the config so Run binds something
	// concrete and the test can prove it was released.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	target, _ := url.Parse("ssh://deuce.tailnet:22")
	cfg.SSHUpstreams = map[int]config.SSHUpstream{
		port: {Port: port, Target: target, AllowedRoles: []string{"ai-dev"}},
	}

	srv, _, err := buildSSHSubsystem(cfg, keys, users, sessions)
	if err != nil {
		t.Fatalf("buildSSHSubsystem: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	// Wait for the listener to come up.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if !waitForListener(addr, 3*time.Second) {
		cancel()
		t.Fatalf("SSH listener never bound on %s", addr)
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-runErr:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}

	// The port must be reusable, or a restart would fail to bind.
	reuse, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port %d still bound after Shutdown: %v", port, err)
	}
	_ = reuse.Close()
}

func waitForListener(addr string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
