package sshca

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestLoadOrGenerate_GeneratesOnMissingPath confirms the bootstrap behaviour:
// on first start with a fresh path, we mint a usable Ed25519 keypair and
// write both halves with the documented modes.
func TestLoadOrGenerate_GeneratesOnMissingPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca_key")

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	signer, err := LoadOrGenerate(path, logger)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if signer == nil {
		t.Fatalf("signer is nil")
	}

	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat private key: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %o, want 0600", got)
	}

	pubPath := path + ".pub"
	if info, err := os.Stat(pubPath); err != nil {
		t.Fatalf("stat public key: %v", err)
	} else if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("public key mode = %o, want 0644", got)
	}

	if !strings.Contains(logBuf.String(), "ssh_key_generated") {
		t.Errorf("generation event not logged; got %s", logBuf.String())
	}

	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(pubRaw); err != nil {
		t.Errorf("public file not parseable: %v", err)
	}

	// Sign + verify a roundtrip to prove the signer is functional.
	msg := []byte("forge-proxy")
	sig, err := signer.Sign(nil, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestLoadOrGenerate_RoundtripsExistingKey proves the load path: after
// generation, a second call on the same path reads the same key bits back.
func TestLoadOrGenerate_RoundtripsExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca_key")

	first, err := LoadOrGenerate(path, slog.Default())
	if err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}
	second, err := LoadOrGenerate(path, slog.Default())
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}

	if !bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Errorf("public key bytes differ between loads — file was regenerated")
	}
}

// TestLoadOrGenerate_WarnsOnPermissiveMode covers the operator-mistake path:
// we don't refuse to start, but we log a warning operators can grep for.
func TestLoadOrGenerate_WarnsOnPermissiveMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca_key")

	if _, err := LoadOrGenerate(path, slog.Default()); err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if _, err := LoadOrGenerate(path, logger); err != nil {
		t.Fatalf("LoadOrGenerate on permissive file: %v", err)
	}

	if !strings.Contains(logBuf.String(), "ssh_key_mode_too_permissive") {
		t.Errorf("permissive-mode warning not logged; got %s", logBuf.String())
	}
}

// TestLoadOrGenerate_ParseErrorWrapped surfaces a corrupt file as a typed
// error rather than letting the binary crash on an undefined ssh internal.
func TestLoadOrGenerate_ParseErrorWrapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca_key")

	if err := os.WriteFile(path, []byte("this is not a private key"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	if _, err := LoadOrGenerate(path, slog.Default()); err == nil {
		t.Errorf("LoadOrGenerate on garbage: want error")
	}
}

// TestLoadOrGenerate_EmptyPathReturnsError guards against the obvious config
// misuse (`SSH_HOST_KEY_PATH=` left empty).
func TestLoadOrGenerate_EmptyPathReturnsError(t *testing.T) {
	if _, err := LoadOrGenerate("", slog.Default()); err == nil {
		t.Errorf("LoadOrGenerate with empty path: want error")
	}
}

// TestLoadOrGenerate_CanBeUsedAsCAForMint exercises the integration between
// the two files in this package: a key produced by LoadOrGenerate must be a
// valid CA signer for Mint.
func TestLoadOrGenerate_CanBeUsedAsCAForMint(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca_key")
	ca, err := LoadOrGenerate(caPath, slog.Default())
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	now := time.Now().UTC()
	certSigner, err := Mint(context.Background(), ca, "alice@example.com", time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cert := certSigner.PublicKey().(*ssh.Certificate)
	if cert.KeyId != "alice@example.com" {
		t.Errorf("KeyId = %q", cert.KeyId)
	}

	checker := &ssh.CertChecker{
		Clock: func() time.Time { return now },
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return keysEqual(auth, ca.PublicKey())
		},
	}
	if err := checker.CheckCert("alice@example.com", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}
}
