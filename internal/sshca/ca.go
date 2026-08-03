package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// LoadOrGenerate reads an Ed25519 private key from path, generating + persisting
// a new one if the file is missing.
//
// On generation: the private half is written to `path` with mode 0600; the
// public half (OpenSSH authorized-keys form) is written to `path + ".pub"`
// with mode 0644 so operators can scp it into upstream sshd's
// TrustedUserCAKeys file or host keys list.
//
// On load: if the file is more permissive than 0600 we log a slog.Warn but
// proceed — refusing to start the proxy because of a file-mode drift would
// be more disruptive than the risk a single misconfigured ACL represents
// when the proxy VM is already firewalled.
//
// `logger` may be nil; nil falls back to slog.Default() so production wiring
// stays a one-liner.
func LoadOrGenerate(path string, logger *slog.Logger) (ssh.Signer, error) {
	if path == "" {
		return nil, errors.New("sshca: empty key path")
	}
	if logger == nil {
		logger = slog.Default()
	}

	info, err := os.Stat(path)
	switch {
	case err == nil:
		if mode := info.Mode().Perm(); mode&^0o600 != 0 {
			logger.Warn("ssh_key_mode_too_permissive", "path", path, "mode", mode.String())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("sshca: read %s: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("sshca: parse %s: %w", path, err)
		}
		return signer, nil

	case errors.Is(err, os.ErrNotExist):
		return generate(path, logger)

	default:
		return nil, fmt.Errorf("sshca: stat %s: %w", path, err)
	}
}

// generate creates a fresh Ed25519 keypair, writes both halves to disk, and
// returns the signer wrapping the private key. The parent directory is
// created with 0700 if missing so we can drop the operator into a runnable
// state without asking them to pre-create /data/ssh by hand.
func generate(path string, logger *slog.Logger) (ssh.Signer, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("sshca: mkdir %s: %w", dir, err)
		}
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshca: generate ed25519: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "forge-proxy")
	if err != nil {
		return nil, fmt.Errorf("sshca: marshal private key: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return nil, fmt.Errorf("sshca: write %s: %w", path, err)
	}

	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: ssh.NewPublicKey: %w", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	pubPath := path + ".pub"
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return nil, fmt.Errorf("sshca: write %s: %w", pubPath, err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: signer from key: %w", err)
	}

	logger.Info("ssh_key_generated", "path", path, "pub_path", pubPath, "type", "ed25519")
	return signer, nil
}
