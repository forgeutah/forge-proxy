package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrInvalidCA is returned by Mint when called with a nil CA signer.
var ErrInvalidCA = errors.New("sshca: nil CA signer")

// validBeforeSkew is the back-dated ValidAfter offset. Two minutes' worth of
// upstream clock skew is the practical envelope we've seen in shared-VM
// environments; 30s is the conservative lower bound that absorbs ordinary
// NTP jitter without enlarging the cert's effective lifetime window.
const validBeforeSkew = 30 * time.Second

// Mint issues a short-TTL Ed25519 user certificate signed by the supplied CA.
//
// The returned signer pairs an ephemeral private key (freshly generated for
// this single cert, never reused) with the signed *ssh.Certificate. The cert's
// principal and KeyId are both set to `principal` — upstream sshd's
// AuthorizedPrincipalsCommand (see README) maps that to a local user account.
//
// Permissions are intentionally minimal: only the "permit-pty" extension is
// set. The proxy declines reverse-port-forward and agent-forward requests
// (see internal/sshproxy/forward.go scope), so broader cert permissions would
// be standing over-privilege relative to what the forwarding path actually
// exercises. The 2-minute TTL only needs to outlive the SSH handshake; once
// the upstream session is authenticated, sshd does not re-verify the cert,
// so VSCode Remote SSH's hours-long sessions are unaffected.
//
// The `now` hook defaults to time.Now when nil; tests use it to drive
// validity-window math deterministically.
func Mint(ctx context.Context, ca ssh.Signer, principal string, ttl time.Duration, now func() time.Time) (ssh.Signer, error) {
	if ca == nil {
		return nil, ErrInvalidCA
	}
	if principal == "" {
		return nil, errors.New("sshca: empty principal")
	}
	if ttl <= 0 {
		return nil, errors.New("sshca: ttl must be > 0")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshca: generate ephemeral key: %w", err)
	}

	ephemSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: new ephemeral signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: ssh public key: %w", err)
	}

	t := now().UTC()
	cert := &ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(t.Add(-validBeforeSkew).Unix()),
		ValidBefore:     uint64(t.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, fmt.Errorf("sshca: sign cert: %w", err)
	}

	certSigner, err := ssh.NewCertSigner(cert, ephemSigner)
	if err != nil {
		return nil, fmt.Errorf("sshca: new cert signer: %w", err)
	}
	return certSigner, nil
}
