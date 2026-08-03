package sshca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// keysEqual compares two PublicKeys by their marshalled SSH wire form.
// x/crypto/ssh has no exported equality helper.
func keysEqual(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// genCA returns a fresh Ed25519 CA signer for tests.
func genCA(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

// fixedNow returns a deterministic clock.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// TestMint_ProducesValidUserCertWithExpectedFields fences the contract that
// the proxy presents to upstream sshd: UserCert with KeyId + ValidPrincipals
// set to the Slack email, ValidAfter back-dated 30s to absorb clock skew,
// ValidBefore = now + ttl, and permit-pty as the only extension.
func TestMint_ProducesValidUserCertWithExpectedFields(t *testing.T) {
	ca := genCA(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	ttl := 2 * time.Minute

	certSigner, err := Mint(context.Background(), ca, "alice@example.com", ttl, fixedNow(now))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	pub := certSigner.PublicKey()
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *ssh.Certificate", pub)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want UserCert(%d)", cert.CertType, ssh.UserCert)
	}
	if cert.KeyId != "alice@example.com" {
		t.Errorf("KeyId = %q, want alice@example.com", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice@example.com" {
		t.Errorf("ValidPrincipals = %v, want [alice@example.com]", cert.ValidPrincipals)
	}
	wantValidAfter := uint64(now.Add(-30 * time.Second).Unix())
	if cert.ValidAfter != wantValidAfter {
		t.Errorf("ValidAfter = %d, want %d (now-30s)", cert.ValidAfter, wantValidAfter)
	}
	wantValidBefore := uint64(now.Add(ttl).Unix())
	if cert.ValidBefore != wantValidBefore {
		t.Errorf("ValidBefore = %d, want %d (now+ttl)", cert.ValidBefore, wantValidBefore)
	}

	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Errorf("Extensions missing permit-pty; got %v", cert.Permissions.Extensions)
	}
	if len(cert.Permissions.Extensions) != 1 {
		t.Errorf("Extensions = %v, want only permit-pty", cert.Permissions.Extensions)
	}
	if _, has := cert.Permissions.Extensions["permit-port-forwarding"]; has {
		t.Errorf("Extensions should not include permit-port-forwarding")
	}

	if cert.SignatureKey == nil {
		t.Errorf("SignatureKey is nil — cert was not signed")
	}

	checker := &ssh.CertChecker{
		Clock: func() time.Time { return now },
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return keysEqual(auth, ca.PublicKey())
		},
	}
	if err := checker.CheckCert("alice@example.com", cert); err != nil {
		t.Errorf("CertChecker.CheckCert: %v", err)
	}
}

// TestMint_ProducesUniqueEphemeralKeyPairs proves Mint does not reuse the
// ephemeral keypair across invocations — a regression here would let one
// outbound cert's compromise impact others.
func TestMint_ProducesUniqueEphemeralKeyPairs(t *testing.T) {
	ca := genCA(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	s1, err := Mint(context.Background(), ca, "alice@example.com", time.Minute, fixedNow(now))
	if err != nil {
		t.Fatalf("Mint #1: %v", err)
	}
	s2, err := Mint(context.Background(), ca, "alice@example.com", time.Minute, fixedNow(now))
	if err != nil {
		t.Fatalf("Mint #2: %v", err)
	}

	c1 := s1.PublicKey().(*ssh.Certificate)
	c2 := s2.PublicKey().(*ssh.Certificate)
	if keysEqual(c1.Key, c2.Key) {
		t.Errorf("ephemeral keypairs reused across Mint calls")
	}
}

// TestMint_EmptyPrincipalReturnsError refuses to mint identityless certs;
// upstream sshd's AuthorizedPrincipalsCommand needs a non-empty principal to
// route.
func TestMint_EmptyPrincipalReturnsError(t *testing.T) {
	ca := genCA(t)
	_, err := Mint(context.Background(), ca, "", time.Minute, time.Now)
	if err == nil {
		t.Fatalf("Mint with empty principal: want error")
	}
}

// TestMint_ZeroTTLReturnsError prevents the "cert valid for 0 seconds" edge
// case slipping through to a confusing upstream authn failure.
func TestMint_ZeroTTLReturnsError(t *testing.T) {
	ca := genCA(t)
	_, err := Mint(context.Background(), ca, "alice@example.com", 0, time.Now)
	if err == nil {
		t.Fatalf("Mint with ttl=0: want error")
	}
}

// TestMint_NegativeTTLReturnsError is the symmetric edge case.
func TestMint_NegativeTTLReturnsError(t *testing.T) {
	ca := genCA(t)
	_, err := Mint(context.Background(), ca, "alice@example.com", -time.Second, time.Now)
	if err == nil {
		t.Fatalf("Mint with ttl<0: want error")
	}
}

// TestMint_NilCAReturnsError guards against the obvious misuse — without a
// CA there's no cert to mint.
func TestMint_NilCAReturnsError(t *testing.T) {
	_, err := Mint(context.Background(), nil, "alice@example.com", time.Minute, time.Now)
	if err == nil {
		t.Fatalf("Mint with nil CA: want error")
	}
	if !errors.Is(err, ErrInvalidCA) && err.Error() == "" {
		t.Errorf("Mint nil-CA err = %v, want non-empty / ErrInvalidCA", err)
	}
}
