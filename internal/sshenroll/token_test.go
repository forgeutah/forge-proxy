package sshenroll

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestMint_ReturnsUniqueTokens proves the token-generation primitive doesn't
// collide across calls. The 32-random-bytes shape makes a collision
// vanishingly unlikely, but a regression in the random source would silently
// give two enrollment URLs the same token, which would cross-bind keys.
func TestMint_ReturnsUniqueTokens(t *testing.T) {
	s := NewStore(time.Now)
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		token, err := s.Mint("SHA256:"+strings.Repeat("A", 43), "ssh-ed25519", []byte{1})
		if err != nil {
			t.Fatalf("Mint %d: %v", i, err)
		}
		if seen[token] {
			t.Fatalf("duplicate token at iteration %d: %s", i, token)
		}
		seen[token] = true
	}
}

// TestMint_ThenConsume_HappyPath fences the round-trip contract: the data
// stored under Mint comes back verbatim under Consume.
func TestMint_ThenConsume_HappyPath(t *testing.T) {
	s := NewStore(time.Now)
	fp := "SHA256:" + strings.Repeat("A", 43)
	keyBlob := []byte{1, 2, 3, 4}

	token, err := s.Mint(fp, "ssh-ed25519", keyBlob)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	got, err := s.Consume(token)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.Fingerprint != fp {
		t.Errorf("Fingerprint = %q", got.Fingerprint)
	}
	if got.KeyType != "ssh-ed25519" {
		t.Errorf("KeyType = %q", got.KeyType)
	}
	if string(got.PublicKey) != string(keyBlob) {
		t.Errorf("PublicKey = %v", got.PublicKey)
	}
}

// TestConsume_DeletesTokenSingleUse covers the security-critical single-use
// contract. After a successful Consume, the same token MUST NOT be redeemable
// a second time — even by the same user (defence against replay).
func TestConsume_DeletesTokenSingleUse(t *testing.T) {
	s := NewStore(time.Now)
	token, err := s.Mint("SHA256:abc", "ssh-ed25519", []byte{1})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := s.Consume(token); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	_, err = s.Consume(token)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Consume err = %v, want ErrNotFound", err)
	}
}

// TestConsume_ExpiredReturnsErrExpired proves the TTL boundary case. A token
// whose 10-minute window has elapsed must surface as ErrExpired (not
// ErrNotFound) so the handler can render the "this link expired — re-run
// ssh" copy specifically.
func TestConsume_ExpiredReturnsErrExpired(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	clk := &t0
	now := func() time.Time { return *clk }

	s := NewStore(now)
	token, err := s.Mint("SHA256:abc", "ssh-ed25519", []byte{1})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	*clk = t0.Add(DefaultTTL + time.Second)
	_, err = s.Consume(token)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Consume after TTL err = %v, want ErrExpired", err)
	}
}

// TestConsume_UnknownTokenReturnsErrNotFound is the unknown-token surface
// the handler relies on to render an identical 404-style page (no info leak
// about whether the token ever existed).
func TestConsume_UnknownTokenReturnsErrNotFound(t *testing.T) {
	s := NewStore(time.Now)
	_, err := s.Consume("nonexistent-token-value")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Consume unknown err = %v, want ErrNotFound", err)
	}
}

// TestSweep_RemovesExpiredOnly fences the cleanup primitive: non-expired
// entries survive a sweep so a stuck user mid-flow isn't kicked out.
func TestSweep_RemovesExpiredOnly(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	clk := &t0
	now := func() time.Time { return *clk }
	s := NewStore(now)

	expiredTok, _ := s.Mint("SHA256:a", "ssh-ed25519", []byte{1})
	*clk = t0.Add(DefaultTTL + time.Second)
	freshTok, _ := s.Mint("SHA256:b", "ssh-ed25519", []byte{2})

	s.Sweep()

	if _, err := s.Consume(expiredTok); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExpired) {
		t.Errorf("expired Consume err = %v, want NotFound or Expired", err)
	}
	if _, err := s.Consume(freshTok); err != nil {
		t.Errorf("fresh Consume err = %v, want nil", err)
	}
}

// TestPeek_DoesNotConsume proves the read-without-delete path used by the
// initial fingerprint-display handler. The handler needs the fingerprint to
// render the page but must NOT consume the token there — consumption happens
// after the OIDC round-trip.
func TestPeek_DoesNotConsume(t *testing.T) {
	s := NewStore(time.Now)
	fp := "SHA256:" + strings.Repeat("A", 43)
	token, err := s.Mint(fp, "ssh-ed25519", []byte{1})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	got, err := s.Peek(token)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if got.Fingerprint != fp {
		t.Errorf("Peek Fingerprint = %q", got.Fingerprint)
	}

	// Token must still be consumable after a Peek.
	if _, err := s.Consume(token); err != nil {
		t.Errorf("Consume after Peek: %v", err)
	}
}
