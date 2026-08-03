package sshenroll

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultTTL is the lifetime of a freshly-minted enrollment token. Ten
// minutes is long enough for a contributor on a slow network to finish the
// Slack consent screen but short enough that a leaked URL has limited
// replay value.
const DefaultTTL = 10 * time.Minute

// ErrNotFound is returned by Consume / Peek when no entry matches the token.
// Handlers map this and ErrExpired to the same "this link is invalid" page
// — no info leak about whether the token ever existed.
var ErrNotFound = errors.New("sshenroll: token not found")

// ErrExpired is returned by Consume / Peek when the entry exists but its
// TTL has elapsed. Kept distinct from ErrNotFound so the handler CAN render
// a more specific message in the future if we ever decide to.
var ErrExpired = errors.New("sshenroll: token expired")

// Enrollment is the payload bound to a single enrollment URL. KeyType comes
// from ssh.PublicKey.Type() (e.g. "ssh-ed25519"); PublicKey is the wire
// form (ssh.PublicKey.Marshal() bytes). Fingerprint is the
// OpenSSH-canonical SHA256 form shown to the user pre-sign-in.
type Enrollment struct {
	Fingerprint string
	KeyType     string
	PublicKey   []byte
	ExpiresAt   time.Time
}

// Store is the in-memory token store. Safe for concurrent use; a single
// mutex protects the map for the lifetime of the process.
type Store struct {
	mu     sync.Mutex
	tokens map[string]Enrollment
	now    func() time.Time
}

// NewStore constructs a Store. now defaults to time.Now when nil so
// production wiring stays a one-liner; tests inject a controllable clock.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		tokens: make(map[string]Enrollment),
		now:    now,
	}
}

// Mint generates a fresh single-use token bound to the supplied key data
// and returns it. The store opportunistically sweeps expired entries
// before inserting so an idle process doesn't accumulate stale rows.
func (s *Store) Mint(fingerprint, keyType string, publicKey []byte) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked()

	// Defensive copy so the caller mutating the slice later can't change
	// what we stored.
	keyCopy := append([]byte(nil), publicKey...)

	s.tokens[token] = Enrollment{
		Fingerprint: fingerprint,
		KeyType:     keyType,
		PublicKey:   keyCopy,
		ExpiresAt:   s.now().Add(DefaultTTL),
	}
	return token, nil
}

// Peek looks up an entry without removing it. Used by the
// fingerprint-display handler that runs before sign-in.
func (s *Store) Peek(token string) (Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.tokens[token]
	if !ok {
		return Enrollment{}, ErrNotFound
	}
	if !s.now().Before(e.ExpiresAt) {
		return Enrollment{}, ErrExpired
	}
	return e, nil
}

// Consume looks up an entry and removes it atomically. Returns ErrNotFound
// for unknown tokens and ErrExpired for entries past their TTL (entries are
// also removed in the expired case so a second consume returns ErrNotFound).
func (s *Store) Consume(token string) (Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.tokens[token]
	if !ok {
		return Enrollment{}, ErrNotFound
	}
	delete(s.tokens, token)
	if !s.now().Before(e.ExpiresAt) {
		return Enrollment{}, ErrExpired
	}
	return e, nil
}

// Sweep removes every entry whose ExpiresAt has elapsed. Called
// opportunistically from Mint; v1 has no background goroutine because
// enrollment traffic is low and Mint is the natural cadence.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *Store) sweepLocked() {
	now := s.now()
	for tok, e := range s.tokens {
		if !now.Before(e.ExpiresAt) {
			delete(s.tokens, tok)
		}
	}
}

// randomToken returns 32 random bytes base64url-encoded with no padding.
// Mirrors internal/auth/state.go's helper of the same shape so logs grep
// identically.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("sshenroll: crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
