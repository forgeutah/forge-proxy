package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
)

// Sentinel errors. Both flow to "redirect to login" at the HTTP boundary, but
// callers (metrics, audit log) should distinguish them. ErrExpired means a
// legitimate session aged out; ErrNotFound means the ID was never minted (or
// has already been swept / revoked). Tracking the two separately helps with
// capacity planning and detecting unusual revocation patterns.
var (
	// ErrNotFound is returned by Get when the session ID is unknown to the
	// store (never minted, swept, or revoked).
	ErrNotFound = errors.New("session: not found")

	// ErrExpired is returned by Get when the session row exists but its
	// expires_at is in the past. The row is left in place; Sweep is the
	// only path that deletes expired rows.
	ErrExpired = errors.New("session: expired")
)

// touchThrottle is the minimum interval between writes to last_seen_at /
// expires_at for a given session. Sub-threshold Touch calls are silent
// no-ops. This bounds the writer-pool pressure created by chatty clients
// without weakening the sliding-window promise in any user-visible way.
const touchThrottle = 60 * time.Second

// Session is one row of the sessions table, decoded into Go time values.
// The DB stores all timestamps as Unix seconds (matching the schema in
// migrations/0002).
type Session struct {
	ID         string
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	UserAgent  string
	IP         string
}

// Options configures a Store. Lifetime is the absolute cap (no session may
// outlive CreatedAt + Lifetime); IdleTimeout drives the sliding renewal
// (each Touch sets expires_at = min(now + IdleTimeout, CreatedAt +
// Lifetime)). CookieDomain is plumbed through here so the package owns the
// one true source for both the store and the cookie helpers; Now is a clock
// hook used by tests — production callers leave it nil and get time.Now.
type Options struct {
	Lifetime     time.Duration
	IdleTimeout  time.Duration
	CookieDomain string
	Now          func() time.Time
}

// Store provides server-side session lifecycle operations against the
// underlying SQLite database. It is safe for concurrent use; writes go
// through DB.WithWriteTx (BEGIN IMMEDIATE) and reads go through the reader
// pool.
type Store struct {
	db   *db.DB
	opts Options
}

// New constructs a Store with the given options. If opts.Now is nil it
// defaults to time.Now, so production wiring stays a one-liner.
func New(database *db.DB, opts Options) *Store {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{db: database, opts: opts}
}

// CookieDomain returns the configured cookie domain (e.g. ".forgeutah.tech").
// Handlers that build cookies should ask the store rather than re-deriving it
// from config — keeps the cookie scope rule in one place.
func (s *Store) CookieDomain() string { return s.opts.CookieDomain }

// generateID returns a 43-character base64url-encoded session ID built from
// 32 cryptographically random bytes. The "no padding" form (RawURLEncoding)
// keeps the cookie value URL- and header-safe without trailing '='.
func generateID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Create mints a new session row for the given user and returns it.
//
// The session's CreatedAt and LastSeenAt are both stamped to the store's
// current clock; ExpiresAt is set to now + IdleTimeout (it can never exceed
// CreatedAt + Lifetime by definition, since CreatedAt == now). The row is
// written inside WithWriteTx so writes serialize cleanly with concurrent
// Touch / Delete / Sweep operations.
func (s *Store) Create(ctx context.Context, userID int64, userAgent, ip string) (*Session, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	now := s.opts.Now().UTC()
	expires := now.Add(s.opts.IdleTimeout)

	err = s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		_, execErr := tx.ExecContext(ctx, `
			INSERT INTO sessions (id, user_id, created_at, last_seen_at, expires_at, user_agent, ip)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, id, userID, now.Unix(), now.Unix(), expires.Unix(), userAgent, ip)
		return execErr
	})
	if err != nil {
		return nil, fmt.Errorf("session: insert: %w", err)
	}

	return &Session{
		ID:         id,
		UserID:     userID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expires,
		UserAgent:  userAgent,
		IP:         ip,
	}, nil
}

// Get looks up a session by ID using the reader pool.
//
// Three outcomes, distinguishable by the returned error:
//   - found and live → (*Session, nil)
//   - row exists but expired → (nil, ErrExpired)
//   - no such row → (nil, ErrNotFound)
//
// We do not delete expired rows here — Sweep handles that. Keeping Get
// read-only means it never blocks on the writer pool and never fails due to
// a write contention.
func (s *Store) Get(ctx context.Context, id string) (*Session, error) {
	var (
		userID                              int64
		createdAt, lastSeenAt, expiresAtSec int64
		userAgent, ip                       sql.NullString
	)
	err := s.db.Reader.QueryRowContext(ctx, `
		SELECT user_id, created_at, last_seen_at, expires_at, user_agent, ip
		FROM sessions
		WHERE id = ?
	`, id).Scan(&userID, &createdAt, &lastSeenAt, &expiresAtSec, &userAgent, &ip)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session: select: %w", err)
	}

	expires := time.Unix(expiresAtSec, 0).UTC()
	if !s.opts.Now().UTC().Before(expires) {
		return nil, ErrExpired
	}

	return &Session{
		ID:         id,
		UserID:     userID,
		CreatedAt:  time.Unix(createdAt, 0).UTC(),
		LastSeenAt: time.Unix(lastSeenAt, 0).UTC(),
		ExpiresAt:  expires,
		UserAgent:  userAgent.String,
		IP:         ip.String,
	}, nil
}

// Touch slides a session's last_seen_at and expires_at forward, subject to
// two constraints:
//
//  1. Throttling: if the existing last_seen_at is younger than 60s the call
//     is a silent no-op (no DB write). This bounds writer pressure from
//     chatty clients without weakening the sliding-window promise.
//  2. Absolute cap: expires_at is set to min(now + IdleTimeout, created_at +
//     Lifetime). Touch never extends a session past its absolute cap, and
//     never resurrects an already-expired session.
//
// Touch failures (disk full, brief WAL contention beyond busy_timeout) are
// returned to the caller but per the plan the proxy hot path logs and
// continues — the session remains valid for the rest of its current window.
// Documenting that here so the caller's contract is unambiguous.
func (s *Store) Touch(ctx context.Context, id string) error {
	now := s.opts.Now().UTC()

	// Fast path: read last_seen_at via the reader pool. The 60s throttle
	// exists to keep chatty clients out of the writer pool entirely, so
	// the throttle check must precede the writer acquisition. A stale read
	// is harmless — the slow path below re-validates inside the writer
	// transaction so two concurrent Touch calls can't both write.
	var lastSeenAtSec int64
	err := s.db.Reader.QueryRowContext(ctx, `
		SELECT last_seen_at FROM sessions WHERE id = ?
	`, id).Scan(&lastSeenAtSec)
	if errors.Is(err, sql.ErrNoRows) {
		// Touch on a nonexistent ID is a no-op. The HTTP layer rejects
		// the request via Get's ErrNotFound; we don't surface the same
		// failure twice.
		return nil
	}
	if err != nil {
		return fmt.Errorf("session: touch pre-check: %w", err)
	}
	lastSeen := time.Unix(lastSeenAtSec, 0).UTC()
	if now.Sub(lastSeen) < touchThrottle {
		return nil
	}

	// Slow path: re-read inside the writer transaction so the throttle
	// decision and the update are atomic. Otherwise two concurrent Touch
	// calls could both observe a stale last_seen_at and both write.
	return s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		var (
			createdAtSec  int64
			expiresAtSec  int64
		)
		err := tx.QueryRowContext(ctx, `
			SELECT created_at, last_seen_at, expires_at FROM sessions WHERE id = ?
		`, id).Scan(&createdAtSec, &lastSeenAtSec, &expiresAtSec)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("session: touch select: %w", err)
		}

		expires := time.Unix(expiresAtSec, 0).UTC()
		// Never resurrect an expired session.
		if !now.Before(expires) {
			return nil
		}

		// Re-check the throttle with the in-transaction read, in case
		// another Touch landed between the fast-path read and BEGIN.
		lastSeen := time.Unix(lastSeenAtSec, 0).UTC()
		if now.Sub(lastSeen) < touchThrottle {
			return nil
		}

		createdAt := time.Unix(createdAtSec, 0).UTC()
		absoluteCap := createdAt.Add(s.opts.Lifetime)
		newExpires := now.Add(s.opts.IdleTimeout)
		if newExpires.After(absoluteCap) {
			newExpires = absoluteCap
		}

		_, err = tx.ExecContext(ctx, `
			UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?
		`, now.Unix(), newExpires.Unix(), id)
		if err != nil {
			return fmt.Errorf("session: touch update: %w", err)
		}
		return nil
	})
}

// Delete removes the session row identified by id. It is a no-op (returns
// nil) if no such row exists — sign-out should be idempotent. End-to-end
// AE5 coverage lives in U6; the store-layer assertion lives in
// store_test.go's TestDelete_RemovesRow_CoversAE5.
func (s *Store) Delete(ctx context.Context, id string) error {
	return s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("session: delete: %w", err)
		}
		return nil
	})
}

// DeleteAllForUser removes every session row belonging to the given user.
// Used by the admin "force sign-out everywhere" path and by the off-boarding
// runbook (see plan §"Workspace membership is verified only at sign-in").
func (s *Store) DeleteAllForUser(ctx context.Context, userID int64) error {
	return s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
		if err != nil {
			return fmt.Errorf("session: delete by user: %w", err)
		}
		return nil
	})
}

// Sweep deletes every session whose expires_at is strictly before the
// supplied "now" and returns the number of rows removed. A periodic janitor
// in main.go calls this on a timer; tests pass in a fixed clock.
func (s *Store) Sweep(ctx context.Context, now time.Time) (int, error) {
	var deleted int
	err := s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM sessions WHERE expires_at < ?`, now.Unix())
		if err != nil {
			return fmt.Errorf("session: sweep: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("session: sweep rows-affected: %w", err)
		}
		deleted = int(n)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
