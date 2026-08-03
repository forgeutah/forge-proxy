package sshkey

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
)

// ErrNotFound is returned by lookup methods when no row matches.
// Callers (SSH auth callback, admin CLI) branch on this sentinel so they can
// distinguish "key not registered" (which triggers TOFU enrollment) from
// other errors (which surface as 500s in the log).
var ErrNotFound = errors.New("sshkey: not found")

// ErrFingerprintTaken is returned by Add when the fingerprint is already
// registered to a user. Enforced by the UNIQUE constraint on
// ssh_keys.fingerprint; we wrap the driver error into this sentinel so
// callers don't have to sniff SQLite-specific text.
var ErrFingerprintTaken = errors.New("sshkey: fingerprint already registered")

// Key is one row of the ssh_keys table, decoded into Go values. Unix-second
// timestamp columns are converted to time.Time at the boundary so the rest of
// the application doesn't carry the DB's representation. LastUsedAt is the
// zero time when the column is NULL (a freshly-enrolled key that has never
// authenticated).
type Key struct {
	ID          int64
	UserID      int64
	Fingerprint string
	KeyType     string
	PublicKey   []byte
	Label       string
	CreatedAt   time.Time
	LastUsedAt  time.Time
}

// Store owns the ssh_keys table. Writes go through DB.WithWriteTx; reads
// use the reader pool. Safe for concurrent use.
type Store struct {
	db  *db.DB
	now func() time.Time
}

// New constructs a Store. If now is nil it defaults to time.Now, so production
// wiring stays a one-liner; tests pass a fixed clock.
func New(database *db.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: database, now: now}
}

// Add inserts a new ssh_keys row for the given user with the supplied
// fingerprint + key bytes. Returns the created Key with the auto-assigned ID
// and CreatedAt stamped from the store's clock. If the fingerprint is already
// registered (UNIQUE violation), returns ErrFingerprintTaken so the caller can
// render a friendly enrollment-conflict page (see U5).
func (s *Store) Add(ctx context.Context, userID int64, fingerprint, keyType string, publicKey []byte, label string) (*Key, error) {
	now := s.now().UTC()
	nowUnix := now.Unix()

	var id int64
	err := s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		res, execErr := tx.ExecContext(ctx, `
			INSERT INTO ssh_keys (user_id, fingerprint, key_type, public_key, label, created_at, last_used_at)
			VALUES (?, ?, ?, ?, ?, ?, NULL)
		`, userID, fingerprint, keyType, publicKey, label, nowUnix)
		if execErr != nil {
			if isUniqueViolation(execErr) {
				return ErrFingerprintTaken
			}
			return fmt.Errorf("sshkey: insert: %w", execErr)
		}
		newID, idErr := res.LastInsertId()
		if idErr != nil {
			return fmt.Errorf("sshkey: last insert id: %w", idErr)
		}
		id = newID
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &Key{
		ID:          id,
		UserID:      userID,
		Fingerprint: fingerprint,
		KeyType:     keyType,
		PublicKey:   append([]byte(nil), publicKey...),
		Label:       label,
		CreatedAt:   now,
	}, nil
}

// Get fetches a key by fingerprint via the reader pool. Returns ErrNotFound
// (not a wrapped sql.ErrNoRows) when no row exists — the SSH auth callback
// branches on this sentinel to trigger TOFU enrollment.
func (s *Store) Get(ctx context.Context, fingerprint string) (*Key, error) {
	var (
		k             Key
		label         sql.NullString
		createdAtSec  int64
		lastUsedAtSec sql.NullInt64
	)
	err := s.db.Reader.QueryRowContext(ctx, `
		SELECT id, user_id, fingerprint, key_type, public_key, label, created_at, last_used_at
		FROM ssh_keys
		WHERE fingerprint = ?
	`, fingerprint).Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.KeyType, &k.PublicKey, &label, &createdAtSec, &lastUsedAtSec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sshkey: select: %w", err)
	}
	k.Label = label.String
	k.CreatedAt = time.Unix(createdAtSec, 0).UTC()
	if lastUsedAtSec.Valid {
		k.LastUsedAt = time.Unix(lastUsedAtSec.Int64, 0).UTC()
	}
	return &k, nil
}

// ListByUser returns every key belonging to the given user, ordered by
// created_at ascending (oldest first — matches the admin CLI's "history"
// display). Returns an empty slice (not nil) when the user has no keys.
func (s *Store) ListByUser(ctx context.Context, userID int64) ([]*Key, error) {
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, user_id, fingerprint, key_type, public_key, label, created_at, last_used_at
		FROM ssh_keys
		WHERE user_id = ?
		ORDER BY created_at ASC, id ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("sshkey: list by user: %w", err)
	}
	defer rows.Close()

	out := make([]*Key, 0)
	for rows.Next() {
		var (
			k             Key
			label         sql.NullString
			createdAtSec  int64
			lastUsedAtSec sql.NullInt64
		)
		if err := rows.Scan(&k.ID, &k.UserID, &k.Fingerprint, &k.KeyType, &k.PublicKey, &label, &createdAtSec, &lastUsedAtSec); err != nil {
			return nil, fmt.Errorf("sshkey: scan: %w", err)
		}
		k.Label = label.String
		k.CreatedAt = time.Unix(createdAtSec, 0).UTC()
		if lastUsedAtSec.Valid {
			k.LastUsedAt = time.Unix(lastUsedAtSec.Int64, 0).UTC()
		}
		out = append(out, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sshkey: rows: %w", err)
	}
	return out, nil
}

// Remove deletes the key with the given fingerprint. It is idempotent: a
// missing fingerprint returns nil (mirroring session.Delete) so admin
// off-boarding scripts don't have to special-case "already removed".
func (s *Store) Remove(ctx context.Context, fingerprint string) error {
	return s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM ssh_keys WHERE fingerprint = ?`, fingerprint)
		if err != nil {
			return fmt.Errorf("sshkey: delete: %w", err)
		}
		return nil
	})
}

// TouchLastUsed stamps last_used_at to the store's current clock. Called from
// the SSH auth callback on every successful publickey authentication. v1 writes
// unconditionally; if profiling shows writer-pool contention, mirror
// session.Touch's 60-second throttle. Missing fingerprints are a silent no-op
// — the auth callback already validated the key via Get.
func (s *Store) TouchLastUsed(ctx context.Context, fingerprint string) error {
	now := s.now().UTC()
	return s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE ssh_keys SET last_used_at = ? WHERE fingerprint = ?`, now.Unix(), fingerprint)
		if err != nil {
			return fmt.Errorf("sshkey: touch last_used_at: %w", err)
		}
		return nil
	})
}

// isUniqueViolation reports whether err is a SQLite UNIQUE-constraint failure.
// modernc.org/sqlite reports these as "constraint failed: UNIQUE constraint
// failed: ssh_keys.fingerprint" in the error text. We sniff for the canonical
// substring rather than importing the driver's error type so the rest of the
// package stays driver-agnostic.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
