package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
)

// ErrNotFound is returned by lookup methods when no row matches the given key.
// Callers (the auth handlers in U6, the admin CLI in U9) distinguish "user
// missing entirely" from other errors so they can choose the right response —
// a forced logout vs. a generic 500.
var ErrNotFound = errors.New("user: not found")

// roleNameRe is the canonical role-name shape: one or more characters from
// A-Z, a-z, 0-9, underscore, or hyphen. The constraint is load-bearing
// because roles are persisted as a single comma-separated TEXT column; any
// character outside this set could either (a) be a separator (',') causing
// one DB value to silently split into two roles, or (b) be whitespace that
// would round-trip differently between Slack and the proxy. Defense in
// depth: SetRoles enforces this on every write, and Roles validates each
// non-empty entry on read — so a hand-edited bad value surfaces as an
// error from Roles rather than a silently mis-parsed role list.
var roleNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// OIDCClaims carries the verified subset of an OpenID Connect ID token that
// the user store needs to provision or refresh a row. U6 (sign-in handler)
// extracts these fields from a Slack OIDC token, validates the issuer and
// audience, and then hands the result here. Keeping this struct in the user
// package (rather than coupling to a Slack-specific token type) lets U5 stay
// pure data-access and lets future identity providers reuse the upsert path.
type OIDCClaims struct {
	// SlackUserID is the stable per-workspace user ID ("U…"). Used as the
	// unique key on the users table.
	SlackUserID string
	// SlackTeamID is the workspace ID ("T…"). Stored but not part of the
	// uniqueness key — a workspace move would change this value while the
	// integer id remains stable.
	SlackTeamID string
	// Email is the verified email claim. Refreshed on every sign-in so
	// downstream apps see the live address.
	Email string
	// Name is the user's display name. Refreshed on every sign-in.
	Name string
	// AvatarURL is the URL of the user's profile image. Refreshed on every
	// sign-in.
	AvatarURL string
}

// User is one row of the users table, decoded into Go values. Timestamps in
// the DB are stored as Unix seconds (matching the U3 schema's INTEGER
// columns); we convert at the boundary so the rest of the application
// works in time.Time.
type User struct {
	ID          int64
	SlackUserID string
	SlackTeamID string
	Email       string
	Name        string
	AvatarURL   string
	Roles       []string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// Store owns the users table. It exposes lookup by id / Slack id,
// auto-provisioning from OIDC claims, and role read/write. Writes go through
// the writer pool inside WithWriteTx (BEGIN IMMEDIATE); reads use the reader
// pool. The Store is safe for concurrent use.
type Store struct {
	db  *db.DB
	now func() time.Time
}

// New constructs a Store. The now hook lets tests drive time deterministically;
// nil defaults to time.Now so production wiring stays a one-liner.
func New(database *db.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: database, now: now}
}

// UpsertFromOIDC inserts a fresh row for an unseen slack_user_id or, if the
// user already exists, refreshes their email, name, avatar_url, and
// last_login_at. The roles column is intentionally NEVER touched on the
// update path — role assignment is an admin operation (see SetRoles and the
// `forge-proxy admin set-roles` CLI) and must survive ordinary sign-ins.
//
// Email is refreshed on every sign-in to honour R6's live-data promise: if
// a user changes their Slack email, the next sign-in propagates it to the
// proxy and from there to downstream apps. Upstream apps that need a
// persistent join key MUST use the integer X-Forge-User-Id header (stable
// for the life of the user row), not X-Forge-Email (which can change
// underneath them between requests).
//
// The whole operation runs inside WithWriteTx so an interrupted upsert
// never leaves a half-populated row visible to readers.
func (s *Store) UpsertFromOIDC(ctx context.Context, claims OIDCClaims) (*User, error) {
	now := s.now().UTC()
	nowUnix := now.Unix()

	var u *User
	err := s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		// Try to load the existing row first. Doing the SELECT inside the
		// IMMEDIATE-locked transaction prevents a concurrent upsert from
		// flipping the row's existence between our check and our write.
		var (
			id          int64
			slackTeamID string
			email, name string
			avatarURL   string
			rolesRaw    string
			createdAt   int64
			lastLoginAt int64
		)
		err := tx.QueryRowContext(ctx, `
			SELECT id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at
			FROM users
			WHERE slack_user_id = ?
		`, claims.SlackUserID).Scan(&id, &slackTeamID, &email, &name, &avatarURL, &rolesRaw, &createdAt, &lastLoginAt)

		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Brand-new user: insert with an empty roles list (per AE2 and
			// R4 — no manual approval, no implicit grants).
			res, insErr := tx.ExecContext(ctx, `
				INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
				VALUES (?, ?, ?, ?, ?, '', ?, ?)
			`, claims.SlackUserID, claims.SlackTeamID, claims.Email, claims.Name, claims.AvatarURL, nowUnix, nowUnix)
			if insErr != nil {
				return fmt.Errorf("user: insert: %w", insErr)
			}
			newID, idErr := res.LastInsertId()
			if idErr != nil {
				return fmt.Errorf("user: last insert id: %w", idErr)
			}
			u = &User{
				ID:          newID,
				SlackUserID: claims.SlackUserID,
				SlackTeamID: claims.SlackTeamID,
				Email:       claims.Email,
				Name:        claims.Name,
				AvatarURL:   claims.AvatarURL,
				Roles:       []string{},
				CreatedAt:   now,
				LastLoginAt: now,
			}
			return nil

		case err != nil:
			return fmt.Errorf("user: select: %w", err)
		}

		// Existing user: refresh profile fields and last_login_at,
		// preserve roles and created_at. Slack team id can shift (extremely
		// rare, but possible across workspace renames) — refresh it too.
		if _, execErr := tx.ExecContext(ctx, `
			UPDATE users
			SET slack_team_id = ?, email = ?, name = ?, avatar_url = ?, last_login_at = ?
			WHERE id = ?
		`, claims.SlackTeamID, claims.Email, claims.Name, claims.AvatarURL, nowUnix, id); execErr != nil {
			return fmt.Errorf("user: update: %w", execErr)
		}

		roles, parseErr := parseRoles(rolesRaw)
		if parseErr != nil {
			return parseErr
		}
		u = &User{
			ID:          id,
			SlackUserID: claims.SlackUserID,
			SlackTeamID: claims.SlackTeamID,
			Email:       claims.Email,
			Name:        claims.Name,
			AvatarURL:   claims.AvatarURL,
			Roles:       roles,
			CreatedAt:   time.Unix(createdAt, 0).UTC(),
			LastLoginAt: now,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Get fetches the user with the given id via the reader pool. Returns
// ErrNotFound (not a wrapped sql.ErrNoRows) when no row exists — callers
// branch on the sentinel.
func (s *Store) Get(ctx context.Context, id int64) (*User, error) {
	return s.queryOne(ctx, `
		SELECT id, slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at
		FROM users
		WHERE id = ?
	`, id)
}

// GetBySlackID fetches the user with the given Slack ID via the reader pool.
// Returns ErrNotFound when no row exists.
func (s *Store) GetBySlackID(ctx context.Context, slackUserID string) (*User, error) {
	return s.queryOne(ctx, `
		SELECT id, slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at
		FROM users
		WHERE slack_user_id = ?
	`, slackUserID)
}

// queryOne is the shared scan path for the two Get variants. Keeping it in
// one place means the column ordering, time zone handling, and ErrNotFound
// translation can't drift between lookups.
func (s *Store) queryOne(ctx context.Context, query string, arg any) (*User, error) {
	var (
		u             User
		rolesRaw      string
		createdAtSec  int64
		lastLoginUnix int64
	)
	err := s.db.Reader.QueryRowContext(ctx, query, arg).Scan(
		&u.ID, &u.SlackUserID, &u.SlackTeamID, &u.Email, &u.Name, &u.AvatarURL,
		&rolesRaw, &createdAtSec, &lastLoginUnix,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user: select: %w", err)
	}
	roles, parseErr := parseRoles(rolesRaw)
	if parseErr != nil {
		return nil, parseErr
	}
	u.Roles = roles
	u.CreatedAt = time.Unix(createdAtSec, 0).UTC()
	u.LastLoginAt = time.Unix(lastLoginUnix, 0).UTC()
	return &u, nil
}

// Roles returns the parsed roles list for the given user id. Reads go
// through the reader pool — the request hot path calls this on every
// proxied request (R6) and we don't want it serialized behind writes.
//
// Parsing behaviour (defence in depth; see roleNameRe doc):
//   - empty column → empty slice (not []string{""})
//   - comma-only / whitespace-only column → empty slice (corrupt entries
//     are dropped silently rather than failing the request)
//   - any non-empty entry that doesn't match the role-name regex → error
//
// This matches U5's "either a clean slice (empty entries dropped) or a
// validation error" choice: drop empty entries silently, but surface a
// genuinely malformed role as a hard error so it can't escape into a
// proxied request header.
func (s *Store) Roles(ctx context.Context, id int64) ([]string, error) {
	var rolesRaw string
	err := s.db.Reader.QueryRowContext(ctx, `SELECT roles FROM users WHERE id = ?`, id).Scan(&rolesRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user: select roles: %w", err)
	}
	return parseRoles(rolesRaw)
}

// SetRoles validates every role name against roleNameRe and then writes the
// comma-joined value to the users row. An empty slice is allowed and
// clears the column to ''. Validation runs before the transaction starts
// so a bad input never even acquires the writer lock.
func (s *Store) SetRoles(ctx context.Context, id int64, roles []string) error {
	for _, r := range roles {
		if !roleNameRe.MatchString(r) {
			return fmt.Errorf("user: invalid role name %q: must match %s", r, roleNameRe.String())
		}
	}
	joined := strings.Join(roles, ",")

	return s.db.WithWriteTx(ctx, func(tx db.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET roles = ? WHERE id = ?`, joined, id)
		if err != nil {
			return fmt.Errorf("user: update roles: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("user: rows-affected: %w", err)
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// parseRoles is the single source of truth for splitting a TEXT roles
// column into a clean []string. Empty / whitespace-only entries are
// dropped (a malformed-but-recoverable DB value should not break sign-in);
// genuinely invalid role names return an error so a corrupted row cannot
// silently inject something like "admin manager" into a downstream
// X-Forge-Roles header.
func parseRoles(raw string) ([]string, error) {
	if raw == "" {
		return []string{}, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if !roleNameRe.MatchString(trimmed) {
			return nil, fmt.Errorf("user: invalid role name %q in stored value", trimmed)
		}
		out = append(out, trimmed)
	}
	return out, nil
}
