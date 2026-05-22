package user

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// defaultSearchLimit caps the number of rows returned by Search. The admin
// CLI's primary use is "find a user by email" — a tight cap keeps a
// fat-fingered `--match ""` from blasting the entire users table to stdout.
// Operators who genuinely need the full list can either narrow their filter
// or fall back to direct SQL (documented in the README).
const defaultSearchLimit = 100

// Search returns up to defaultSearchLimit users whose email or name contains
// the given substring (case-insensitive). An empty substring matches every
// row — useful for "list everyone" — but still capped at defaultSearchLimit.
// Results are ordered by last_login_at DESC so the most recently active
// users surface first; ties break on id DESC to make the order stable across
// runs.
//
// Reads use the reader pool. Roles are parsed via parseRoles so a corrupted
// stored value surfaces as an error (consistent with Roles / queryOne).
func (s *Store) Search(ctx context.Context, substring string) ([]*User, error) {
	sub := strings.TrimSpace(substring)
	// SQLite LIKE is case-insensitive for ASCII by default. Wrap the
	// substring in % wildcards on both sides; an empty sub becomes "%%"
	// which matches every row.
	pattern := "%" + sub + "%"

	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at
		FROM users
		WHERE email LIKE ? OR name LIKE ?
		ORDER BY last_login_at DESC, id DESC
		LIMIT ?
	`, pattern, pattern, defaultSearchLimit)
	if err != nil {
		return nil, fmt.Errorf("user: search: %w", err)
	}
	defer rows.Close()

	out := make([]*User, 0, 16)
	for rows.Next() {
		var (
			u             User
			rolesRaw      string
			createdAtSec  int64
			lastLoginUnix int64
		)
		if err := rows.Scan(
			&u.ID, &u.SlackUserID, &u.SlackTeamID, &u.Email, &u.Name, &u.AvatarURL,
			&rolesRaw, &createdAtSec, &lastLoginUnix,
		); err != nil {
			return nil, fmt.Errorf("user: search scan: %w", err)
		}
		roles, parseErr := parseRoles(rolesRaw)
		if parseErr != nil {
			return nil, parseErr
		}
		u.Roles = roles
		u.CreatedAt = time.Unix(createdAtSec, 0).UTC()
		u.LastLoginAt = time.Unix(lastLoginUnix, 0).UTC()
		out = append(out, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user: search rows: %w", err)
	}
	return out, nil
}

// GetByEmail fetches the user with the given email address via the reader
// pool. Returns ErrNotFound when no row matches. Used by the admin CLI to
// resolve `set-roles` / `force-logout` arguments before issuing the write.
//
// Email comparison is case-insensitive: Slack normalises addresses but
// operator-typed input may not, and we'd rather match "Clint@x.com" against
// the stored "clint@x.com" than make the admin retry. We use LOWER() rather
// than a COLLATE NOCASE comparison so this code remains portable if the
// column collation ever changes.
func (s *Store) GetByEmail(ctx context.Context, email string) (*User, error) {
	return s.queryOne(ctx, `
		SELECT id, slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at
		FROM users
		WHERE LOWER(email) = LOWER(?)
	`, strings.TrimSpace(email))
}
