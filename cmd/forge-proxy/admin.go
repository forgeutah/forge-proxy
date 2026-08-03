package main

// Admin CLI subcommand. The same binary that serves traffic also runs admin
// operations: `forge-proxy admin <subcommand> [args]`. main() dispatches on
// os.Args[1] so an operator can `docker exec` (or run the binary directly)
// without a separate tool.
//
// Concurrency note: the admin path opens its own *db.DB pool against the
// same SQLite file as the running server. Both writer pools coordinate via
// SQLite's file-level lock + the `busy_timeout=5000` pragma — a concurrent
// admin write that can't acquire the lock within 5s returns SQLITE_BUSY,
// which surfaces here as an error message advising the operator to retry.
// Read-only subcommands (list-users) never contend with the server.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// adminEnv is the small environment the admin subcommands need. Keeping it
// behind an interface-like struct lets the per-subcommand tests inject a
// pre-built env against a temp DB without round-tripping through config.Load
// (which would force every test to set six required env vars).
type adminEnv struct {
	database *db.DB
	users    *user.Store
	sessions *session.Store
	keys     *sshkey.Store
	stdout   io.Writer
}

// runAdmin is the entry point for the admin subcommand. Returns nil on
// success, non-nil error otherwise. The error is printed by main() before
// os.Exit(1); the surface stays exit-zero on success so the commands compose
// in shell pipelines (e.g. `for u in $(... list-users); do ... force-logout
// $u; done`).
func runAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: forge-proxy admin <subcommand> [args...]\n\nsubcommands:\n  list-users [--match <substring>]\n  set-roles <email> <comma-roles>\n  force-logout <email>\n  force-logout-all\n  ssh-list-keys <email>\n  ssh-remove-key <fingerprint>\n  ssh-force-logout <email>")
	}

	// Build the env up front: every subcommand needs config + DB + stores.
	env, cleanup, err := newAdminEnv(os.Stdout)
	if err != nil {
		return err
	}
	defer cleanup()

	return dispatchAdmin(env, args)
}

// dispatchAdmin runs the subcommand against an already-built env. Pulled
// out of runAdmin so admin_test.go can drive every subcommand against a
// temp DB without round-tripping through config.Load (which would force
// every test to set the full required-env-var set).
func dispatchAdmin(env *adminEnv, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list-users":
		return adminListUsers(env, rest)
	case "set-roles":
		return adminSetRoles(env, rest)
	case "force-logout":
		return adminForceLogout(env, rest)
	case "force-logout-all":
		return adminForceLogoutAll(env, rest)
	case "ssh-list-keys":
		return adminSSHListKeys(env, rest)
	case "ssh-remove-key":
		return adminSSHRemoveKey(env, rest)
	case "ssh-force-logout":
		return adminSSHForceLogout(env, rest)
	default:
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

// newAdminEnv loads config, opens the DB pools, and constructs the user and
// session stores. The returned cleanup closes the DB; callers defer it.
func newAdminEnv(stdout io.Writer) (*adminEnv, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, func() {}, err
	}

	dbCtx, dbCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dbCancel()
	database, err := db.Open(dbCtx, cfg.DBPath)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open db: %w", err)
	}

	env := &adminEnv{
		database: database,
		users:    user.New(database, nil),
		sessions: session.New(database, session.Options{
			Lifetime:     cfg.SessionLifetime,
			IdleTimeout:  cfg.SessionIdleTimeout,
			CookieDomain: cfg.CookieDomain,
		}),
		keys:   sshkey.New(database, nil),
		stdout: stdout,
	}
	cleanup := func() { _ = database.Close() }
	return env, cleanup, nil
}

// adminListUsers prints a tab-separated table of users matching --match
// (or all users, capped at internal/user.defaultSearchLimit, when --match is
// omitted). The leading header line makes the output unambiguous for both
// humans and downstream `awk` / `cut` pipelines.
func adminListUsers(env *adminEnv, args []string) error {
	fs := flag.NewFlagSet("list-users", flag.ContinueOnError)
	fs.SetOutput(env.stdout)
	match := fs.String("match", "", "case-insensitive substring filter against email or name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("list-users: unexpected positional args: %v", fs.Args())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	users, err := env.users.Search(ctx, *match)
	if err != nil {
		return classifyBusy(err)
	}

	// Header row uses the same tab separators as the data rows so the
	// table aligns on standard terminal widths.
	fmt.Fprintln(env.stdout, "id\temail\tname\troles\tlast_login_at")
	for _, u := range users {
		roles := strings.Join(u.Roles, ",")
		fmt.Fprintf(env.stdout, "%d\t%s\t%s\t%s\t%s\n",
			u.ID, u.Email, u.Name, roles, u.LastLoginAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// adminSetRoles validates and writes the new roles for the named user. Role
// validation happens inside user.Store.SetRoles, so a comma- or
// whitespace-containing role name fails fast with a clear error that the
// operator sees on stderr.
func adminSetRoles(env *adminEnv, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: forge-proxy admin set-roles <email> <comma-roles>\n\npass an empty string for <comma-roles> to clear all roles")
	}
	email, rolesArg := args[0], args[1]
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("set-roles: email is required")
	}

	roles := parseRolesArg(rolesArg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := env.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf("set-roles: no user with email %q (try `forge-proxy admin list-users --match %s`)", email, strings.Split(email, "@")[0])
		}
		return classifyBusy(err)
	}

	if err := env.users.SetRoles(ctx, u.ID, roles); err != nil {
		return classifyBusy(err)
	}
	fmt.Fprintf(env.stdout, "set roles for %s (id=%d): [%s]\n", u.Email, u.ID, strings.Join(roles, ","))
	return nil
}

// adminForceLogout deletes every session row for the named user. Used during
// off-boarding: workspace removal does NOT auto-revoke sessions (R5/R6
// trade-off), so this is the operator's manual step.
func adminForceLogout(env *adminEnv, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: forge-proxy admin force-logout <email>")
	}
	email := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := env.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf("force-logout: no user with email %q", email)
		}
		return classifyBusy(err)
	}

	if err := env.sessions.DeleteAllForUser(ctx, u.ID); err != nil {
		return classifyBusy(err)
	}
	fmt.Fprintf(env.stdout, "force-logout: deleted sessions for %s (id=%d)\n", u.Email, u.ID)
	return nil
}

// adminForceLogoutAll deletes every session row. The incident-response
// trigger documented in the README: after a suspected R2 bucket read
// compromise, every session ID becomes a temporary impersonation token, so
// the only safe response is to invalidate every one of them.
func adminForceLogoutAll(env *adminEnv, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: forge-proxy admin force-logout-all (no args)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Direct UPDATE-style delete via the writer pool — we don't need the
	// user-id round-trip since this nukes everything. Routed through
	// WithWriteTx to match the rest of the writer-pool discipline.
	var deleted int64
	if err := env.database.WithWriteTx(ctx, func(tx db.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sessions`)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		deleted = n
		return nil
	}); err != nil {
		return classifyBusy(err)
	}
	fmt.Fprintf(env.stdout, "force-logout-all: deleted %d session(s)\n", deleted)
	return nil
}

// parseRolesArg splits the CLI's comma-roles argument into a slice. An empty
// or whitespace-only input becomes an empty slice — the documented way to
// clear all roles. Per-role trimming is intentional: an operator typing
// "admin, organizer" with a stray space gets the obvious behavior rather
// than a confusing validation error.
func parseRolesArg(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// classifyBusy translates a SQLITE_BUSY-flavored error into a friendlier
// "retry" message. SQLite returns "database is locked" when the
// `busy_timeout=5000` (set in internal/db) elapses without the lock
// becoming available — this is the expected failure mode when the running
// server holds a long-running write while the admin tries to write
// concurrently. Detection is by string match because modernc.org/sqlite
// doesn't export a typed sentinel for the busy condition that survives
// database/sql wrapping.
func classifyBusy(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "database is locked") || strings.Contains(msg, "sqlite_busy") {
		return fmt.Errorf("the database write lock is held by the running server; retry in a few seconds: %w", err)
	}
	return err
}

// --- SSH key administration ---------------------------------------------

// adminSSHListKeys prints every SSH public key registered to the named user.
// Same tab-separated shape as list-users so the two compose in the same
// pipelines.
func adminSSHListKeys(env *adminEnv, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: forge-proxy admin ssh-list-keys <email>")
	}
	email := strings.TrimSpace(args[0])
	if email == "" {
		return fmt.Errorf("ssh-list-keys: email is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := env.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf("ssh-list-keys: no user with email %q (try `forge-proxy admin list-users --match %s`)", email, strings.Split(email, "@")[0])
		}
		return classifyBusy(err)
	}

	keys, err := env.keys.ListByUser(ctx, u.ID)
	if err != nil {
		return classifyBusy(err)
	}

	// Header prints even when there are no keys, so an operator can tell
	// "no keys registered" apart from "command did nothing".
	fmt.Fprintln(env.stdout, "id\tfingerprint\tkey_type\tlabel\tcreated_at\tlast_used_at")
	for _, k := range keys {
		fmt.Fprintf(env.stdout, "%d\t%s\t%s\t%s\t%s\t%s\n",
			k.ID, k.Fingerprint, k.KeyType, k.Label,
			k.CreatedAt.UTC().Format(time.RFC3339),
			formatLastUsed(k.LastUsedAt))
	}
	return nil
}

// formatLastUsed renders a never-used key's zero timestamp as "never"
// rather than year 1, which reads as corruption in a terminal.
func formatLastUsed(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// adminSSHRemoveKey deletes one key by fingerprint. Idempotent: removing a
// fingerprint that is not registered is a no-op that exits zero, mirroring
// force-logout, so off-boarding scripts can run twice without failing.
func adminSSHRemoveKey(env *adminEnv, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: forge-proxy admin ssh-remove-key <fingerprint>\n\nlist fingerprints with `forge-proxy admin ssh-list-keys <email>`")
	}
	fingerprint := strings.TrimSpace(args[0])
	if fingerprint == "" {
		return fmt.Errorf("ssh-remove-key: fingerprint is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	k, err := env.keys.Get(ctx, fingerprint)
	if err != nil {
		if errors.Is(err, sshkey.ErrNotFound) {
			fmt.Fprintf(env.stdout, "ssh-remove-key: no key with fingerprint %q; nothing to do\n", fingerprint)
			return nil
		}
		return classifyBusy(err)
	}

	if err := env.keys.Remove(ctx, fingerprint); err != nil {
		if errors.Is(err, sshkey.ErrNotFound) {
			fmt.Fprintf(env.stdout, "ssh-remove-key: no key with fingerprint %q; nothing to do\n", fingerprint)
			return nil
		}
		return classifyBusy(err)
	}
	fmt.Fprintf(env.stdout, "removed key %s (id=%d, user_id=%d)\n", fingerprint, k.ID, k.UserID)
	return nil
}

// adminSSHForceLogout reports why it cannot do what its name suggests.
//
// The live-session registry is in-memory inside the running server process,
// and admin subcommands run as a *separate* process against the same SQLite
// file. There is no IPC between them, so this command can never reach the
// sessions it would need to close. Rather than print "closed 0 sessions" and
// exit zero -- which reads as "there were none" and would let an operator
// believe an off-boarding completed -- it fails loudly and names the two
// things that do work.
func adminSSHForceLogout(env *adminEnv, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: forge-proxy admin ssh-force-logout <email>")
	}
	email := strings.TrimSpace(args[0])
	if email == "" {
		return fmt.Errorf("ssh-force-logout: email is required")
	}

	// Resolve the user anyway: a typo'd email should surface as a typo,
	// not as the process-boundary message.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := env.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return fmt.Errorf("ssh-force-logout: no user with email %q", email)
		}
		return classifyBusy(err)
	}

	return fmt.Errorf(
		"ssh-force-logout: cannot close live SSH sessions for %s (id=%d) from a separate process.\n\n"+
			"Active SSH sessions live in the running server's memory, and this command runs as its own\n"+
			"process, so it has no way to reach them.\n\n"+
			"To revoke SSH access:\n"+
			"  1. forge-proxy admin ssh-list-keys %s\n"+
			"  2. forge-proxy admin ssh-remove-key <fingerprint>   # blocks all future connections\n"+
			"  3. restart forge-proxy to drop sessions that are still open",
		u.Email, u.ID, u.Email)
}
