package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/sshkey"
	"github.com/forgeutah/forge-proxy/internal/user"
)

// newAdminTestEnv builds an adminEnv against a fresh temp DB. Used by every
// admin_test.go case to bypass config.Load (which would otherwise force
// every test to set the full required-env-var set just to open a DB).
func newAdminTestEnv(t *testing.T) (*adminEnv, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "forge.db")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	database, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	stdout := &bytes.Buffer{}
	env := &adminEnv{
		database: database,
		users:    user.New(database, nil),
		sessions: session.New(database, session.Options{
			Lifetime:    30 * 24 * time.Hour,
			IdleTimeout: 14 * 24 * time.Hour,
		}),
		keys:   sshkey.New(database, nil),
		stdout: stdout,
	}
	return env, stdout
}

// seedUser is a tiny helper that creates a user via the OIDC upsert path.
// Mirrors the production sign-in flow so the tests exercise the same
// constraints (FK-less but otherwise representative).
func seedUser(t *testing.T, env *adminEnv, slackID, email, name string) *user.User {
	t.Helper()
	u, err := env.users.UpsertFromOIDC(context.Background(), user.OIDCClaims{
		SlackUserID: slackID,
		SlackTeamID: "T_FORGE",
		Email:       email,
		Name:        name,
	})
	if err != nil {
		t.Fatalf("UpsertFromOIDC(%s): %v", email, err)
	}
	return u
}

// TestAdmin_ListUsers_EmptyDB documents the zero-row case: header line only.
// The leading header keeps the output machine-readable even with no rows.
func TestAdmin_ListUsers_EmptyDB(t *testing.T) {
	env, stdout := newAdminTestEnv(t)

	if err := dispatchAdmin(env, []string{"list-users"}); err != nil {
		t.Fatalf("dispatchAdmin: %v", err)
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "id\temail\tname\troles\tlast_login_at") {
		t.Errorf("output missing header line: %q", out)
	}
	// Exactly one line (the header) + a trailing newline.
	if got := strings.Count(out, "\n"); got != 1 {
		t.Errorf("line count = %d, want 1 (header only)", got)
	}
}

// TestAdmin_ListUsers_MatchFiltersByEmail pins the --match flag's primary
// use case: filter to a single user by email substring.
func TestAdmin_ListUsers_MatchFiltersByEmail(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	seedUser(t, env, "U_CLINT", "clint@example.com", "Clint B.")
	seedUser(t, env, "U_OTHER", "other@example.com", "Other User")

	if err := dispatchAdmin(env, []string{"list-users", "--match", "clint"}); err != nil {
		t.Fatalf("dispatchAdmin: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "clint@example.com") {
		t.Errorf("output missing clint row: %q", out)
	}
	if strings.Contains(out, "other@example.com") {
		t.Errorf("output should not contain other@example.com: %q", out)
	}
}

// TestAdmin_SetRoles_HappyPath end-to-end checks the most common write path:
// set the roles, then read them back via the store to confirm persistence.
func TestAdmin_SetRoles_HappyPath(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	u := seedUser(t, env, "U_ALICE", "alice@example.com", "Alice")

	if err := dispatchAdmin(env, []string{"set-roles", "alice@example.com", "admin,organizer"}); err != nil {
		t.Fatalf("dispatchAdmin: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "set roles for alice@example.com") {
		t.Errorf("output missing confirmation: %q", out)
	}

	got, err := env.users.Roles(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	want := []string{"admin", "organizer"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Roles = %v, want %v", got, want)
	}
}

// TestAdmin_SetRoles_RejectsRoleWithComma is the load-bearing validation
// case: the underlying store rejects comma-bearing role names, and the
// admin path must surface that as a non-zero exit (an error from
// dispatchAdmin in test terms).
func TestAdmin_SetRoles_RejectsRoleWithComma(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	seedUser(t, env, "U_ALICE", "alice@example.com", "Alice")

	// The CLI parses the second arg by splitting on commas, so a literal
	// comma in a role name is impossible to type — the validation kicks in
	// on the underlying SetRoles for whitespace-containing names. We test
	// the whitespace case here to exercise the same code path.
	err := dispatchAdmin(env, []string{"set-roles", "alice@example.com", "bad role"})
	if err == nil {
		t.Fatalf("dispatchAdmin returned nil, want validation error")
	}
	if !strings.Contains(err.Error(), "invalid role name") {
		t.Errorf("error %q does not mention invalid role name", err.Error())
	}
}

// TestAdmin_SetRoles_NonexistentEmailErrors documents the "no silent
// no-op" requirement: an unknown email produces a clear error rather than
// a successful exit that did nothing.
func TestAdmin_SetRoles_NonexistentEmailErrors(t *testing.T) {
	env, _ := newAdminTestEnv(t)

	err := dispatchAdmin(env, []string{"set-roles", "nobody@example.com", "admin"})
	if err == nil {
		t.Fatalf("dispatchAdmin returned nil, want not-found error")
	}
	if !strings.Contains(err.Error(), "no user with email") {
		t.Errorf("error %q does not mention missing user", err.Error())
	}
}

// TestAdmin_ForceLogout_DeletesOnlyTargetUser checks the off-boarding path's
// blast-radius constraint: only the named user's sessions disappear.
func TestAdmin_ForceLogout_DeletesOnlyTargetUser(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	alice := seedUser(t, env, "U_ALICE", "alice@example.com", "Alice")
	bob := seedUser(t, env, "U_BOB", "bob@example.com", "Bob")

	ctx := context.Background()
	aliceSess, err := env.sessions.Create(ctx, alice.ID, "ua", "1.1.1.1")
	if err != nil {
		t.Fatalf("Create alice session: %v", err)
	}
	bobSess, err := env.sessions.Create(ctx, bob.ID, "ua", "2.2.2.2")
	if err != nil {
		t.Fatalf("Create bob session: %v", err)
	}

	if err := dispatchAdmin(env, []string{"force-logout", "alice@example.com"}); err != nil {
		t.Fatalf("dispatchAdmin: %v", err)
	}

	// Alice's session should be gone, Bob's should still resolve.
	if _, err := env.sessions.Get(ctx, aliceSess.ID); err == nil {
		t.Errorf("alice session still resolves after force-logout")
	}
	if _, err := env.sessions.Get(ctx, bobSess.ID); err != nil {
		t.Errorf("bob session lost after alice force-logout: %v", err)
	}
}

// TestAdmin_ForceLogout_NonexistentEmailErrors mirrors the set-roles case:
// no silent no-op.
func TestAdmin_ForceLogout_NonexistentEmailErrors(t *testing.T) {
	env, _ := newAdminTestEnv(t)

	err := dispatchAdmin(env, []string{"force-logout", "nobody@example.com"})
	if err == nil {
		t.Fatalf("dispatchAdmin returned nil, want not-found error")
	}
}

// TestAdmin_ForceLogoutAll_DeletesEverySession is the incident-response
// path: nuke every session row after a suspected bucket compromise.
func TestAdmin_ForceLogoutAll_DeletesEverySession(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	alice := seedUser(t, env, "U_ALICE", "alice@example.com", "Alice")
	bob := seedUser(t, env, "U_BOB", "bob@example.com", "Bob")

	ctx := context.Background()
	for _, uid := range []int64{alice.ID, bob.ID} {
		if _, err := env.sessions.Create(ctx, uid, "ua", "1.1.1.1"); err != nil {
			t.Fatalf("Create session: %v", err)
		}
	}

	if err := dispatchAdmin(env, []string{"force-logout-all"}); err != nil {
		t.Fatalf("dispatchAdmin: %v", err)
	}

	// The output should report a 2-row deletion.
	if !strings.Contains(stdout.String(), "deleted 2 session(s)") {
		t.Errorf("output = %q, want deleted=2", stdout.String())
	}

	// Verify via raw count — both users should now have zero sessions.
	var count int
	if err := env.database.Reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatalf("raw count: %v", err)
	}
	if count != 0 {
		t.Errorf("sessions remaining = %d, want 0", count)
	}
}

// TestAdmin_SetRoles_EmptyRolesClears documents the "empty string clears"
// contract referenced in the help text: pass "" and all roles drop.
func TestAdmin_SetRoles_EmptyRolesClears(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	u := seedUser(t, env, "U_ALICE", "alice@example.com", "Alice")

	// Seed some roles first so the clear has something to remove.
	if err := dispatchAdmin(env, []string{"set-roles", "alice@example.com", "admin"}); err != nil {
		t.Fatalf("seed set-roles: %v", err)
	}

	if err := dispatchAdmin(env, []string{"set-roles", "alice@example.com", ""}); err != nil {
		t.Fatalf("clear set-roles: %v", err)
	}

	got, err := env.users.Roles(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Roles = %v, want empty", got)
	}
}

// TestAdmin_UnknownSubcommandErrors keeps the dispatcher's error message
// honest: an unknown verb should land at a clear "unknown subcommand"
// rather than a generic usage dump.
func TestAdmin_UnknownSubcommandErrors(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	err := dispatchAdmin(env, []string{"sudo-rm-rf"})
	if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("err = %v, want unknown subcommand", err)
	}
}

// TestAdmin_ParseRolesArg covers the small CLI-side splitter:
// whitespace-trim per entry, drop empty entries, empty input → empty slice.
func TestAdmin_ParseRolesArg(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"   ", []string{}},
		{"admin", []string{"admin"}},
		{"admin,organizer", []string{"admin", "organizer"}},
		{"admin, organizer ", []string{"admin", "organizer"}},
		{",admin,,organizer,", []string{"admin", "organizer"}},
	}
	for _, tc := range cases {
		got := parseRolesArg(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("parseRolesArg(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseRolesArg(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// --- SSH key administration ---------------------------------------------

// seedKey registers an SSH key for a user, mirroring what the enrollment
// flow writes.
func seedKey(t *testing.T, env *adminEnv, userID int64, fingerprint, label string) *sshkey.Key {
	t.Helper()
	k, err := env.keys.Add(context.Background(), userID, fingerprint,
		"ssh-ed25519", []byte("public-key-bytes"), label)
	if err != nil {
		t.Fatalf("keys.Add(%s): %v", fingerprint, err)
	}
	return k
}

func TestAdmin_SSHListKeys_ShowsEveryRegisteredKey(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	u := seedUser(t, env, "U1", "alice@example.com", "Alice")
	seedKey(t, env, u.ID, "SHA256:aaa", "laptop")
	seedKey(t, env, u.ID, "SHA256:bbb", "desktop")

	if err := dispatchAdmin(env, []string{"ssh-list-keys", "alice@example.com"}); err != nil {
		t.Fatalf("ssh-list-keys: %v", err)
	}

	out := stdout.String()
	for _, want := range []string{"fingerprint", "SHA256:aaa", "SHA256:bbb", "laptop", "desktop"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Header + two keys.
	if got := len(strings.Split(strings.TrimSpace(out), "\n")); got != 3 {
		t.Errorf("line count = %d, want 3 (header + 2 keys):\n%s", got, out)
	}
}

func TestAdmin_SSHListKeys_NeverUsedKeyReadsAsNever(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	u := seedUser(t, env, "U1", "alice@example.com", "Alice")
	seedKey(t, env, u.ID, "SHA256:aaa", "laptop")

	if err := dispatchAdmin(env, []string{"ssh-list-keys", "alice@example.com"}); err != nil {
		t.Fatalf("ssh-list-keys: %v", err)
	}
	if !strings.Contains(stdout.String(), "never") {
		t.Errorf("a never-used key should read as \"never\", not a zero timestamp:\n%s", stdout.String())
	}
}

func TestAdmin_SSHListKeys_NoKeysPrintsHeaderOnly(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	seedUser(t, env, "U1", "alice@example.com", "Alice")

	if err := dispatchAdmin(env, []string{"ssh-list-keys", "alice@example.com"}); err != nil {
		t.Fatalf("ssh-list-keys: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); !strings.HasPrefix(got, "id\tfingerprint") ||
		len(strings.Split(got, "\n")) != 1 {
		t.Errorf("want header line only, got:\n%s", got)
	}
}

func TestAdmin_SSHListKeys_NonexistentEmailErrors(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	err := dispatchAdmin(env, []string{"ssh-list-keys", "nobody@example.com"})
	if err == nil {
		t.Fatal("expected an error for an unknown email")
	}
	if !strings.Contains(err.Error(), "no user with email") {
		t.Errorf("error = %v, want a user-not-found message", err)
	}
}

func TestAdmin_SSHRemoveKey_RemovesOnlyThatKey(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	u := seedUser(t, env, "U1", "alice@example.com", "Alice")
	seedKey(t, env, u.ID, "SHA256:aaa", "laptop")
	seedKey(t, env, u.ID, "SHA256:bbb", "desktop")

	if err := dispatchAdmin(env, []string{"ssh-remove-key", "SHA256:aaa"}); err != nil {
		t.Fatalf("ssh-remove-key: %v", err)
	}
	stdout.Reset()
	if err := dispatchAdmin(env, []string{"ssh-list-keys", "alice@example.com"}); err != nil {
		t.Fatalf("ssh-list-keys: %v", err)
	}
	out := stdout.String()
	if strings.Contains(out, "SHA256:aaa") {
		t.Errorf("removed key still listed:\n%s", out)
	}
	if !strings.Contains(out, "SHA256:bbb") {
		t.Errorf("the other key was removed too:\n%s", out)
	}
}

// TestAdmin_SSHRemoveKey_UnknownFingerprintIsIdempotent keeps off-boarding
// scripts re-runnable: removing a key that is already gone must not fail.
func TestAdmin_SSHRemoveKey_UnknownFingerprintIsIdempotent(t *testing.T) {
	env, stdout := newAdminTestEnv(t)
	if err := dispatchAdmin(env, []string{"ssh-remove-key", "SHA256:nonexistent"}); err != nil {
		t.Fatalf("removing an unknown fingerprint should succeed, got: %v", err)
	}
	if !strings.Contains(stdout.String(), "nothing to do") {
		t.Errorf("output should say the key was already absent:\n%s", stdout.String())
	}
}

// TestAdmin_SSHForceLogout_ExplainsProcessBoundary pins the deliberate
// behavior: admin runs in its own process and cannot reach the running
// server's in-memory session registry, so the command must fail loudly
// rather than report zero sessions closed as success.
func TestAdmin_SSHForceLogout_ExplainsProcessBoundary(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	seedUser(t, env, "U1", "alice@example.com", "Alice")

	err := dispatchAdmin(env, []string{"ssh-force-logout", "alice@example.com"})
	if err == nil {
		t.Fatal("expected a non-nil error; reporting success would let an operator " +
			"believe live sessions were closed when they were not")
	}
	for _, want := range []string{"separate process", "ssh-remove-key", "restart"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got:\n%v", want, err)
		}
	}
}

func TestAdmin_SSHForceLogout_NonexistentEmailErrorsAsTypo(t *testing.T) {
	env, _ := newAdminTestEnv(t)
	err := dispatchAdmin(env, []string{"ssh-force-logout", "nobody@example.com"})
	if err == nil {
		t.Fatal("expected an error for an unknown email")
	}
	if !strings.Contains(err.Error(), "no user with email") {
		t.Errorf("an unknown email should surface as a typo, not the process-boundary "+
			"message; got:\n%v", err)
	}
}

func TestAdmin_SSHSubcommands_UsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"ssh-list-keys no args", []string{"ssh-list-keys"}},
		{"ssh-list-keys too many args", []string{"ssh-list-keys", "a@b.c", "extra"}},
		{"ssh-remove-key no args", []string{"ssh-remove-key"}},
		{"ssh-force-logout no args", []string{"ssh-force-logout"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := newAdminTestEnv(t)
			if err := dispatchAdmin(env, tc.args); err == nil {
				t.Error("expected a usage error")
			}
		})
	}
}
