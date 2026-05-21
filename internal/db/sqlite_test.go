package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// openTempDB opens a fresh DB in a per-test temp dir and registers cleanup.
func openTempDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "forge.db")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return d
}

// tableColumns returns the column names for table (in declaration order).
func tableColumns(t *testing.T, d *sql.DB, table string) []string {
	t.Helper()
	rows, err := d.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan PRAGMA table_info(%s): %v", table, err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	return cols
}

func TestOpen_CreatesTablesWithExpectedColumns(t *testing.T) {
	d := openTempDB(t)

	wantUsers := []string{
		"id", "slack_user_id", "slack_team_id", "email",
		"name", "avatar_url", "roles", "created_at", "last_login_at",
	}
	gotUsers := tableColumns(t, d.Reader, "users")
	if !equalSlices(gotUsers, wantUsers) {
		t.Errorf("users columns = %v, want %v", gotUsers, wantUsers)
	}

	wantSessions := []string{
		"id", "user_id", "created_at", "last_seen_at",
		"expires_at", "user_agent", "ip",
	}
	gotSessions := tableColumns(t, d.Reader, "sessions")
	if !equalSlices(gotSessions, wantSessions) {
		t.Errorf("sessions columns = %v, want %v", gotSessions, wantSessions)
	}

	// The expires_at index from migration 0002 should exist.
	var idxName string
	err := d.Reader.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='sessions_expires'`,
	).Scan(&idxName)
	if err != nil {
		t.Errorf("sessions_expires index lookup: %v", err)
	}
}

func TestOpen_MigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forge.db")
	ctx := context.Background()

	d1, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Capture the migration version after first Open.
	var v1 int64
	if err := d1.Reader.QueryRow(
		`SELECT MAX(version_id) FROM goose_db_version`,
	).Scan(&v1); err != nil {
		t.Fatalf("read version after first Open: %v", err)
	}
	if err := d1.Close(); err != nil {
		t.Fatalf("close after first Open: %v", err)
	}

	// Re-open: should be a no-op.
	d2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer d2.Close()
	var v2 int64
	if err := d2.Reader.QueryRow(
		`SELECT MAX(version_id) FROM goose_db_version`,
	).Scan(&v2); err != nil {
		t.Fatalf("read version after second Open: %v", err)
	}
	if v1 != v2 {
		t.Errorf("migration version changed across reopens: %d -> %d", v1, v2)
	}
	if v1 < 2 {
		t.Errorf("expected at least 2 migrations applied, got version %d", v1)
	}
}

func TestOpen_NonexistentDirectoryReturnsErrorNamingPath(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "does-not-exist", "forge.db")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Open(ctx, bogus)
	if err == nil {
		t.Fatalf("expected error opening %q, got nil", bogus)
	}
	if !strings.Contains(err.Error(), bogus) {
		t.Errorf("error %q does not mention bad path %q", err.Error(), bogus)
	}
}

func TestOpen_EmptyPathReturnsError(t *testing.T) {
	_, err := Open(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestWriterReader_WALVisibility writes via the writer and reads via the
// reader pool, confirming that committed writes are visible to a separate
// read-only connection without contention.
func TestWriterReader_WALVisibility(t *testing.T) {
	d := openTempDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	res, err := d.Writer.ExecContext(ctx, `
		INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "U001", "T123", "alice@example.com", "Alice", "https://example.com/a.png", "", now, now)
	if err != nil {
		t.Fatalf("writer insert: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	var (
		gotEmail string
		gotName  string
	)
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT email, name FROM users WHERE id = ?`, id,
	).Scan(&gotEmail, &gotName); err != nil {
		t.Fatalf("reader query: %v", err)
	}
	if gotEmail != "alice@example.com" || gotName != "Alice" {
		t.Errorf("reader saw email=%q name=%q, want alice@example.com / Alice", gotEmail, gotName)
	}
}

// TestWriter_ReadOnlyEnforced verifies the reader pool refuses writes,
// guarding against accidental misuse of d.Reader for mutations.
func TestWriter_ReadOnlyEnforced(t *testing.T) {
	d := openTempDB(t)
	_, err := d.Reader.ExecContext(context.Background(),
		`INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
		 VALUES ('U', 'T', 'e', 'n', 'a', '', 0, 0)`)
	if err == nil {
		t.Fatal("expected reader insert to fail (mode=ro), got nil error")
	}
}

// TestConcurrentInserts simulates 10 goroutines hammering the writer pool.
// With MaxOpenConns=1 and busy_timeout=5000, all inserts should succeed with
// no SQLITE_BUSY errors.
func TestConcurrentInserts(t *testing.T) {
	d := openTempDB(t)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := d.Writer.ExecContext(ctx, `
				INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`,
				fmt.Sprintf("U%03d", i),
				"T123",
				fmt.Sprintf("u%d@example.com", i),
				fmt.Sprintf("User %d", i),
				"https://example.com/avatar.png",
				"",
				time.Now().Unix(),
				time.Now().Unix(),
			)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent insert failed: %v", err)
	}

	var count int
	if err := d.Reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != n {
		t.Errorf("got %d users, want %d", count, n)
	}
}

// TestWithWriteTx_Basic verifies the WithWriteTx helper commits on nil
// return and rolls back on error.
func TestWithWriteTx_Basic(t *testing.T) {
	d := openTempDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Commit path.
	err := d.WithWriteTx(ctx, func(tx Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
			VALUES ('U_TX1', 'T123', 'tx1@example.com', 'TX One', 'a', '', ?, ?)
		`, now, now)
		return err
	})
	if err != nil {
		t.Fatalf("WithWriteTx commit: %v", err)
	}

	var count int
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE slack_user_id='U_TX1'`).Scan(&count); err != nil {
		t.Fatalf("post-commit count: %v", err)
	}
	if count != 1 {
		t.Errorf("post-commit count = %d, want 1", count)
	}

	// Rollback path.
	sentinel := errors.New("force rollback")
	err = d.WithWriteTx(ctx, func(tx Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
			VALUES ('U_TX2', 'T123', 'tx2@example.com', 'TX Two', 'a', '', ?, ?)
		`, now, now)
		if err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithWriteTx rollback returned %v, want %v", err, sentinel)
	}

	if err := d.Reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE slack_user_id='U_TX2'`).Scan(&count); err != nil {
		t.Fatalf("post-rollback count: %v", err)
	}
	if count != 0 {
		t.Errorf("post-rollback count = %d, want 0", count)
	}
}

// TestWithWriteTx_ConcurrentSelectThenUpdate exercises the BEGIN IMMEDIATE
// guarantee. Two goroutines both SELECT a row and then UPDATE it inside a
// WithWriteTx. Without BEGIN IMMEDIATE (or our MaxOpenConns=1 serialization),
// one would hit SQLITE_BUSY_SNAPSHOT on the upgrade.
//
// This is the F1 verification from the doc review: confirms the helper
// actually prevents the upgrade-deadlock pathway, even when many goroutines
// race on it.
func TestWithWriteTx_ConcurrentSelectThenUpdate(t *testing.T) {
	d := openTempDB(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Seed a single row that both goroutines will contend over.
	if _, err := d.Writer.ExecContext(ctx, `
		INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
		VALUES ('U_RACE', 'T123', 'race@example.com', 'Race', 'a', '', ?, ?)
	`, now, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var userID int64
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT id FROM users WHERE slack_user_id='U_RACE'`).Scan(&userID); err != nil {
		t.Fatalf("look up seeded id: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := d.WithWriteTx(ctx, func(tx Tx) error {
				// SELECT inside the transaction, then UPDATE based on what we
				// read — the classic shape that would hit SQLITE_BUSY_SNAPSHOT
				// under DEFERRED isolation with multiple concurrent writers.
				var current int64
				if err := tx.QueryRowContext(ctx,
					`SELECT last_login_at FROM users WHERE id = ?`, userID,
				).Scan(&current); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx,
					`UPDATE users SET last_login_at = ? WHERE id = ?`, current+1, userID)
				return err
			})
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("WithWriteTx contention failure: %v", err)
	}

	// Every successful WithWriteTx incremented last_login_at by one, so the
	// final value should equal the seed value plus the number of goroutines.
	var got int64
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT last_login_at FROM users WHERE id = ?`, userID).Scan(&got); err != nil {
		t.Fatalf("final read: %v", err)
	}
	want := now + int64(n)
	if got != want {
		t.Errorf("last_login_at = %d, want %d (lost updates indicate the contention model broke)", got, want)
	}
}

// TestClose_IsIdempotentOnError verifies Close returns sensibly even on
// double-close — important because main.go's defer runs even when Open
// partially failed (though in our codepath that branch already closed).
func TestClose_DoubleCloseIsSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forge.db")
	d, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close on database/sql is safe (returns an error but doesn't
	// panic). We only care that no panic occurs.
	_ = d.Close()
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
