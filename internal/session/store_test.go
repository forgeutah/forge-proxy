package session

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
)

// openTempDB opens a fresh DB in a per-test temp dir and registers cleanup.
// Returns the DB; callers should not close it manually (cleanup handles it).
func openTempDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "forge.db")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = d.Close()
	})
	return d
}

// seedUser inserts a row in the users table and returns its id. Sessions
// reference users(id) with ON DELETE CASCADE — without a real user row, the
// foreign key on sessions blocks our inserts.
func seedUser(t *testing.T, d *db.DB, slackID string) int64 {
	t.Helper()
	now := time.Now().Unix()
	res, err := d.Writer.ExecContext(context.Background(), `
		INSERT INTO users (slack_user_id, slack_team_id, email, name, avatar_url, roles, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, slackID, "T123", slackID+"@example.com", slackID, "https://example.com/a.png", "", now, now)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

// fixedClock returns a closure that yields successive times when called. Tests
// drive time by replacing it after each call. The session.Store treats Now as
// a pure source of time, so each call observes whatever the test last set.
type fixedClock struct {
	t time.Time
}

func (f *fixedClock) now() time.Time { return f.t }
func (f *fixedClock) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

// defaultOpts builds an Options struct with the production defaults
// (30-day absolute, 14-day idle) and a controllable clock.
func defaultOpts(c *fixedClock) Options {
	return Options{
		Lifetime:     30 * 24 * time.Hour,
		IdleTimeout:  14 * 24 * time.Hour,
		CookieDomain: ".forgeutah.tech",
		Now:          c.now,
	}
}

// TestCreate_ReturnsBase64URLIDWithoutPaddingAndStoresRow exercises the
// session-ID-shape promise: 32 random bytes encoded with base64.RawURLEncoding
// yields exactly 43 characters with no '=' padding.
func TestCreate_ReturnsBase64URLIDWithoutPaddingAndStoresRow(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_CREATE")

	ctx := context.Background()
	sess, err := store.Create(ctx, userID, "Mozilla/5.0", "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := len(sess.ID); got != 43 {
		t.Errorf("session ID len = %d, want 43", got)
	}
	if strings.Contains(sess.ID, "=") {
		t.Errorf("session ID %q contains base64 padding", sess.ID)
	}
	// base64url alphabet: A-Z a-z 0-9 - _
	for _, r := range sess.ID {
		ok := (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_'
		if !ok {
			t.Errorf("session ID %q contains non-base64url char %q", sess.ID, r)
			break
		}
	}

	// Row should be readable back via the reader pool.
	var (
		gotUserID    int64
		gotUA, gotIP string
	)
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT user_id, user_agent, ip FROM sessions WHERE id = ?`, sess.ID,
	).Scan(&gotUserID, &gotUA, &gotIP); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if gotUserID != userID || gotUA != "Mozilla/5.0" || gotIP != "10.0.0.1" {
		t.Errorf("row mismatch: user=%d ua=%q ip=%q", gotUserID, gotUA, gotIP)
	}
}

// TestCreate_GeneratesUniqueIDs verifies two consecutive Create calls produce
// different session IDs. With 32 random bytes the collision probability is
// astronomical, but the assertion still catches misuse like reusing a buffer.
func TestCreate_GeneratesUniqueIDs(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_UNIQUE")

	ctx := context.Background()
	a, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	b, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}
	if a.ID == b.ID {
		t.Errorf("two Create calls returned the same ID %q", a.ID)
	}
}

// TestGet_ReturnsSessionWhenNotExpired covers the happy path: a freshly
// created session is retrievable and the round-tripped timestamps reflect
// what Create wrote.
func TestGet_ReturnsSessionWhenNotExpired(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_GET")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "ua", "ip")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID mismatch: %q vs %q", got.ID, created.ID)
	}
	if got.UserID != userID {
		t.Errorf("UserID = %d, want %d", got.UserID, userID)
	}
	if !got.CreatedAt.Equal(clk.t) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, clk.t)
	}
	wantExpires := clk.t.Add(14 * 24 * time.Hour)
	if !got.ExpiresAt.Equal(wantExpires) {
		t.Errorf("ExpiresAt = %v, want %v (created + idle)", got.ExpiresAt, wantExpires)
	}
}

// TestGet_ExpiredReturnsErrExpired drives the clock forward past expires_at
// and verifies Get distinguishes "expired" from "missing" — distinct sentinels
// per the plan.
func TestGet_ExpiredReturnsErrExpired(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_EXPIRED")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Jump to one second past expires_at.
	clk.t = created.ExpiresAt.Add(time.Second)

	_, err = store.Get(ctx, created.ID)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("Get past expires_at: got %v, want ErrExpired", err)
	}
}

// TestGet_MissingIDReturnsErrNotFound is the error-path counterpart: a
// session ID we never minted must produce ErrNotFound, not ErrExpired.
func TestGet_MissingIDReturnsErrNotFound(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))

	_, err := store.Get(context.Background(), "this-id-does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing: got %v, want ErrNotFound", err)
	}
	if errors.Is(err, ErrExpired) {
		t.Errorf("Get missing must not collapse to ErrExpired: %v", err)
	}
}

// TestTouch_SlidesExpirationAfter60Seconds verifies the >=60s threshold:
// once enough time has passed, Touch advances both last_seen_at and
// expires_at.
func TestTouch_SlidesExpirationAfter60Seconds(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_TOUCH_SLIDE")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	clk.advance(2 * time.Minute) // > 60s threshold
	if err := store.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get post-touch: %v", err)
	}
	if !got.LastSeenAt.Equal(clk.t) {
		t.Errorf("LastSeenAt = %v, want %v", got.LastSeenAt, clk.t)
	}
	wantExpires := clk.t.Add(14 * 24 * time.Hour)
	if !got.ExpiresAt.Equal(wantExpires) {
		t.Errorf("ExpiresAt = %v, want %v (now + idle)", got.ExpiresAt, wantExpires)
	}
}

// TestTouch_NeverExtendsPastAbsoluteLifetime walks the clock forward in
// two steps so the session stays live through both Touch calls but the
// second Touch would, naively, set expires_at past the absolute cap.
//
// Timeline (Lifetime=2h, IdleTimeout=1h):
//
//	t=0       create:   created_at=0,    last_seen=0,    expires_at=60m
//	t=30m     Touch #1: > 60s, not expired,
//	                    new expires_at = min(30m+60m, 0+120m) = 90m
//	t=80m     Touch #2: > 60s since last_seen=30m, not expired,
//	                    new expires_at = min(80m+60m, 120m) = 120m (clamped!)
//
// The assertion: after Touch #2, expires_at equals created_at + Lifetime
// (the cap), not now + IdleTimeout.
func TestTouch_NeverExtendsPastAbsoluteLifetime(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	opts := Options{
		Lifetime:     2 * time.Hour,
		IdleTimeout:  1 * time.Hour,
		CookieDomain: ".forgeutah.tech",
		Now:          clk.now,
	}
	store := New(d, opts)
	userID := seedUser(t, d, "U_TOUCH_CAP")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	absoluteCap := created.CreatedAt.Add(2 * time.Hour)

	// Touch #1 at t=30m: keeps the session alive past its initial expiry.
	clk.advance(30 * time.Minute)
	if err := store.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch #1: %v", err)
	}

	// Touch #2 at t=80m: 80m+60m = 140m would exceed the 120m absolute cap,
	// so expires_at must clamp.
	clk.advance(50 * time.Minute)
	if err := store.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch #2: %v", err)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.ExpiresAt.Equal(absoluteCap) {
		t.Errorf("ExpiresAt = %v, want %v (clamped to created + lifetime)",
			got.ExpiresAt, absoluteCap)
	}
}

// TestTouch_TwiceWithin60SecondsIsNoOp verifies the throttle: the second call
// must not touch the DB. We assert that last_seen_at after both calls equals
// the value written by the first call, which is the load-bearing observable
// the plan requires.
func TestTouch_TwiceWithin60SecondsIsNoOp(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_TOUCH_THROTTLE")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// First touch: 90s after create, well past the 60s threshold — DOES write.
	clk.advance(90 * time.Second)
	if err := store.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch #1: %v", err)
	}
	firstTouch := clk.t

	// Second touch: 30s later, BELOW the 60s threshold — no-op.
	clk.advance(30 * time.Second)
	if err := store.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch #2: %v", err)
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastSeenAt.Equal(firstTouch) {
		t.Errorf("LastSeenAt = %v, want %v (second Touch must not write)",
			got.LastSeenAt, firstTouch)
	}
}

// TestTouch_ExpiredSessionIsNoOp ensures we never resurrect an expired
// session. Touch on a row whose expires_at is in the past must not extend it
// (and must not return an error — callers don't want extra branching on this).
func TestTouch_ExpiredSessionIsNoOp(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_TOUCH_EXPIRED")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	originalExpires := created.ExpiresAt

	// Jump past expires_at.
	clk.t = originalExpires.Add(time.Hour)
	if err := store.Touch(ctx, created.ID); err != nil {
		t.Fatalf("Touch on expired: %v", err)
	}

	// Read the row directly (Get would refuse to return it).
	var expiresUnix int64
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT expires_at FROM sessions WHERE id = ?`, created.ID,
	).Scan(&expiresUnix); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if expiresUnix != originalExpires.Unix() {
		t.Errorf("expires_at = %d, want %d (Touch must not resurrect expired)",
			expiresUnix, originalExpires.Unix())
	}
}

// TestTouch_ReturnsErrorWhenWriterClosed simulates a writer failure by
// closing the DB before calling Touch. The plan requires the error to
// propagate so callers can log/meter it (but choose not to block the
// request).
func TestTouch_ReturnsErrorWhenWriterClosed(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_TOUCH_FAIL")

	ctx := context.Background()
	created, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Advance past the throttle threshold so Touch would attempt a write.
	clk.advance(2 * time.Minute)

	// Close the DB; subsequent writes must error rather than silently succeed.
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := store.Touch(ctx, created.ID); err == nil {
		t.Error("Touch on closed DB returned nil error")
	}
}

// TestSweep_DeletesExpiredAndReturnsCount creates three sessions — two
// already expired, one still valid — and asserts Sweep removes exactly the
// two and returns 2.
func TestSweep_DeletesExpiredAndReturnsCount(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_SWEEP")

	ctx := context.Background()
	expiredA, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	expiredB, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}

	// Jump to just past the expiry of A and B.
	clk.t = expiredA.ExpiresAt.Add(time.Minute)

	// Live session is created AFTER the jump, so its expires_at is well past now.
	live, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create live: %v", err)
	}

	n, err := store.Sweep(ctx, clk.t)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 2 {
		t.Errorf("Sweep deleted %d, want 2", n)
	}

	if _, err := store.Get(ctx, expiredA.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expiredA after Sweep: %v, want ErrNotFound", err)
	}
	if _, err := store.Get(ctx, expiredB.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expiredB after Sweep: %v, want ErrNotFound", err)
	}
	if _, err := store.Get(ctx, live.ID); err != nil {
		t.Errorf("live after Sweep: %v, want nil", err)
	}
}

// TestDelete_RemovesRow_CoversAE5 is the explicit AE5 store-layer assertion:
// after Delete, Get returns ErrNotFound (not ErrExpired, not a stale row).
// The end-to-end /auth/logout assertion lives in U6.
func TestDelete_RemovesRow_CoversAE5(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	userID := seedUser(t, d, "U_DELETE")

	ctx := context.Background()
	sess, err := store.Create(ctx, userID, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.Get(ctx, sess.ID); err != nil {
		t.Fatalf("pre-Delete Get: %v", err)
	}

	if err := store.Delete(ctx, sess.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Get(ctx, sess.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("post-Delete Get: %v, want ErrNotFound", err)
	}
}

// TestDeleteAllForUser_RemovesEveryRowForUser covers the admin force-logout
// path: deleting by user_id wipes every device's session but leaves other
// users untouched.
func TestDeleteAllForUser_RemovesEveryRowForUser(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, defaultOpts(clk))
	target := seedUser(t, d, "U_TARGET")
	other := seedUser(t, d, "U_OTHER")

	ctx := context.Background()
	t1, err := store.Create(ctx, target, "", "")
	if err != nil {
		t.Fatalf("Create t1: %v", err)
	}
	t2, err := store.Create(ctx, target, "", "")
	if err != nil {
		t.Fatalf("Create t2: %v", err)
	}
	o1, err := store.Create(ctx, other, "", "")
	if err != nil {
		t.Fatalf("Create o1: %v", err)
	}

	if err := store.DeleteAllForUser(ctx, target); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}

	if _, err := store.Get(ctx, t1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("t1 after DeleteAllForUser: %v, want ErrNotFound", err)
	}
	if _, err := store.Get(ctx, t2.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("t2 after DeleteAllForUser: %v, want ErrNotFound", err)
	}
	if _, err := store.Get(ctx, o1.ID); err != nil {
		t.Errorf("o1 after DeleteAllForUser: %v, want nil (other user)", err)
	}
}
