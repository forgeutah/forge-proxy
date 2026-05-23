package sshkey

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
)

// openTempDB opens a fresh DB in a per-test temp dir and registers cleanup.
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
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// seedUser inserts a row in users so ssh_keys.user_id FK is satisfied.
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

// fixedClock yields a controllable wall clock for the store.
type fixedClock struct {
	t time.Time
}

func (f *fixedClock) now() time.Time { return f.t }
func (f *fixedClock) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

const fpAlice = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const fpBob = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// TestAdd_StoresAndGet exercises the happy path: insert + read-back returns
// the same row, with LastUsedAt zero (NULL column).
func TestAdd_StoresAndGet(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := New(d, clk.now)
	uid := seedUser(t, d, "U_ADD")

	ctx := context.Background()
	added, err := s.Add(ctx, uid, fpAlice, "ssh-ed25519", []byte{1, 2, 3}, "laptop")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if added.ID == 0 {
		t.Fatalf("Add: zero ID")
	}
	if added.UserID != uid || added.Fingerprint != fpAlice {
		t.Errorf("Add returned wrong row: %+v", added)
	}
	if !added.LastUsedAt.IsZero() {
		t.Errorf("Add: LastUsedAt = %v, want zero", added.LastUsedAt)
	}

	got, err := s.Get(ctx, fpAlice)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != added.ID || got.UserID != uid {
		t.Errorf("Get returned wrong row: %+v", got)
	}
	if got.KeyType != "ssh-ed25519" || got.Label != "laptop" {
		t.Errorf("Get fields wrong: type=%q label=%q", got.KeyType, got.Label)
	}
	if string(got.PublicKey) != string([]byte{1, 2, 3}) {
		t.Errorf("Get: PublicKey = %v, want [1 2 3]", got.PublicKey)
	}
	if !got.CreatedAt.Equal(clk.now()) {
		t.Errorf("Get: CreatedAt = %v, want %v", got.CreatedAt, clk.now())
	}
	if !got.LastUsedAt.IsZero() {
		t.Errorf("Get: LastUsedAt = %v, want zero", got.LastUsedAt)
	}
}

// TestAdd_DuplicateFingerprintReturnsErrFingerprintTaken proves the UNIQUE
// constraint on fingerprint is wrapped into the documented sentinel. This is
// the enrollment-race fence: if two parallel TOFU flows try to bind the same
// public key to two different users, only one wins.
func TestAdd_DuplicateFingerprintReturnsErrFingerprintTaken(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := New(d, clk.now)
	uid1 := seedUser(t, d, "U_DUP1")
	uid2 := seedUser(t, d, "U_DUP2")

	ctx := context.Background()
	if _, err := s.Add(ctx, uid1, fpAlice, "ssh-ed25519", []byte{1}, ""); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	_, err := s.Add(ctx, uid2, fpAlice, "ssh-ed25519", []byte{2}, "")
	if !errors.Is(err, ErrFingerprintTaken) {
		t.Fatalf("second Add err = %v, want ErrFingerprintTaken", err)
	}
}

// TestGet_UnknownFingerprintReturnsErrNotFound proves the sentinel mapping is
// in place — the SSH auth callback branches on this exact error to fall
// through to KBI enrollment.
func TestGet_UnknownFingerprintReturnsErrNotFound(t *testing.T) {
	d := openTempDB(t)
	s := New(d, nil)

	_, err := s.Get(context.Background(), fpAlice)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get err = %v, want ErrNotFound", err)
	}
}

// TestTouchLastUsed_UpdatesTimestamp covers the auth-callback hot path that
// stamps last_used_at on every successful publickey authn.
func TestTouchLastUsed_UpdatesTimestamp(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := New(d, clk.now)
	uid := seedUser(t, d, "U_TOUCH")

	ctx := context.Background()
	if _, err := s.Add(ctx, uid, fpAlice, "ssh-ed25519", []byte{0xAA}, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}

	clk.advance(time.Hour)
	if err := s.TouchLastUsed(ctx, fpAlice); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}

	got, err := s.Get(ctx, fpAlice)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastUsedAt.Equal(clk.now()) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, clk.now())
	}
}

// TestTouchLastUsed_UnknownFingerprintIsNoop documents the silent-no-op
// behaviour. Auth callback already validated via Get; we don't surface the
// same "no such key" twice.
func TestTouchLastUsed_UnknownFingerprintIsNoop(t *testing.T) {
	d := openTempDB(t)
	s := New(d, nil)
	if err := s.TouchLastUsed(context.Background(), fpAlice); err != nil {
		t.Fatalf("TouchLastUsed on missing: %v", err)
	}
}

// TestListByUser_ReturnsAllKeysOldestFirst covers the multi-key-per-user case
// and proves the ordering contract used by the admin CLI.
func TestListByUser_ReturnsAllKeysOldestFirst(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := New(d, clk.now)
	uid := seedUser(t, d, "U_LIST")

	ctx := context.Background()
	if _, err := s.Add(ctx, uid, fpAlice, "ssh-ed25519", []byte{1}, "first"); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	clk.advance(time.Second)
	if _, err := s.Add(ctx, uid, fpBob, "ssh-ed25519", []byte{2}, "second"); err != nil {
		t.Fatalf("second Add: %v", err)
	}

	keys, err := s.ListByUser(ctx, uid)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d, want 2", len(keys))
	}
	if keys[0].Fingerprint != fpAlice || keys[1].Fingerprint != fpBob {
		t.Errorf("ordering: got %s, %s; want %s, %s", keys[0].Fingerprint, keys[1].Fingerprint, fpAlice, fpBob)
	}
}

// TestListByUser_UnknownUserReturnsEmpty proves empty-list, not nil.
func TestListByUser_UnknownUserReturnsEmpty(t *testing.T) {
	d := openTempDB(t)
	s := New(d, nil)

	keys, err := s.ListByUser(context.Background(), 99999)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if keys == nil {
		t.Errorf("keys = nil, want empty slice")
	}
	if len(keys) != 0 {
		t.Errorf("len(keys) = %d, want 0", len(keys))
	}
}

// TestRemove_DeletesRow covers the admin ssh-remove-key happy path.
func TestRemove_DeletesRow(t *testing.T) {
	d := openTempDB(t)
	s := New(d, nil)
	uid := seedUser(t, d, "U_REM")

	ctx := context.Background()
	if _, err := s.Add(ctx, uid, fpAlice, "ssh-ed25519", []byte{1}, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Remove(ctx, fpAlice); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := s.Get(ctx, fpAlice); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Remove err = %v, want ErrNotFound", err)
	}
}

// TestRemove_UnknownFingerprintIsIdempotent matches session.Delete's contract:
// off-boarding admin scripts can `ssh-remove-key` blindly without checking
// presence first.
func TestRemove_UnknownFingerprintIsIdempotent(t *testing.T) {
	d := openTempDB(t)
	s := New(d, nil)
	if err := s.Remove(context.Background(), fpAlice); err != nil {
		t.Fatalf("Remove on missing: %v", err)
	}
}

// TestCascade_RemovesKeysWhenUserDeleted covers the ON DELETE CASCADE
// integration. Deleting a user via the existing users-table path drops all of
// their registered SSH keys — required so off-boarding remains a single
// authoritative action.
func TestCascade_RemovesKeysWhenUserDeleted(t *testing.T) {
	d := openTempDB(t)
	s := New(d, nil)
	uid := seedUser(t, d, "U_CASCADE")

	ctx := context.Background()
	if _, err := s.Add(ctx, uid, fpAlice, "ssh-ed25519", []byte{1}, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s.Add(ctx, uid, fpBob, "ssh-ed25519", []byte{2}, ""); err != nil {
		t.Fatalf("Add2: %v", err)
	}

	if _, err := d.Writer.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, uid); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	keys, err := s.ListByUser(ctx, uid)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("after user delete, keys = %d, want 0 (CASCADE failed)", len(keys))
	}
}
