package user

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/forgeutah/forge-proxy/internal/db"
)

// openTempDB opens a fresh DB in a per-test temp dir and registers cleanup.
// Mirrors the helper in the session package so the two test suites stay
// recognisably similar.
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

// fixedClock yields a controllable time for tests. The user.Store reads now
// on each call, so advancing the underlying time field is enough to make
// the next UpsertFromOIDC observe a new "now".
type fixedClock struct {
	t time.Time
}

func (f *fixedClock) now() time.Time { return f.t }
func (f *fixedClock) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

// sampleClaims returns an OIDCClaims with predictable values; tests vary one
// or two fields at a time without rebuilding the whole struct.
func sampleClaims() OIDCClaims {
	return OIDCClaims{
		SlackUserID: "U_ALICE",
		SlackTeamID: "T_FORGE",
		Email:       "alice@example.com",
		Name:        "Alice",
		AvatarURL:   "https://example.com/alice.png",
	}
}

// TestUpsertFromOIDC_NewUserInsertsRow exercises the fresh-DB happy path: a
// first upsert creates a row populated from the claims, an empty roles list,
// and created_at == last_login_at == now.
func TestUpsertFromOIDC_NewUserInsertsRow(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	got, err := store.UpsertFromOIDC(context.Background(), sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}
	if got.ID == 0 {
		t.Errorf("ID = 0, want non-zero auto-increment")
	}
	if got.SlackUserID != "U_ALICE" || got.Email != "alice@example.com" {
		t.Errorf("identity mismatch: slack=%q email=%q", got.SlackUserID, got.Email)
	}
	if !got.CreatedAt.Equal(clk.t) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, clk.t)
	}
	if !got.LastLoginAt.Equal(clk.t) {
		t.Errorf("LastLoginAt = %v, want %v", got.LastLoginAt, clk.t)
	}
	if len(got.Roles) != 0 {
		t.Errorf("Roles = %v, want empty", got.Roles)
	}
}

// TestUpsertFromOIDC_NewUserGetsEmptyRoles_CoversAE2 is the explicit
// data-layer assertion for AE2 (R4, R5): a brand-new OIDC sign-in must
// create a row with an empty roles list — no implicit grants, no
// auto-admin. End-to-end first-sign-in coverage lives in U6.
func TestUpsertFromOIDC_NewUserGetsEmptyRoles_CoversAE2(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	// Returned object must have empty roles.
	if len(u.Roles) != 0 {
		t.Fatalf("Roles on returned user = %v, want empty", u.Roles)
	}

	// Read back through the reader pool to confirm the row itself is empty.
	roles, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("Roles in DB = %v, want empty", roles)
	}

	// And the raw column should be the empty string, not " " or "null".
	var rolesRaw string
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT roles FROM users WHERE id = ?`, u.ID,
	).Scan(&rolesRaw); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if rolesRaw != "" {
		t.Errorf("raw roles column = %q, want \"\"", rolesRaw)
	}
}

// TestUpsertFromOIDC_SecondCallUpdatesProfilePreservesRoles is the
// returning-user happy path: profile fields refresh on re-sign-in but the
// admin-managed roles column survives untouched.
func TestUpsertFromOIDC_SecondCallUpdatesProfilePreservesRoles(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	first, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("first UpsertFromOIDC: %v", err)
	}

	// An admin assigns roles between sign-ins.
	if err := store.SetRoles(ctx, first.ID, []string{"admin", "organizer"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}

	// User updates their Slack profile and signs in again.
	clk.advance(24 * time.Hour)
	updated := OIDCClaims{
		SlackUserID: "U_ALICE", // unchanged — this is the join key
		SlackTeamID: "T_FORGE",
		Email:       "alice.new@example.com",
		Name:        "Alice (she/her)",
		AvatarURL:   "https://example.com/alice-v2.png",
	}
	second, err := store.UpsertFromOIDC(ctx, updated)
	if err != nil {
		t.Fatalf("second UpsertFromOIDC: %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("ID changed across upserts: %d -> %d", first.ID, second.ID)
	}
	if second.Email != "alice.new@example.com" {
		t.Errorf("Email = %q, want refreshed value", second.Email)
	}
	if second.Name != "Alice (she/her)" {
		t.Errorf("Name = %q, want refreshed value", second.Name)
	}
	if second.AvatarURL != "https://example.com/alice-v2.png" {
		t.Errorf("AvatarURL = %q, want refreshed value", second.AvatarURL)
	}
	if !second.LastLoginAt.Equal(clk.t) {
		t.Errorf("LastLoginAt = %v, want %v", second.LastLoginAt, clk.t)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt drifted: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	wantRoles := []string{"admin", "organizer"}
	if !slices.Equal(second.Roles, wantRoles) {
		t.Errorf("Roles = %v, want %v (must be preserved across re-sign-in)", second.Roles, wantRoles)
	}

	// Roles should also survive when read independently.
	roles, err := store.Roles(ctx, second.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, wantRoles) {
		t.Errorf("Roles via separate read = %v, want %v", roles, wantRoles)
	}
}

// TestRoles_ParsesCommaSeparated covers the happy path: a comma-joined
// stored value comes back as the expected []string with no extra trimming
// surprises.
func TestRoles_ParsesCommaSeparated(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}
	if err := store.SetRoles(ctx, u.ID, []string{"admin", "organizer"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}

	got, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	want := []string{"admin", "organizer"}
	if !slices.Equal(got, want) {
		t.Errorf("Roles = %v, want %v", got, want)
	}
}

// TestRoles_EmptyColumnReturnsEmptySlice ensures we never expose a
// []string{""} singleton (which would silently inject a blank role into an
// X-Forge-Roles header downstream).
func TestRoles_EmptyColumnReturnsEmptySlice(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	got, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Roles = %v (len %d), want empty slice", got, len(got))
	}
	// Explicit reflect check: must be an empty slice, never a slice of one
	// empty string. The reflect.DeepEqual is the load-bearing assertion
	// because slices.Equal({""}, {""}) and slices.Equal({}, {}) both
	// return true and obscure the bug.
	if reflect.DeepEqual(got, []string{""}) {
		t.Errorf("Roles = []string{\"\"} — must be empty, not a single blank")
	}
}

// TestRoles_WhitespaceEntriesAreTrimmed covers the "tolerant read" half of
// the defence-in-depth contract: a hand-edited DB value with spaces around
// each role still produces clean, regex-valid roles.
func TestRoles_WhitespaceEntriesAreTrimmed(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	// Hand-edit the column to simulate a runbook user.
	if _, err := d.Writer.ExecContext(ctx,
		`UPDATE users SET roles = ? WHERE id = ?`, " admin , organizer ", u.ID,
	); err != nil {
		t.Fatalf("raw update: %v", err)
	}

	got, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	want := []string{"admin", "organizer"}
	if !slices.Equal(got, want) {
		t.Errorf("Roles = %v, want %v", got, want)
	}
}

// TestSetRoles_RejectsRoleContainingComma is the load-bearing validation
// case: a role name with a literal comma must NEVER be accepted because
// the storage format is comma-joined — a successful insert would silently
// turn one role into two.
func TestSetRoles_RejectsRoleContainingComma(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	err = store.SetRoles(ctx, u.ID, []string{"area,manager"})
	if err == nil {
		t.Fatalf("SetRoles with comma returned nil error")
	}
	if !strings.Contains(err.Error(), "invalid role name") {
		t.Errorf("error message %q does not mention invalid role name", err.Error())
	}

	// The row must not have been mutated.
	got, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles after rejected SetRoles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Roles = %v, want empty (write must have been rejected pre-commit)", got)
	}
}

// TestSetRoles_RejectsRoleContainingWhitespace prevents the other obvious
// footgun: a role with a space ("area manager") would round-trip but
// produce an invalid header value at the proxy boundary.
func TestSetRoles_RejectsRoleContainingWhitespace(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	for _, bad := range []string{"area manager", "area\tmanager", "admin "} {
		if err := store.SetRoles(ctx, u.ID, []string{bad}); err == nil {
			t.Errorf("SetRoles(%q) returned nil error", bad)
		}
	}
}

// TestSetRoles_EmptySliceWritesEmptyColumn confirms that clearing roles
// works end-to-end: SetRoles([]) writes '' and Roles round-trips to
// an empty slice.
func TestSetRoles_EmptySliceWritesEmptyColumn(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	// Seed some roles, then clear them.
	if err := store.SetRoles(ctx, u.ID, []string{"admin"}); err != nil {
		t.Fatalf("SetRoles seed: %v", err)
	}
	if err := store.SetRoles(ctx, u.ID, []string{}); err != nil {
		t.Fatalf("SetRoles clear: %v", err)
	}

	var rolesRaw string
	if err := d.Reader.QueryRowContext(ctx,
		`SELECT roles FROM users WHERE id = ?`, u.ID,
	).Scan(&rolesRaw); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if rolesRaw != "" {
		t.Errorf("raw roles column = %q, want \"\"", rolesRaw)
	}

	got, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Roles = %v, want empty", got)
	}
}

// TestRoles_CorruptedDoubleCommaProducesCleanSlice documents the
// corruption-read strategy: a row like "admin,,organizer" or ",," from a
// hand-edit drops empty entries but keeps the regex-valid ones rather than
// failing the read.
func TestRoles_CorruptedDoubleCommaProducesCleanSlice(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	// Pure ",,": no valid entries at all.
	if _, err := d.Writer.ExecContext(ctx,
		`UPDATE users SET roles = ',,' WHERE id = ?`, u.ID,
	); err != nil {
		t.Fatalf("raw update: %v", err)
	}
	got, err := store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles for ',,': %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Roles for ',,' = %v, want empty", got)
	}

	// Mixed: "admin,,organizer" — drop the gap, keep the rest.
	if _, err := d.Writer.ExecContext(ctx,
		`UPDATE users SET roles = 'admin,,organizer' WHERE id = ?`, u.ID,
	); err != nil {
		t.Fatalf("raw update: %v", err)
	}
	got, err = store.Roles(ctx, u.ID)
	if err != nil {
		t.Fatalf("Roles for 'admin,,organizer': %v", err)
	}
	want := []string{"admin", "organizer"}
	if !slices.Equal(got, want) {
		t.Errorf("Roles = %v, want %v", got, want)
	}
}

// TestRoles_CorruptedInvalidNameReturnsError completes the corruption
// contract: empty entries are dropped, but a non-empty entry that fails
// the regex (e.g. "admin manager" hand-edited in) returns an error. The
// HTTP layer in U7 surfaces this as a 500 rather than a silently
// mis-parsed header.
func TestRoles_CorruptedInvalidNameReturnsError(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	u, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	if _, err := d.Writer.ExecContext(ctx,
		`UPDATE users SET roles = 'admin,bad role' WHERE id = ?`, u.ID,
	); err != nil {
		t.Fatalf("raw update: %v", err)
	}

	_, err = store.Roles(ctx, u.ID)
	if err == nil {
		t.Fatalf("Roles on corrupted value returned nil error")
	}
	if !strings.Contains(err.Error(), "invalid role name") {
		t.Errorf("error %q does not mention invalid role name", err.Error())
	}
}

// TestRolesReflectLiveDBUpdate_CoversAE4 is the explicit AE4 (R6)
// data-layer assertion: a manual UPDATE to the roles column is visible to
// the next GetBySlackID / Roles call, without any cache invalidation or
// session re-issue. End-to-end "active session sees new roles" coverage
// lives in U8's proxy-injection tests.
func TestRolesReflectLiveDBUpdate_CoversAE4(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	ctx := context.Background()
	first, err := store.UpsertFromOIDC(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}

	// Sanity check: empty before any external edit.
	got, err := store.Roles(ctx, first.ID)
	if err != nil {
		t.Fatalf("Roles initial: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Roles initial = %v, want empty", got)
	}

	// Operator edits the row directly (the R15 runbook path).
	if _, err := d.Writer.ExecContext(ctx,
		`UPDATE users SET roles = ? WHERE id = ?`, "admin,organizer", first.ID,
	); err != nil {
		t.Fatalf("raw update: %v", err)
	}

	// GetBySlackID sees the new value with no cache priming.
	u, err := store.GetBySlackID(ctx, "U_ALICE")
	if err != nil {
		t.Fatalf("GetBySlackID: %v", err)
	}
	want := []string{"admin", "organizer"}
	if !slices.Equal(u.Roles, want) {
		t.Errorf("GetBySlackID Roles = %v, want %v", u.Roles, want)
	}

	// And Roles() sees it too — both reader-pool paths must agree.
	got, err = store.Roles(ctx, first.ID)
	if err != nil {
		t.Fatalf("Roles after edit: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("Roles after edit = %v, want %v", got, want)
	}
}

// TestGet_MissingIDReturnsErrNotFound covers the error path for the
// integer-keyed lookup. U6 / U7 branch on this sentinel to choose between
// "forced logout" and "internal server error".
func TestGet_MissingIDReturnsErrNotFound(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	_, err := store.Get(context.Background(), 9999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on missing id: got %v, want ErrNotFound", err)
	}
}

// TestGetBySlackID_MissingReturnsErrNotFound is the matching sentinel
// assertion for the Slack-keyed lookup — used by U6 right after token
// verification to decide whether to insert.
func TestGetBySlackID_MissingReturnsErrNotFound(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	_, err := store.GetBySlackID(context.Background(), "U_NEVER_SEEN")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetBySlackID on missing: got %v, want ErrNotFound", err)
	}
}

// TestNew_DefaultsNowToTimeNow ensures the New(db, nil) path stays a
// one-liner for production wiring — without this default, callers would
// silently get a nil-pointer panic on the first upsert.
func TestNew_DefaultsNowToTimeNow(t *testing.T) {
	d := openTempDB(t)
	store := New(d, nil)

	before := time.Now().Add(-time.Second)
	u, err := store.UpsertFromOIDC(context.Background(), sampleClaims())
	if err != nil {
		t.Fatalf("UpsertFromOIDC: %v", err)
	}
	after := time.Now().Add(time.Second)

	if u.CreatedAt.Before(before) || u.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v outside [%v, %v] — Now hook did not default to time.Now", u.CreatedAt, before, after)
	}
}
