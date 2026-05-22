package user

import (
	"context"
	"errors"
	"testing"
	"time"
)

// seedUsers inserts three users with distinct emails / names / last_login
// timestamps. The fixed-clock pattern keeps last_login_at predictable so the
// ordering assertion in TestSearch_OrdersByLastLoginDESC is deterministic.
func seedUsers(t *testing.T, store *Store, clk *fixedClock) (alice, bob, carol *User) {
	t.Helper()
	ctx := context.Background()

	// Alice signs in first (oldest last_login_at).
	a, err := store.UpsertFromOIDC(ctx, OIDCClaims{
		SlackUserID: "U_ALICE", SlackTeamID: "T_FORGE",
		Email: "alice@example.com", Name: "Alice Admin",
	})
	if err != nil {
		t.Fatalf("upsert alice: %v", err)
	}

	// Bob signs in an hour later.
	clk.advance(time.Hour)
	b, err := store.UpsertFromOIDC(ctx, OIDCClaims{
		SlackUserID: "U_BOB", SlackTeamID: "T_FORGE",
		Email: "bob@example.com", Name: "Bob Builder",
	})
	if err != nil {
		t.Fatalf("upsert bob: %v", err)
	}

	// Carol signs in last (newest last_login_at — so she sorts first).
	clk.advance(time.Hour)
	c, err := store.UpsertFromOIDC(ctx, OIDCClaims{
		SlackUserID: "U_CAROL", SlackTeamID: "T_FORGE",
		Email: "carol@example.com", Name: "Carol Coder",
	})
	if err != nil {
		t.Fatalf("upsert carol: %v", err)
	}
	return a, b, c
}

// TestSearch_EmptySubstringReturnsAll covers the admin CLI's "list everyone"
// path: invoking `forge-proxy admin list-users` with no `--match` flag.
func TestSearch_EmptySubstringReturnsAll(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.Search(context.Background(), "")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
}

// TestSearch_OrdersByLastLoginDESC documents the CLI's UX contract: the
// most-recently-active users sort first so an operator's "find Clint" usually
// hits in the first screen of output.
func TestSearch_OrdersByLastLoginDESC(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.Search(context.Background(), "")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got[0].Email != "carol@example.com" {
		t.Errorf("first = %q, want carol (newest last_login)", got[0].Email)
	}
	if got[2].Email != "alice@example.com" {
		t.Errorf("last = %q, want alice (oldest last_login)", got[2].Email)
	}
}

// TestSearch_MatchesEmailSubstring covers the primary lookup path used by
// the admin CLI: an email fragment narrows to the matching row(s).
func TestSearch_MatchesEmailSubstring(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.Search(context.Background(), "carol")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Email != "carol@example.com" {
		t.Errorf("Email = %q, want carol@example.com", got[0].Email)
	}
}

// TestSearch_MatchesNameSubstring confirms the OR-on-name half of the
// query: a name fragment also produces a hit.
func TestSearch_MatchesNameSubstring(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.Search(context.Background(), "Builder")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Email != "bob@example.com" {
		t.Errorf("Email = %q, want bob@example.com", got[0].Email)
	}
}

// TestSearch_IsCaseInsensitive guards SQLite's LIKE default behavior: the
// operator types "ALICE" and still finds the row with email "alice@…".
func TestSearch_IsCaseInsensitive(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.Search(context.Background(), "ALICE")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].Email != "alice@example.com" {
		t.Errorf("Search(ALICE) = %+v, want a single alice row", got)
	}
}

// TestSearch_NoMatchReturnsEmpty: the zero-result case is a clean empty
// slice rather than a sentinel error — keeps the CLI's loop body trivial.
func TestSearch_NoMatchReturnsEmpty(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.Search(context.Background(), "nobody-here")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestGetByEmail_Found covers the lookup path the admin CLI uses to resolve
// a `set-roles <email>` or `force-logout <email>` argument before writing.
func TestGetByEmail_Found(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.GetByEmail(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if got.Name != "Bob Builder" {
		t.Errorf("Name = %q, want Bob Builder", got.Name)
	}
}

// TestGetByEmail_CaseInsensitive: matching the Search behavior so a
// fat-fingered case mismatch doesn't fail the admin write outright.
func TestGetByEmail_CaseInsensitive(t *testing.T) {
	d := openTempDB(t)
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := New(d, clk.now)

	seedUsers(t, store, clk)

	got, err := store.GetByEmail(context.Background(), "BOB@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Errorf("Email = %q, want bob@example.com", got.Email)
	}
}

// TestGetByEmail_NotFound returns ErrNotFound so admin CLI can produce a
// clear "no such user" error instead of a generic 500.
func TestGetByEmail_NotFound(t *testing.T) {
	d := openTempDB(t)
	store := New(d, nil)

	_, err := store.GetByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
