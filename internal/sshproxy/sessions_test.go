package sshproxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newRegistryServer builds a Server with only the registry fields set. The
// registry is independent of listeners and authn, so these tests exercise
// it directly rather than standing up SSH connections.
func newRegistryServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		conns: make(map[*ssh.ServerConn]*sessionEntry),
		now:   time.Now,
	}
}

// closedFlag records whether a session was torn down, so a test can assert
// force-close reached the right sessions and only those.
type closedFlag struct {
	mu        sync.Mutex
	cancelled bool
	closed    bool
}

func (f *closedFlag) wasCancelled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cancelled
}

func (f *closedFlag) wasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// register adds an entry keyed by a distinct connection pointer. The
// registry uses the key only as an identity and tears sessions down through
// the injected cancel/close funcs, so tests need no live connection.
func register(t *testing.T, s *Server, userID int64, email string, port int) (*ssh.ServerConn, func(), *closedFlag) {
	t.Helper()
	conn := &ssh.ServerConn{}
	flag := &closedFlag{}
	cleanup := s.registerConnWith(conn, port, "10.0.0.1:5000", func() error {
		flag.mu.Lock()
		defer flag.mu.Unlock()
		flag.closed = true
		return nil
	})
	if email != "" {
		s.attachIdentity(conn, userID, email, func() {
			flag.mu.Lock()
			defer flag.mu.Unlock()
			flag.cancelled = true
		})
	}
	return conn, cleanup, flag
}

func TestRegistry_AddAndCleanup(t *testing.T) {
	s := newRegistryServer(t)

	_, cleanup, _ := register(t, s, 1, "alice@example.com", 2222)
	got := s.List()
	if len(got) != 1 {
		t.Fatalf("List() = %d entries, want 1", len(got))
	}
	if got[0].Email != "alice@example.com" || got[0].UserID != 1 || got[0].Port != 2222 {
		t.Errorf("List()[0] = %+v, want alice@example.com/1/2222", got[0])
	}
	if got[0].ConnectedAt.IsZero() {
		t.Error("ConnectedAt is zero; registerConn should stamp it")
	}

	cleanup()
	if got := s.List(); len(got) != 0 {
		t.Errorf("List() after cleanup = %d entries, want 0", len(got))
	}
}

func TestRegistry_UnauthenticatedConnIsTrackedButNotListed(t *testing.T) {
	s := newRegistryServer(t)

	// No attachIdentity — mid-handshake.
	register(t, s, 0, "", 2222)

	if got := s.List(); len(got) != 0 {
		t.Errorf("List() = %v, want empty; a connection without an identity must not be listed", got)
	}

	// But it is still tracked, so Shutdown can reach it.
	s.mu.Lock()
	tracked := len(s.conns)
	s.mu.Unlock()
	if tracked != 1 {
		t.Errorf("tracked connections = %d, want 1; Shutdown must still be able to close it", tracked)
	}
}

func TestRegistry_ForceCloseByEmail(t *testing.T) {
	s := newRegistryServer(t)

	_, _, aliceCancelled := register(t, s, 1, "alice@example.com", 2222)
	_, _, bobCancelled := register(t, s, 2, "bob@example.com", 2222)

	if n := s.ForceCloseByEmail("alice@example.com"); n != 1 {
		t.Errorf("ForceCloseByEmail = %d, want 1", n)
	}
	if !aliceCancelled.wasCancelled() {
		t.Error("alice's session was not cancelled")
	}
	if !aliceCancelled.wasClosed() {
		t.Error("alice's transport was not closed; cancellation alone leaves the client hanging")
	}
	if bobCancelled.wasCancelled() || bobCancelled.wasClosed() {
		t.Error("bob's session was torn down; force-close must be scoped to the named user")
	}
}

func TestRegistry_ForceCloseClosesEveryMatchingSession(t *testing.T) {
	s := newRegistryServer(t)

	_, _, first := register(t, s, 7, "carol@example.com", 2222)
	_, _, second := register(t, s, 7, "carol@example.com", 2223)

	if n := s.ForceCloseByEmail("carol@example.com"); n != 2 {
		t.Errorf("ForceCloseByEmail = %d, want 2 (a user may hold several sessions)", n)
	}
	if !first.wasCancelled() || !second.wasCancelled() {
		t.Errorf("not every session was cancelled: first=%v second=%v",
			first.wasCancelled(), second.wasCancelled())
	}
}

func TestRegistry_ForceCloseByUser(t *testing.T) {
	s := newRegistryServer(t)

	_, _, cancelled := register(t, s, 42, "dave@example.com", 2222)

	if n := s.ForceCloseByUser(42); n != 1 {
		t.Errorf("ForceCloseByUser = %d, want 1", n)
	}
	if !cancelled.wasCancelled() {
		t.Error("session was not cancelled")
	}
}

func TestRegistry_ForceCloseUnknownIsZeroNotError(t *testing.T) {
	s := newRegistryServer(t)
	register(t, s, 1, "alice@example.com", 2222)

	if n := s.ForceCloseByEmail("nobody@example.com"); n != 0 {
		t.Errorf("ForceCloseByEmail(unknown) = %d, want 0", n)
	}
	if n := s.ForceCloseByUser(9999); n != 0 {
		t.Errorf("ForceCloseByUser(unknown) = %d, want 0", n)
	}
	// Empty inputs must not match the not-yet-identified entries either.
	if n := s.ForceCloseByEmail(""); n != 0 {
		t.Errorf("ForceCloseByEmail(\"\") = %d, want 0", n)
	}
	if n := s.ForceCloseByUser(0); n != 0 {
		t.Errorf("ForceCloseByUser(0) = %d, want 0", n)
	}
}

func TestRegistry_UnauthenticatedSessionIsNotForceClosed(t *testing.T) {
	s := newRegistryServer(t)
	// Identity attached, but cancel deliberately nil — mirrors a
	// connection that registered and never reached attachIdentity.
	conn := &ssh.ServerConn{}
	s.registerConnWith(conn, 2222, "10.0.0.1:5000", func() error { return nil })

	if n := s.ForceCloseByEmail("alice@example.com"); n != 0 {
		t.Errorf("ForceCloseByEmail = %d, want 0 for a connection with no cancel func", n)
	}
}

// TestRegistry_ConcurrentRegisterAndCleanup is the -race gate: connections
// arrive and depart on independent goroutines while an operator lists and
// force-closes.
func TestRegistry_ConcurrentRegisterAndCleanup(t *testing.T) {
	s := newRegistryServer(t)

	var wg sync.WaitGroup
	const workers = 16

	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := &ssh.ServerConn{}
			cleanup := s.registerConnWith(conn, 2222+i, "10.0.0.1:5000",
				func() error { return nil })
			s.attachIdentity(conn, int64(i), "user@example.com", func() {})
			cleanup()
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.List()
			_ = s.ForceCloseByEmail("user@example.com")
		}()
	}
	wg.Wait()

	if got := s.List(); len(got) != 0 {
		t.Errorf("List() = %d entries after all cleanups ran, want 0", len(got))
	}
}

// TestRegistry_ShutdownStillClosesAfterValueTypeChange guards the
// regression risk in swapping the map's value type: Shutdown must still
// walk the registry and close everything, including connections that never
// authenticated.
func TestRegistry_ShutdownStillClosesAfterValueTypeChange(t *testing.T) {
	s := newRegistryServer(t)
	_, _, authed := register(t, s, 1, "alice@example.com", 2222)
	_, _, handshaking := register(t, s, 0, "", 2223) // no identity yet

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if !closed {
		t.Error("Shutdown did not mark the server closed")
	}
	if !authed.wasClosed() {
		t.Error("Shutdown did not close the authenticated session")
	}
	if !handshaking.wasClosed() {
		t.Error("Shutdown did not close the still-handshaking connection; " +
			"registering before authn exists precisely so these get torn down")
	}
}
