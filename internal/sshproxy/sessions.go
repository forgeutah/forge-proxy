package sshproxy

import (
	"context"
	"time"
)

// sessionEntry is the registry's record for one live SSH connection. It is
// created at handshake time with only transport facts, then filled in with
// identity once authn and the role check pass — see Server.registerConn and
// Server.attachIdentity.
//
// The registry lives on Server rather than in a parallel structure so that
// Shutdown, List, and force-close all read one map under one lock. A second
// map keyed by the same connections would have to be kept in step with this
// one on every connect and disconnect.
type sessionEntry struct {
	userID      int64
	email       string
	port        int
	clientAddr  string
	connectedAt time.Time

	// cancel tears down this connection specifically. Nil until
	// attachIdentity runs, so connections that never authenticated are
	// skipped by force-close.
	cancel context.CancelFunc

	// closeConn drops the transport. Cancellation alone propagates through
	// the forwarder's goroutines, but closing is what makes the client
	// observe the disconnect immediately. Held as a func rather than
	// calling through the map key so the registry has no dependency on the
	// connection type beyond using it as an identity.
	closeConn func() error
}

// SessionInfo is a read-only snapshot of one live session, shaped for
// operator-facing output.
type SessionInfo struct {
	UserID      int64
	Email       string
	Port        int
	ClientAddr  string
	ConnectedAt time.Time
}

// List returns a snapshot of the sessions that have completed authn. A
// connection still handshaking is tracked internally (so Shutdown can close
// it) but has no identity yet and is omitted here.
func (s *Server) List() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]SessionInfo, 0, len(s.conns))
	for _, e := range s.conns {
		if e.email == "" {
			continue
		}
		out = append(out, SessionInfo{
			UserID:      e.userID,
			Email:       e.email,
			Port:        e.port,
			ClientAddr:  e.clientAddr,
			ConnectedAt: e.connectedAt,
		})
	}
	return out
}

// ForceCloseByEmail tears down every live session belonging to email and
// returns how many were closed.
func (s *Server) ForceCloseByEmail(email string) int {
	if email == "" {
		return 0
	}
	return s.forceClose(func(e *sessionEntry) bool { return e.email == email })
}

// ForceCloseByUser tears down every live session belonging to userID and
// returns how many were closed.
func (s *Server) ForceCloseByUser(userID int64) int {
	if userID == 0 {
		return 0
	}
	return s.forceClose(func(e *sessionEntry) bool { return e.userID == userID })
}

// forceClose cancels and closes every session matching pred. Matching runs
// under the lock; the actual teardown does not, because closing a
// connection unblocks handler goroutines that need the lock to deregister
// themselves — holding it across Close would deadlock against them.
func (s *Server) forceClose(pred func(*sessionEntry) bool) int {
	type victim struct {
		cancel    context.CancelFunc
		closeConn func() error
	}

	s.mu.Lock()
	var victims []victim
	for _, e := range s.conns {
		if e.cancel == nil || !pred(e) {
			continue
		}
		victims = append(victims, victim{cancel: e.cancel, closeConn: e.closeConn})
	}
	s.mu.Unlock()

	for _, v := range victims {
		v.cancel()
		if v.closeConn != nil {
			_ = v.closeConn()
		}
	}
	return len(victims)
}
