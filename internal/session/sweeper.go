package session

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// SweepStore is the narrow surface Sweeper needs from the session store —
// just enough to delete expired rows. Defining it explicitly keeps the
// sweeper testable without spinning up a real SQLite DB.
type SweepStore interface {
	Sweep(ctx context.Context, now time.Time) (int, error)
}

// DefaultSweepInterval is the production cadence. Sessions whose
// expires_at has passed are deleted on each tick; the 1-hour interval
// trades freshness (deleted rows take up disk for at most ~1h after
// expiry) against writer-pool pressure (one BEGIN IMMEDIATE per hour).
const DefaultSweepInterval = time.Hour

// Sweeper is the background goroutine that periodically prunes expired
// session rows. It lives in the session package — the store, the schema,
// and the sweep query are all here, and U9's /readyz check needs a
// liveness signal that's specific to "the sweeper actually ran".
//
// The sweeper does not own a context; Run is given one and exits when
// it's cancelled. main.go pairs the sweeper context with the HTTP
// server's shutdown context so SIGTERM stops both in lockstep.
type Sweeper struct {
	store SweepStore

	// mu protects lastSuccess. Using a small mutex (rather than
	// atomic.Pointer[time.Time]) keeps the read side trivially safe
	// against any future writer that wants to publish more than just a
	// timestamp.
	mu                    sync.RWMutex
	lastSuccessfulSweepAt time.Time

	now func() time.Time
}

// NewSweeper constructs a Sweeper bound to the given store. The clock
// hook lets tests drive Run deterministically; production callers pass
// nil and get time.Now.
func NewSweeper(store SweepStore) *Sweeper {
	return &Sweeper{store: store, now: time.Now}
}

// LastSuccess returns the time of the most recent successful sweep, or
// the zero value if no successful sweep has happened yet. Readers (e.g.
// /readyz) must treat IsZero() as "not yet run" rather than "stale" — see
// main.go for the cold-start carve-out.
func (s *Sweeper) LastSuccess() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSuccessfulSweepAt
}

// Run executes the sweep loop until ctx is cancelled. Each tick calls
// store.Sweep; transient errors are logged and the loop continues (a
// failed sweep is not fatal — the expired rows just take another hour to
// disappear). The function returns nil exactly when ctx is cancelled, so
// main.go can wait on a single done channel and report cleanup status.
//
// Run kicks off an immediate first sweep before entering the tick loop.
// That populates LastSuccess() during startup so /readyz doesn't have to
// special-case the first hour of life. If the first sweep errors, the
// loop continues; LastSuccess stays zero until a tick succeeds.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultSweepInterval
	}

	// Immediate first sweep. Logs at debug level so quiet boots stay
	// quiet; an operator running with LOG_LEVEL=debug sees the count.
	s.tick(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.tick(ctx)
		}
	}
}

// tick runs one sweep iteration. Errors that aren't context cancellation
// are logged at warn level and the loop continues; a series of failures
// is visible in the logs without crashing the process.
func (s *Sweeper) tick(ctx context.Context) {
	now := s.now()
	deleted, err := s.store.Sweep(ctx, now)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Shutdown in flight; not interesting to log loudly.
			return
		}
		slog.Warn("session_sweeper_tick_failed", "error", err.Error())
		return
	}
	s.mu.Lock()
	s.lastSuccessfulSweepAt = now
	s.mu.Unlock()
	slog.Info("session_sweeper_tick", "deleted", deleted)
}
