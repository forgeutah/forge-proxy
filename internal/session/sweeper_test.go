package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// quietSlog redirects the default slog handler to io.Discard so test
// output stays clean. Restored on test cleanup.
func quietSlog(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// fakeSweepStore is a SweepStore stub that counts calls and lets tests
// inject failures and observe the "now" argument.
type fakeSweepStore struct {
	mu      sync.Mutex
	calls   atomic.Int32
	results []sweepResult // FIFO: each call dequeues the head
}

type sweepResult struct {
	deleted int
	err     error
}

func (f *fakeSweepStore) Sweep(_ context.Context, _ time.Time) (int, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) == 0 {
		return 0, nil
	}
	r := f.results[0]
	f.results = f.results[1:]
	return r.deleted, r.err
}

func TestSweeper_DeletesExpiredOnTick(t *testing.T) {
	quietSlog(t)
	store := &fakeSweepStore{results: []sweepResult{{deleted: 3}}}
	sw := NewSweeper(store)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// 1 ns interval forces a tick effectively-immediately; we cancel
	// after observing the first tick via LastSuccess() going non-zero.
	done := make(chan struct{})
	go func() {
		_ = sw.Run(ctx, time.Millisecond)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for sw.LastSuccess().IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got := store.calls.Load(); got < 1 {
		t.Fatalf("expected at least 1 sweep call, got %d", got)
	}
	if sw.LastSuccess().IsZero() {
		t.Fatal("expected LastSuccess to be set after a successful sweep")
	}
}

func TestSweeper_ExitsCleanlyOnContextCancel(t *testing.T) {
	quietSlog(t)
	store := &fakeSweepStore{}
	sw := NewSweeper(store)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sw.Run(ctx, time.Hour) }()

	// Give the goroutine a moment to enter the select.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sweeper.Run did not exit within 2s of context cancel")
	}
}

func TestSweeper_LastSuccessReturnsMostRecentRun(t *testing.T) {
	quietSlog(t)
	store := &fakeSweepStore{}
	sw := NewSweeper(store)

	t1 := time.Unix(1_700_000_000, 0)
	t2 := time.Unix(1_700_003_600, 0)

	// Tick #1.
	sw.now = func() time.Time { return t1 }
	sw.tick(context.Background())
	if got := sw.LastSuccess(); !got.Equal(t1) {
		t.Fatalf("after tick 1, LastSuccess = %v, want %v", got, t1)
	}

	// Tick #2 — LastSuccess advances.
	sw.now = func() time.Time { return t2 }
	sw.tick(context.Background())
	if got := sw.LastSuccess(); !got.Equal(t2) {
		t.Fatalf("after tick 2, LastSuccess = %v, want %v", got, t2)
	}
}

func TestSweeper_ContinuesAfterTransientError(t *testing.T) {
	quietSlog(t)
	store := &fakeSweepStore{results: []sweepResult{
		{err: errors.New("disk wobble")},
		{deleted: 7},
	}}
	sw := NewSweeper(store)

	// First tick: errors → LastSuccess stays zero.
	sw.tick(context.Background())
	if !sw.LastSuccess().IsZero() {
		t.Fatalf("LastSuccess should remain zero after a failing sweep, got %v", sw.LastSuccess())
	}

	// Second tick: succeeds → LastSuccess populated.
	sw.tick(context.Background())
	if sw.LastSuccess().IsZero() {
		t.Fatal("LastSuccess should be set after the second (successful) tick")
	}
	if got := store.calls.Load(); got != 2 {
		t.Fatalf("expected 2 sweep calls, got %d", got)
	}
}
