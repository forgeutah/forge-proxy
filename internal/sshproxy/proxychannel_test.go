package sshproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The tests below drive proxyChannel against fake channels so the timing of
// each stream is controlled rather than raced for. The real forwarder tests
// cover behavior end to end; these pin the *ordering invariant* that end-to-end
// tests can only catch by luck.

// slowReader yields its payload after a delay, then EOF. It models an
// upstream whose stderr is still in flight when stdout has already ended.
type slowReader struct {
	delay   time.Duration
	payload []byte
	once    sync.Once
	done    bool
}

func (r *slowReader) Read(p []byte) (int, error) {
	r.once.Do(func() { time.Sleep(r.delay) })
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.payload)
	return n, nil
}

// fakeChannel implements ssh.Channel with injectable readers and captured
// writes. Writes after Close fail, which is what makes a premature close
// observable instead of merely unlucky.
type fakeChannel struct {
	stdoutSrc io.Reader
	stderrSrc io.Reader

	// onClose mirrors a real ssh.Channel, where Close unblocks reads that
	// are already in flight. Without it a fake can report a deadlock that
	// production does not have.
	onClose func()

	mu        sync.Mutex
	closed    bool
	stdoutBuf bytes.Buffer
	stderrBuf bytes.Buffer
}

var errChannelClosed = errors.New("write on closed channel")

func (c *fakeChannel) Read(p []byte) (int, error) {
	if c.stdoutSrc == nil {
		return 0, io.EOF
	}
	return c.stdoutSrc.Read(p)
}

func (c *fakeChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errChannelClosed
	}
	return c.stdoutBuf.Write(p)
}

func (c *fakeChannel) Close() error {
	c.mu.Lock()
	alreadyClosed := c.closed
	c.closed = true
	onClose := c.onClose
	c.mu.Unlock()

	if !alreadyClosed && onClose != nil {
		onClose()
	}
	return nil
}

func (c *fakeChannel) CloseWrite() error { return nil }

func (c *fakeChannel) SendRequest(string, bool, []byte) (bool, error) { return true, nil }

func (c *fakeChannel) Stderr() io.ReadWriter { return (*fakeStderr)(c) }

func (c *fakeChannel) gotStderr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stderrBuf.String()
}

func (c *fakeChannel) gotStdout() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stdoutBuf.String()
}

// fakeStderr is the extended-data stream view of a fakeChannel.
type fakeStderr fakeChannel

func (s *fakeStderr) Read(p []byte) (int, error) {
	c := (*fakeChannel)(s)
	if c.stderrSrc == nil {
		return 0, io.EOF
	}
	return c.stderrSrc.Read(p)
}

func (s *fakeStderr) Write(p []byte) (int, error) {
	c := (*fakeChannel)(s)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errChannelClosed
	}
	return c.stderrBuf.Write(p)
}

var _ ssh.Channel = (*fakeChannel)(nil)

func closedReqChan() <-chan *ssh.Request {
	ch := make(chan *ssh.Request)
	close(ch)
	return ch
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestProxyChannel_WaitsForUpstreamStderrBeforeClosing is the deterministic
// fence for the stderr-truncation bug. The upstream's stdout ends
// immediately while its stderr arrives later. If the channel pair closes on
// the stdout signal alone, the late stderr write lands on a closed channel
// and is lost -- the command still reports success, so the loss is silent.
func TestProxyChannel_WaitsForUpstreamStderrBeforeClosing(t *testing.T) {
	const lateMsg = "warning: arrived after stdout ended\n"

	upstream := &fakeChannel{
		stdoutSrc: bytes.NewReader(nil), // EOF at once
		stderrSrc: &slowReader{delay: 150 * time.Millisecond, payload: []byte(lateMsg)},
	}
	client := &fakeChannel{stdoutSrc: bytes.NewReader(nil)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxyChannel(context.Background(), client, closedReqChan(),
			upstream, closedReqChan(), discardLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyChannel did not return")
	}

	if got := client.gotStderr(); got != lateMsg {
		t.Errorf("client stderr = %q, want %q\n"+
			"the channel pair closed before the upstream's stderr copy drained, "+
			"so the write landed on a closed channel", got, lateMsg)
	}
}

// TestProxyChannel_ForwardsBothStreams is the straightforward case, kept so
// a fix to the ordering above cannot pass by never forwarding anything.
func TestProxyChannel_ForwardsBothStreams(t *testing.T) {
	upstream := &fakeChannel{
		stdoutSrc: bytes.NewReader([]byte("stdout payload")),
		stderrSrc: bytes.NewReader([]byte("stderr payload")),
	}
	client := &fakeChannel{stdoutSrc: bytes.NewReader(nil)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxyChannel(context.Background(), client, closedReqChan(),
			upstream, closedReqChan(), discardLogger())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyChannel did not return")
	}

	if got := client.gotStdout(); got != "stdout payload" {
		t.Errorf("client stdout = %q, want %q", got, "stdout payload")
	}
	if got := client.gotStderr(); got != "stderr payload" {
		t.Errorf("client stderr = %q, want %q", got, "stderr payload")
	}
}

// TestProxyChannel_ReturnsWhenClientHoldsStdinOpen is the deadlock fence at
// the unit level: an interactive client never closes stdin, so the
// client-to-upstream copy cannot finish on its own. proxyChannel must still
// return once the upstream is done, driven by closing the pair.
func TestProxyChannel_ReturnsWhenClientHoldsStdinOpen(t *testing.T) {
	// An interactive client's stdin yields nothing and never EOFs on its
	// own. Closing the channel is the only thing that ends the read, which
	// is how a real ssh.Channel behaves.
	blocking, blockingW := io.Pipe()

	upstream := &fakeChannel{stdoutSrc: bytes.NewReader([]byte("done"))}
	client := &fakeChannel{stdoutSrc: blocking}
	client.onClose = func() { _ = blockingW.Close() }

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxyChannel(context.Background(), client, closedReqChan(),
			upstream, closedReqChan(), discardLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxyChannel never returned while the client held stdin open — " +
			"the close that releases the drain stage must not sit behind it")
	}
}
