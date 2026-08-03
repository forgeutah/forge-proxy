package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/forgeutah/forge-proxy/internal/sshca"
)

// dialTimeout is the per-upstream-dial budget. Tailscale hops typically
// resolve in well under a second; ten seconds is comfortably above the
// noise floor and short enough that a dead upstream surfaces as a fast
// failure rather than a hung handshake.
const dialTimeout = 10 * time.Second

// certTTL is how long the proxy→upstream cert is valid. Two minutes only
// needs to outlive the SSH handshake; once authenticated, upstream sshd
// does not re-verify, so VSCode Remote SSH's hours-long sessions are
// unaffected.
const certTTL = 2 * time.Minute

// Forwarder is the channel + request proxy that implements the
// session-forwarding bastion. It is constructed once at startup with the
// CA key + known_hosts callback and re-invoked per authenticated
// connection from the Server.
type ChannelForwarder struct {
	caKey      ssh.Signer
	knownHosts ssh.HostKeyCallback
	logger     *slog.Logger
}

// NewForwarder constructs a ChannelForwarder. logger defaults to
// slog.Default when nil.
func NewForwarder(ca ssh.Signer, knownHosts ssh.HostKeyCallback, logger *slog.Logger) *ChannelForwarder {
	if logger == nil {
		logger = slog.Default()
	}
	return &ChannelForwarder{
		caKey:      ca,
		knownHosts: knownHosts,
		logger:     logger,
	}
}

// Handle is the per-connection entry point invoked by the SSH server
// after authn + role check. It opens a fresh outbound SSH connection to
// the upstream as the user's Slack identity, then proxies every channel
// and request between the two ends.
func (f *ChannelForwarder) Handle(ctx context.Context, ac *AuthenticatedConn) error {
	if ac == nil || ac.ServerConn == nil || ac.Target == nil || ac.User == nil {
		return errors.New("sshproxy: nil AuthenticatedConn field")
	}

	principal := ac.User.Email
	if principal == "" {
		return errors.New("sshproxy: empty user email — refusing to mint upstream cert without principal")
	}

	certSigner, err := sshca.Mint(ctx, f.caKey, principal, certTTL, nil)
	if err != nil {
		f.logger.Error("ssh_upstream_cert_mint_failed",
			"user_id", ac.User.ID, "error", err.Error())
		return fmt.Errorf("mint upstream cert: %w", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            principal,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: f.knownHosts,
		Timeout:         dialTimeout,
	}
	clientCfg.KeyExchanges = []string{
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
	}
	clientCfg.Ciphers = []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
	}
	clientCfg.MACs = []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
	}

	upstreamAddr := ac.Target.Target.Host
	rawConn, err := net.DialTimeout("tcp", upstreamAddr, dialTimeout)
	if err != nil {
		f.logger.Warn("ssh_upstream_dial_failed",
			"target", upstreamAddr,
			"user_id", ac.User.ID,
			"error", err.Error())
		return fmt.Errorf("dial upstream: %w", err)
	}
	sshClientConn, upChans, upReqs, err := ssh.NewClientConn(rawConn, upstreamAddr, clientCfg)
	if err != nil {
		_ = rawConn.Close()
		// Distinguish host-key-mismatch (from the knownhosts callback)
		// from other handshake failures so operators can grep for the
		// specific event. knownhosts.KeyError is returned both for
		// "host not in known_hosts" and "key mismatch with stored
		// entry" — we collapse those to one log signal.
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			f.logger.Warn("ssh_upstream_host_key_mismatch",
				"target", upstreamAddr,
				"user_id", ac.User.ID,
				"error", err.Error())
		} else {
			f.logger.Warn("ssh_upstream_handshake_failed",
				"target", upstreamAddr,
				"user_id", ac.User.ID,
				"error", err.Error())
		}
		return fmt.Errorf("upstream handshake: %w", err)
	}
	upstreamClient := ssh.NewClient(sshClientConn, upChans, upReqs)
	defer upstreamClient.Close()

	f.logger.Info("ssh_session_opened",
		"user_id", ac.User.ID,
		"email", ac.User.Email,
		"port", ac.Port,
		"target", upstreamAddr,
		"fingerprint", ac.Fingerprint,
		"client_addr", ac.ClientAddr)

	// Per-session cancellation: closes both connections, all goroutines
	// drain on the next read/write attempt.
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()
	go func() {
		<-sessCtx.Done()
		_ = upstreamClient.Close()
		_ = ac.ServerConn.Close()
	}()

	// Global request bridges (both directions). Many ssh.Client and
	// ssh.ServerConn implementations leave global requests open until
	// closed; we run two goroutines that consume each side's req channel
	// and forward to the other.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		forwardGlobalRequests(ac.Reqs, upstreamClient.Conn, f.logger, "client→upstream")
	}()
	go func() {
		defer wg.Done()
		// upReqs was consumed by ssh.NewClient — the client surfaces
		// upstream-originated global requests by exposing them on the
		// returned channel. With go's API we get them via
		// Client.HandleChannelOpen for channel-open; global requests
		// to the client are typically just keepalive-style and
		// ssh.Client drops them. There's no direct upstream-global-req
		// channel exposed here, so this goroutine just waits for the
		// upstream to close, then exits.
		_ = upstreamClient.Wait()
	}()

	// Channel pump: every NewChannel from the client opens a matching
	// channel on the upstream and we proxy data + requests on both.
	// chanWG tracks the per-channel proxy goroutines so Handle does not
	// return while channels are still being proxied — otherwise the
	// deferred upstreamClient.Close() below yanks the connection out from
	// under them.
	var chanWG sync.WaitGroup
	chanDone := make(chan struct{})
	go func() {
		defer close(chanDone)
		for newCh := range ac.Chans {
			f.handleChannel(sessCtx, newCh, upstreamClient, &chanWG)
		}
	}()

	// Wait for either end to terminate. Cancelling sessCtx closes both.
	select {
	case <-sessCtx.Done():
	case err := <-clientWait(ac.ServerConn):
		if err != nil && !errors.Is(err, io.EOF) {
			f.logger.Info("ssh_client_wait_returned", "user_id", ac.User.ID, "error", err.Error())
		}
		sessCancel()
	}
	<-chanDone
	chanWG.Wait()
	wg.Wait()
	return nil
}

// clientWait wraps ServerConn.Wait so we can select on its completion.
func clientWait(c *ssh.ServerConn) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
	}()
	return done
}

// handleChannel proxies one client-initiated channel to the upstream.
// Forwarded channel types: session, direct-tcpip. Anything else
// (forwarded-tcpip is upstream→client only; reverse forwards declined at
// the request level) is rejected so the client gets immediate feedback.
func (f *ChannelForwarder) handleChannel(ctx context.Context, newCh ssh.NewChannel, upstream *ssh.Client, chanWG *sync.WaitGroup) {
	chType := newCh.ChannelType()
	switch chType {
	case "session", "direct-tcpip":
		// Forwarded verbatim — see plan Key Technical Decisions.
	default:
		f.logger.Info("ssh_channel_type_rejected", "type", chType)
		_ = newCh.Reject(ssh.UnknownChannelType, "channel type not supported")
		return
	}

	upChan, upReqs, err := upstream.OpenChannel(chType, newCh.ExtraData())
	if err != nil {
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			_ = newCh.Reject(openErr.Reason, openErr.Message)
		} else {
			f.logger.Warn("ssh_upstream_channel_open_failed",
				"type", chType, "error", err.Error())
			_ = newCh.Reject(ssh.ConnectionFailed, "upstream rejected channel")
		}
		return
	}

	clientChan, clientReqs, err := newCh.Accept()
	if err != nil {
		_ = upChan.Close()
		f.logger.Warn("ssh_client_channel_accept_failed", "error", err.Error())
		return
	}

	chanWG.Add(1)
	go func() {
		defer chanWG.Done()
		proxyChannel(ctx, clientChan, clientReqs, upChan, upReqs, f.logger)
	}()
}

// proxyChannel proxies one channel pair: two ordered request loops, two
// byte-stream copies, and two stderr copies.
//
// The teardown order is the delicate part, and three plausible-looking
// orderings are each wrong in a different, silent way:
//
//  1. Waiting on all six goroutines before closing DEADLOCKS. Four of them
//     (both request loops, both stderr copies) only unblock when the
//     channels close, and that close would sit behind the wait.
//  2. Closing as soon as the byte-stream copies finish TRUNCATES STDERR.
//     The stderr copy can still be flushing when stdout reaches EOF.
//  3. Closing when the upstream's streams reach EOF closes a LIVE SESSION.
//     Stream EOF is not channel close: the channel stays open afterwards so
//     the upstream can send exit-status, and the client may still be
//     sending setup requests. Closing here makes the client's next request
//     fail with a bare EOF.
//
// So the signal used is the upstream's *request channel closing*, which
// the SSH library does when the channel itself closes. That is the only
// authoritative "this session is over". It also means exit-status has
// already been forwarded by the time it fires, so there is nothing to race.
//
// Order: wait for the upstream channel to close, drain what it had already
// written, close both sides, then drain the goroutines that were waiting
// for that close.
func proxyChannel(_ context.Context, clientChan ssh.Channel, clientReqs <-chan *ssh.Request, upChan ssh.Channel, upReqs <-chan *ssh.Request, logger *slog.Logger) {
	// fromUpstream must complete before the client side closes; anything
	// still buffered would otherwise be discarded.
	var fromUpstream sync.WaitGroup
	// drain unblocks only once the channels are closed.
	var drain sync.WaitGroup
	fromUpstream.Add(2)
	drain.Add(4)

	// Closed when the upstream's request loop has drained. The upstream
	// sends exit-status *after* EOF, so the client side must stay open
	// until this fires or the client's Session.Wait() reports a channel
	// closed without exit status (golang/go#29733).
	upReqsDone := make(chan struct{})

	// Held while a client request is being forwarded upstream and its
	// reply written back. Teardown takes it before closing so a reply the
	// client is still blocked on cannot be cut off mid-flight -- see the
	// close sequence at the bottom of this function.
	var replying sync.Mutex

	// Request loop: client → upstream. One goroutine per direction keeps
	// requests ordered relative to each other on the wire.
	go func() {
		defer drain.Done()
		for r := range clientReqs {
			forwardClientRequest(r, upChan, &replying, logger)
		}
	}()

	// Request loop: upstream → client. Ordered, and the carrier for
	// exit-status / exit-signal.
	go func() {
		defer drain.Done()
		defer close(upReqsDone)
		for r := range upReqs {
			ok, err := clientChan.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				logger.Warn("ssh_chan_req_forward_to_client_failed",
					"type", r.Type, "error", err.Error())
			}
			if r.WantReply {
				_ = r.Reply(ok, nil)
			}
		}
	}()

	// Upstream → client: stdout.
	go func() {
		defer fromUpstream.Done()
		_, _ = io.Copy(clientChan, upChan)
	}()

	// Upstream → client: stderr. Sessions carry stderr as a separate
	// extended-data stream, so this is not covered by the copy above.
	// Missing or truncating it breaks rsync, scp -v, and anything else
	// whose diagnostics matter.
	go func() {
		defer fromUpstream.Done()
		_, _ = io.Copy(clientChan.Stderr(), upChan.Stderr())
	}()

	// Client → upstream: stdout. CloseWrite propagates EOF so commands
	// that read to end-of-input (cat, git push) terminate.
	go func() {
		defer drain.Done()
		_, _ = io.Copy(upChan, clientChan)
		_ = upChan.CloseWrite()
	}()

	// Client → upstream: stderr. Rare, but symmetric.
	go func() {
		defer drain.Done()
		_, _ = io.Copy(upChan.Stderr(), clientChan.Stderr())
	}()

	// Stage 1: wait for the upstream to close the channel.
	//
	// Closing is the authoritative end-of-session signal, and it is not the
	// same as the data streams reaching EOF. A channel stays open after EOF
	// so the upstream can still send exit-status, and the client is often
	// still sending setup requests of its own. Treating stream EOF as the
	// end closes the pair out from under a live session -- the client's
	// next request then fails with a bare EOF.
	//
	// This also removes any need to race the trailing exit-status: by the
	// time the request channel closes, the request loop has already
	// forwarded everything on it.
	<-upReqsDone

	// Stage 2: drain whatever the upstream had already written. The close
	// that ended stage 1 makes both of these return promptly.
	fromUpstream.Wait()

	// Stage 3: close, which is what releases the drain group.
	//
	// Take the reply lock first. A request the client is still waiting on
	// may be mid-flight in the loop above: forwarded upstream, answered,
	// but not yet replied back. Closing in that window drops the reply and
	// the client's request fails with a bare EOF. It is easy to hit --
	// a fast command finishes and closes the upstream channel in well
	// under a millisecond, racing the reply to its own exec request.
	replying.Lock()
	_ = clientChan.Close()
	_ = upChan.Close()
	replying.Unlock()

	drain.Wait()
}

// forwardClientRequest forwards one client channel request upstream and
// relays the answer back. replying is held for the whole forward-and-reply
// so teardown cannot close the channel between the two.
func forwardClientRequest(r *ssh.Request, upChan ssh.Channel, replying *sync.Mutex, logger *slog.Logger) {
	replying.Lock()
	defer replying.Unlock()

	if r.Type == "auth-agent-req@openssh.com" {
		logger.Info("ssh_agent_forwarding_declined")
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
		return
	}

	ok, _ := upChan.SendRequest(r.Type, r.WantReply, r.Payload)
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
}

// forwardGlobalRequests reads from in and forwards each request to the
// other end's connection. Reverse-port-forwarding requests (tcpip-forward,
// cancel-tcpip-forward) are explicitly declined since the proxy doesn't
// support them in v1; agent-forward and other unknown requests are
// passed through (a future hardening pass can tighten this).
func forwardGlobalRequests(in <-chan *ssh.Request, out ssh.Conn, logger *slog.Logger, direction string) {
	for r := range in {
		switch r.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			logger.Info("ssh_reverse_forward_declined", "direction", direction, "type", r.Type)
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := out.SendRequest(r.Type, r.WantReply, r.Payload)
		if err != nil {
			// Likely the far side closed; reply false and let the
			// loop exit when the channel drains.
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			return
		}
		if r.WantReply {
			_ = r.Reply(ok, payload)
		}
	}
}

// Ensure ChannelForwarder satisfies the Forwarder interface.
var _ Forwarder = (*ChannelForwarder)(nil)
