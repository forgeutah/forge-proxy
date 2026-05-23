package sshproxy

import (
	"net/url"

	"golang.org/x/crypto/ssh"
)

// Upstream is the per-port configuration the SSH server runs against. It
// mirrors internal/config.SSHUpstream but lives in this package so callers
// don't pull internal/config into sshproxy's test surface.
type Upstream struct {
	Port         int
	Target       *url.URL
	AllowedRoles []string
}

// Config is the wiring the SSH server takes at construction. Every field is
// required when the SSH subsystem is enabled.
type Config struct {
	// ListenAddr is the bind address each per-port listener uses
	// (defaults to "0.0.0.0" via internal/config).
	ListenAddr string

	// Upstreams keys each Upstream by listening port. The server binds one
	// listener per entry.
	Upstreams map[int]Upstream

	// HostKey is the proxy's SSH host key shared across all listeners.
	HostKey ssh.Signer

	// CAKey is the user-cert CA the proxy signs outbound certs with.
	CAKey ssh.Signer

	// KnownHostsCallback verifies the outbound proxy → upstream host key.
	// Loaded from internal/sshca's knownhosts helper at startup.
	KnownHostsCallback ssh.HostKeyCallback

	// AuthHost is the auth host name used to build the enrollment URL
	// embedded in the keyboard-interactive challenge.
	AuthHost string
}
