// Package sshproxy implements the per-port SSH bastion: one listener per
// configured upstream, publickey-or-keyboard-interactive auth via the
// sshkey + sshenroll stores, role-check against the listener's allowlist,
// and transparent channel/request forwarding to the upstream over a fresh
// outbound SSH connection authenticated via the sshca-issued ephemeral
// user certificate.
package sshproxy
