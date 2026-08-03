// Package sshca owns the proxy's SSH host key and its internal user-cert CA.
// LoadOrGenerate persists Ed25519 keys at startup; Mint issues short-TTL
// ephemeral certs the proxy presents to upstream sshd as the connecting
// user's Slack identity. Certs intentionally carry only the permit-pty
// extension — the proxy declines reverse-port-forward and agent-forward, so
// broader permissions would be standing over-privilege.
package sshca
