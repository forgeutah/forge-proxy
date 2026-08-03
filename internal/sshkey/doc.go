// Package sshkey owns the ssh_keys table: per-user public-key registration
// keyed by OpenSSH canonical fingerprint (SHA256:base64nopad). Writes serialize
// through the DB writer pool; reads use the reader pool. The fingerprint
// column is UNIQUE so an enrollment race cannot bind the same key to two
// users.
package sshkey
