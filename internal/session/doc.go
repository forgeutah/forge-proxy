// Package session owns the server-side session lifecycle: opaque random
// session IDs, sliding expiration with absolute cap, server-side revocation,
// and the shared .forgeutah.tech cookie. Sessions live in SQLite.
package session
