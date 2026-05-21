// Package user owns the users table: lookup by Slack ID, auto-provisioning
// from OIDC claims on first sign-in, and role read/write. Roles are stored
// as a comma-separated TEXT column constrained to [A-Za-z0-9_-]+ per role.
package user
