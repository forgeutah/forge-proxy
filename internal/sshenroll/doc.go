// Package sshenroll owns the TOFU enrollment URL flow: an in-memory token
// store that binds a short-TTL token to an offered SSH key fingerprint, plus
// the two HTTP handlers that render the fingerprint-confirmation page and
// register the key once the Slack OIDC sign-in completes. No DB table for v1
// — proxy restart drops pending enrollments and the user re-runs `ssh` to
// get a fresh URL.
package sshenroll
