// Package proxy implements the reverse-proxy hot path: per-host upstream
// resolution, session lookup, header strip + inject, and the X-Forge-*
// contract emission. Uses httputil.ReverseProxy with Rewrite.
package proxy
