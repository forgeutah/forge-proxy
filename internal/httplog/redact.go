package httplog

import "log/slog"

// SessionID is a string newtype that redacts itself when logged via slog.
// The full session ID is a bearer credential — anyone with it can replay
// the user's session until expiry. Wrapping it in this type means a
// defensively-typed slog call (`slog.Any("session_id", id)`) renders as
// [REDACTED] even if an engineer reaches for the raw value by mistake.
//
// Plain %v / Sprintf interpolation still emits the underlying string —
// LogValuer only applies inside slog. Code that handles session IDs in
// log lines should use slog directly; the legacy log.Printf paths are
// being retired by U9.
//
// The type lives in this package (rather than internal/session) to avoid
// a circular import: internal/session has no slog dependency today, and
// adding LogValuer there would pull log/slog into a package that doesn't
// otherwise need it. Callers convert at the log site:
//
//	logger.Info("session lookup", "session_id", httplog.SessionID(id))
type SessionID string

// LogValue implements slog.LogValuer. The constant string keeps the
// rendered value compact and grep-friendly across log shippers.
func (SessionID) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ProxySecret is the X-Forge-Proxy-Secret newtype. It is defensive — the
// proxy never logs the secret today — but wrapping it consistently at the
// boundary (config load, header injection) means a future refactor can't
// silently log it via slog.
type ProxySecret string

// LogValue implements slog.LogValuer.
func (ProxySecret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
