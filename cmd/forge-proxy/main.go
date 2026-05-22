// Command forge-proxy is the Forge Utah Foundation auth proxy.
//
// It sits in front of *.forgeutah.tech apps, authenticates users via Slack
// OpenID Connect, and forwards X-Forge-* identity headers to upstream apps.
// See docs/plans/2026-05-20-001-feat-forge-auth-proxy-plan.md for the design.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/forgeutah/forge-proxy/internal/auth"
	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/httplog"
	"github.com/forgeutah/forge-proxy/internal/proxy"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
	"github.com/forgeutah/forge-proxy/internal/web"
)

func main() {
	// `forge-proxy admin <sub> [args]` dispatches to the admin CLI; every
	// other invocation drops through to run() which serves traffic. The
	// admin path is intentionally first so an operator running the binary
	// inside the production container (where env vars are configured for
	// the server) can `docker exec ... forge-proxy admin set-roles ...`
	// without a separate image. See cmd/forge-proxy/admin.go for the
	// concurrent-writer coordination notes.
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		if err := runAdmin(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "forge-proxy admin: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		// Fall back to stderr without slog — slog may not be configured
		// yet (config load failure happens before setupLogging).
		fmt.Fprintf(os.Stderr, "forge-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	setupLogging(cfg.LogLevel)
	slog.Info("forge-proxy starting", "listen_addr", cfg.ListenAddr, "log_level", cfg.LogLevel)

	dbCtx, dbCancel := context.WithTimeout(context.Background(), 30*time.Second)
	database, err := db.Open(dbCtx, cfg.DBPath)
	dbCancel()
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			slog.Error("closing db", "error", err.Error())
		}
	}()
	slog.Info("db ready", "path", database.Path())

	// Build the auth stack. The OIDC client kicks off a background JWKS
	// fetch immediately; the binary stays up even if Slack is unreachable.
	users := user.New(database, nil)
	sessions := session.New(database, session.Options{
		Lifetime:     cfg.SessionLifetime,
		IdleTimeout:  cfg.SessionIdleTimeout,
		CookieDomain: cfg.CookieDomain,
	})
	oidcCtx, oidcStop := context.WithCancel(context.Background())
	defer oidcStop()
	oidcClient := auth.New(oidcCtx, cfg)
	authH := auth.NewHandler(cfg, oidcClient, users, sessions)

	// Sweeper: prune expired session rows on a 1-hour cadence. Started
	// here so it has the same lifecycle as the HTTP server.
	sweeper := session.NewSweeper(sessions)
	sweeperCtx, sweeperStop := context.WithCancel(context.Background())
	defer sweeperStop()
	var sweeperWG sync.WaitGroup
	sweeperWG.Go(func() {
		_ = sweeper.Run(sweeperCtx, session.DefaultSweepInterval)
	})

	// Rate limiters: in-memory per-IP token buckets. /auth/login at 30/min,
	// /auth/callback at 5/min. Buckets reset on restart (single-VM v1).
	loginLimiter := httplog.NewRateLimiter(30)
	callbackLimiter := httplog.NewRateLimiter(5)

	// authMux serves traffic destined for the auth host
	// (cfg.AuthHost) — /healthz, /readyz, the /auth/* routes, and the
	// embedded login-page asset tree at /. The login page handler runs
	// an already-signed-in check at "/" and 302s live sessions to the
	// default landing URL (R13).
	authMux := http.NewServeMux()
	authMux.HandleFunc("GET /healthz", healthz)
	authMux.Handle("GET /readyz", readyzHandler(database.Writer, database.Reader, oidcClient, sweeper))

	// Register auth routes with per-endpoint rate limits.
	authMux.Handle("GET /auth/login",
		httplog.RateLimitMiddleware(loginLimiter, http.HandlerFunc(authH.HandleLogin)))
	authMux.Handle("GET /auth/callback",
		httplog.RateLimitMiddleware(callbackLimiter, http.HandlerFunc(authH.HandleCallback)))
	authMux.HandleFunc("POST /auth/logout", authH.HandleLogout)

	webH := web.NewHandler(authH, web.Config{DefaultLandingURL: cfg.DefaultLandingURL})
	authMux.Handle("GET /", webH)

	// proxyH is the reverse-proxy hot path for every non-auth-host
	// *.forgeutah.tech subdomain (U8). It authenticates the request,
	// strips any client-supplied X-Forge-* headers, and injects the
	// nine trusted X-Forge-* contract headers before forwarding to the
	// configured upstream.
	proxyH := proxy.New(cfg, sessions, users)

	// Host-routing dispatcher: net/http.ServeMux's host patterns require
	// each host be known literally, but the upstream hosts are runtime
	// configuration. The dispatcher splits on the inbound Host header:
	// requests for the auth host go to authMux (auth + web), everything
	// else goes to the proxy. The /healthz endpoint stays scoped to the
	// auth host — operators target it explicitly.
	//
	// Both branches share proxy.NormalizeHost so the auth-host comparison
	// applies the same lowercase + port-strip rule the upstream lookup uses.
	authHostNorm := proxy.NormalizeHost(cfg.AuthHost)
	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxy.NormalizeHost(r.Host) == authHostNorm {
			authMux.ServeHTTP(w, r)
			return
		}
		proxyH.ServeHTTP(w, r)
	})

	// Middleware chain (outermost first):
	//  1. RequestID — guarantees X-Request-Id on every response and a
	//     per-request slog.Logger on context for all downstream code.
	//  2. AccessLog — emits one structured line per request at end.
	//  3. HSTS — Strict-Transport-Security on every response.
	//  4. dispatcher — host-based routing to authMux or proxyH.
	rootHandler := httplog.RequestIDMiddleware(
		httplog.AccessLogMiddleware(
			httplog.HSTSMiddleware(dispatcher)))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           rootHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("forge-proxy listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	// Stop the sweeper and wait for it to exit before letting the
	// deferred db.Close() run. Otherwise the sweeper's in-flight
	// Sweep transaction could race the writer pool's close.
	sweeperStop()
	sweeperWG.Wait()

	slog.Info("forge-proxy stopped")
	return nil
}

// setupLogging configures the default slog logger as a JSON handler on
// stdout with level driven by cfg.LogLevel. The LevelVar wrapper allows
// future runtime level changes (e.g. via SIGHUP) without reconstructing
// the handler.
func setupLogging(logLevel string) {
	level := new(slog.LevelVar)
	switch strings.ToLower(strings.TrimSpace(logLevel)) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn", "warning":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// pinger is the narrow surface readyzHandler needs from each DB pool.
// Defining it locally keeps main_test.go able to construct a stub /readyz
// without spinning up a real SQLite database.
type pinger interface {
	PingContext(ctx context.Context) error
}

// readinessOIDC is the narrow OIDC surface readyzHandler needs.
type readinessOIDC interface {
	IsReady() bool
}

// readinessSweeper is the narrow Sweeper surface readyzHandler needs.
type readinessSweeper interface {
	LastSuccess() time.Time
}

// readyzHandler reports readiness. 200 if all checks pass; 503 with a
// plain-text body naming the failing check(s) otherwise.
//
// Checks:
//   - writer DB ping (catches "WAL volume gone" / "schema not migrated")
//   - reader DB ping (catches "reader pool died independently")
//   - OIDC verifier ready (Slack JWKS fetched at least once)
//   - sweeper staleness — only enforced if the sweeper has previously
//     succeeded. Zero-valued LastSuccess means "still on the first sweep
//     after startup," which is fine; we don't want /readyz to fail
//     during the first interval of life. The sweeper kicks off an
//     immediate first sweep in Run, so LastSuccess populates within a
//     few ms of startup in the happy path.
func readyzHandler(writer, reader pinger, oidcClient readinessOIDC, sweeper readinessSweeper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var problems []string
		if err := writer.PingContext(r.Context()); err != nil {
			problems = append(problems, fmt.Sprintf("writer db: %v", err))
		}
		if err := reader.PingContext(r.Context()); err != nil {
			problems = append(problems, fmt.Sprintf("reader db: %v", err))
		}
		if !oidcClient.IsReady() {
			problems = append(problems, "oidc: JWKS not yet fetched from Slack")
		}
		if last := sweeper.LastSuccess(); !last.IsZero() && time.Since(last) > 2*time.Hour {
			problems = append(problems, fmt.Sprintf("sweeper: last successful run was %s ago", time.Since(last)))
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(problems) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, strings.Join(problems, "\n")+"\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
}

// hostMatches compares an inbound Host header against the configured auth
// host using proxy.NormalizeHost so the dispatcher and the upstream lookup
// share a single normalisation rule. Kept as a thin wrapper because the
// existing test suite covers the auth-host edge cases here.
func hostMatches(inbound, authHost string) bool {
	return proxy.NormalizeHost(inbound) == proxy.NormalizeHost(authHost)
}
