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
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/forgeutah/forge-proxy/internal/auth"
	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/proxy"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
	"github.com/forgeutah/forge-proxy/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("forge-proxy: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	dbCtx, dbCancel := context.WithTimeout(context.Background(), 30*time.Second)
	database, err := db.Open(dbCtx, cfg.DBPath)
	dbCancel()
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("forge-proxy: closing db: %v", err)
		}
	}()
	log.Printf("forge-proxy: db ready at %s", database.Path())

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

	// authMux serves traffic destined for the auth host
	// (cfg.AuthHost) — /healthz, the /auth/* routes, and the embedded
	// login-page asset tree at /. The login page handler runs an
	// already-signed-in check at "/" and 302s live sessions to the
	// default landing URL (R13).
	authMux := http.NewServeMux()
	authMux.HandleFunc("GET /healthz", healthz)
	authH.Register(authMux)
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
	// auth host — operators target it explicitly. This keeps the routing
	// rule visible in main and avoids a second ServeMux layer.
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostMatches(r.Host, cfg.AuthHost) {
			authMux.ServeHTTP(w, r)
			return
		}
		proxyH.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           rootHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("forge-proxy listening on %s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Print("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Print("forge-proxy stopped")
	return nil
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// hostMatches compares an inbound Host header against the configured auth
// host. Host comparisons are case-insensitive per RFC 7230 §5.4 and the
// inbound value may carry a ":port" suffix (most browsers strip the
// default port, but tests and load-balanced setups don't always).
func hostMatches(inbound, authHost string) bool {
	inbound = strings.ToLower(inbound)
	if i := strings.IndexByte(inbound, ':'); i >= 0 {
		inbound = inbound[:i]
	}
	return inbound == strings.ToLower(authHost)
}
