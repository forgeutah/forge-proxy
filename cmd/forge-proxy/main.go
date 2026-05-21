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
	"syscall"
	"time"

	"github.com/forgeutah/forge-proxy/internal/auth"
	"github.com/forgeutah/forge-proxy/internal/config"
	"github.com/forgeutah/forge-proxy/internal/db"
	"github.com/forgeutah/forge-proxy/internal/session"
	"github.com/forgeutah/forge-proxy/internal/user"
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	authH.Register(mux)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
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
