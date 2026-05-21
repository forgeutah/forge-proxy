package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

// embeddedMigrations bundles the SQL migration files into the binary so
// the proxy can apply schema changes on startup without shipping the SQL
// files alongside the executable.
//
//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// gooseDialect is the dialect string goose expects for modernc.org/sqlite.
// Goose treats "sqlite3" as a synonym for "sqlite" — we use "sqlite3" because
// the plan and the wider Go ecosystem use that name.
const gooseDialect = "sqlite3"

// migrate runs all pending goose migrations against the writer handle.
// Idempotent: re-running on an up-to-date DB is a no-op.
//
// goose maintains its own connection state via SetBaseFS + SetDialect, which
// are package-level globals. We restore the previous BaseFS afterwards so
// callers (e.g. tests) can repeatedly Open without leaking state between runs.
func migrate(ctx context.Context, writer *sql.DB) error {
	goose.SetBaseFS(embeddedMigrations)
	defer goose.SetBaseFS(nil)

	if err := goose.SetDialect(gooseDialect); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}

	// Silence goose's default stdout logger. The proxy emits its own log line
	// after migrations succeed; we don't want goose's chatty per-migration prints
	// in production logs.
	goose.SetLogger(goose.NopLogger())

	if err := goose.UpContext(ctx, writer, "migrations"); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
