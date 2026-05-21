package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"

	// Register the pure-Go sqlite driver under the name "sqlite".
	_ "modernc.org/sqlite"
)

// driverName is the driver string modernc.org/sqlite registers with database/sql.
const driverName = "sqlite"

// DB is a SQLite database opened with the two-pool pattern: a single-connection
// writer pool and a multi-connection reader pool, both pointing at the same
// underlying WAL-mode file.
//
// Callers should:
//   - read via DB.Reader (or DB.Writer if a write is needed; both serve reads)
//   - perform writes via DB.Writer.ExecContext / .QueryContext
//   - wrap write transactions in DB.WithWriteTx so they take a BEGIN IMMEDIATE
//     lock and avoid SQLITE_BUSY upgrade-deadlocks
type DB struct {
	// Writer is the single-connection writer pool. It serializes all writes
	// at the database/sql layer (MaxOpenConns=1), eliminating writer contention
	// at the SQLite layer and making BEGIN IMMEDIATE transactions safe.
	Writer *sql.DB

	// Reader is the multi-connection reader pool, opened in read-only mode.
	// Concurrent reads are allowed; in WAL mode they do not block on the writer.
	Reader *sql.DB

	// path is the on-disk file path, retained for error messages and diagnostics.
	path string
}

// Tx is the transactional surface exposed by WithWriteTx. It deliberately
// excludes Begin/Commit/Rollback so callers can't undermine the helper's
// commit/rollback ownership. The concrete value carried under the hood is a
// *sql.Conn that has had BEGIN IMMEDIATE issued on it.
type Tx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// Open opens the SQLite file at path and returns a *DB with both pools.
//
// Order of operations:
//  1. Open the writer pool (this creates the file if missing).
//  2. Apply embedded goose migrations on the writer.
//  3. Open the reader pool in read-only mode (the file now definitely exists).
//
// If any step fails, all opened handles are closed before returning.
func Open(ctx context.Context, path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("db: empty path")
	}

	writer, err := openWriter(path)
	if err != nil {
		return nil, fmt.Errorf("db: open writer %q: %w", path, err)
	}

	// Ping so we surface "directory does not exist" / permissions errors here,
	// with the file path in the message, rather than letting them bubble up
	// from the first migration statement.
	if err := writer.PingContext(ctx); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("db: ping writer %q: %w", path, err)
	}

	if err := migrate(ctx, writer); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("db: migrate %q: %w", path, err)
	}

	reader, err := openReader(path)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("db: open reader %q: %w", path, err)
	}
	if err := reader.PingContext(ctx); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, fmt.Errorf("db: ping reader %q: %w", path, err)
	}

	return &DB{Writer: writer, Reader: reader, path: path}, nil
}

// openWriter opens the writer pool with WAL mode and the production pragmas.
//
// Note: we intentionally do NOT use the _txlock=immediate DSN parameter. Even
// though modernc.org/sqlite documents it, we prefer to make the IMMEDIATE
// locking explicit at the call site via DB.WithWriteTx. That keeps the
// behavior visible in the Go source and immune to driver-specific quirks.
func openWriter(path string) (*sql.DB, error) {
	dsn := buildDSN(path, false)
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	// Single writer connection: serializes all writes through the Go layer,
	// which is the cleanest way to avoid SQLITE_BUSY on a single-process
	// SQLite database in WAL mode.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// openReader opens the reader pool in read-only mode.
func openReader(path string) (*sql.DB, error) {
	dsn := buildDSN(path, true)
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	maxConns := max(runtime.NumCPU(), 4)
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	return db, nil
}

// buildDSN constructs a modernc.org/sqlite DSN with the production pragmas.
// Read-only handles use the URI mode=ro flag, which prevents accidental writes
// from connections in the reader pool.
//
// Pragmas:
//   - journal_mode=WAL: readers don't block the writer and vice versa
//   - synchronous=NORMAL: safe in WAL mode, much faster than FULL
//   - foreign_keys=ON: enforce REFERENCES (off by default in SQLite)
//   - busy_timeout=5000: wait up to 5s for a lock before returning SQLITE_BUSY
func buildDSN(path string, readOnly bool) string {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=busy_timeout(5000)"
	if readOnly {
		dsn += "&mode=ro"
	}
	return dsn
}

// Close closes both the reader and writer pools. Errors are joined so we
// don't lose one when the other also fails.
func (d *DB) Close() error {
	var errs []error
	if d.Reader != nil {
		if err := d.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close reader: %w", err))
		}
	}
	if d.Writer != nil {
		if err := d.Writer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close writer: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Path returns the on-disk path of the database file.
func (d *DB) Path() string { return d.path }

// WithWriteTx runs fn inside a BEGIN IMMEDIATE transaction on the writer pool.
// It commits if fn returns nil, otherwise rolls back. Panics inside fn are
// converted to a rollback and re-raised.
//
// Why BEGIN IMMEDIATE: a SQLite DEFERRED transaction (the database/sql
// default with Begin/BeginTx) only acquires the write lock when it first
// writes. If two transactions both SELECT and then attempt to UPDATE the same
// row, the second hits SQLITE_BUSY_SNAPSHOT and database/sql cannot retry
// without losing transaction state. Taking the write lock at BEGIN serializes
// writers at the cheapest possible point.
//
// Implementation detail: database/sql doesn't expose a way to start an
// IMMEDIATE transaction portably across drivers (sql.TxOptions only carries
// an Isolation level, and modernc.org/sqlite's mapping from
// sql.LevelSerializable to "IMMEDIATE" is not part of any contract we want to
// rely on). Instead we acquire a dedicated *sql.Conn, issue "BEGIN IMMEDIATE"
// as raw SQL, and expose the conn through a narrow Tx interface that only
// permits Exec/Query operations. Commit and Rollback are owned by the helper.
//
// Because our writer pool has MaxOpenConns=1, this is mostly belt-and-braces:
// the Go layer already serializes writers. But making the locking semantics
// explicit at the boundary protects us if that invariant ever changes (e.g.
// migrating to a multi-process setup, or accidentally bumping the pool size).
func (d *DB) WithWriteTx(ctx context.Context, fn func(tx Tx) error) (err error) {
	conn, err := d.Writer.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire writer conn: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin immediate: %w", err)
	}

	committed := false
	defer func() {
		if r := recover(); r != nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			panic(r)
		}
		if committed {
			return
		}
		// On error (or fn returned an error), roll back. Use a fresh context
		// so we don't fail the rollback when the caller's context was
		// already cancelled — leaving an open SQLite transaction would
		// hold the write lock for the next caller.
		if _, rbErr := conn.ExecContext(context.Background(), "ROLLBACK"); rbErr != nil && err == nil {
			err = fmt.Errorf("rollback: %w", rbErr)
		}
	}()

	if fnErr := fn(conn); fnErr != nil {
		return fnErr
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}
