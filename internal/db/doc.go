// Package db opens SQLite via the pure-Go modernc.org/sqlite driver,
// configures the writer/reader pool split with WAL mode, and runs
// embedded goose migrations at startup.
package db
