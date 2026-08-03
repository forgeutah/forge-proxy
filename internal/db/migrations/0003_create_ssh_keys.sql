-- +goose Up
-- +goose StatementBegin
CREATE TABLE ssh_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint   TEXT    NOT NULL UNIQUE,
    key_type      TEXT    NOT NULL,
    public_key    BLOB    NOT NULL,
    label         TEXT,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX ssh_keys_user_id ON ssh_keys(user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS ssh_keys_user_id;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE ssh_keys;
-- +goose StatementEnd
