-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slack_user_id TEXT    NOT NULL UNIQUE,
    slack_team_id TEXT    NOT NULL,
    email         TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    avatar_url    TEXT    NOT NULL,
    roles         TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
-- +goose StatementEnd
