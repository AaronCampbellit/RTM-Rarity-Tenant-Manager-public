-- +goose Up
-- +goose StatementBegin
-- Version zero preserves every token issued before this migration. A password
-- change or admin reset increments the value, immediately invalidating tokens
-- carrying the previous credential version.
ALTER TABLE accounts
    ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE accounts DROP COLUMN IF EXISTS credential_version;
-- +goose StatementEnd
