-- +goose Up
-- +goose StatementBegin
-- Per-tenant Entra app credentials (optional; empty = use the global
-- RTM_ENTRA_* app). The secret is write-only through the API: handlers never
-- return it and it must never be logged.
ALTER TABLE tenants ADD COLUMN client_id     TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN client_secret TEXT NOT NULL DEFAULT '';

-- Forced password rotation: accounts seeded/created with a default password
-- must change it on first login before using the rest of the API.
ALTER TABLE accounts ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE accounts DROP COLUMN IF EXISTS must_change_password;
ALTER TABLE tenants DROP COLUMN IF EXISTS client_secret;
ALTER TABLE tenants DROP COLUMN IF EXISTS client_id;
-- +goose StatementEnd
