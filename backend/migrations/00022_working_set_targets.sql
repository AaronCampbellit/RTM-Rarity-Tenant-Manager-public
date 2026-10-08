-- +goose Up
-- +goose StatementBegin
ALTER TABLE working_sets
    ADD COLUMN description TEXT NOT NULL DEFAULT '',
    ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN user_ids TEXT[] NOT NULL DEFAULT '{}';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE working_sets
    DROP COLUMN IF EXISTS user_ids,
    DROP COLUMN IF EXISTS tenant_id,
    DROP COLUMN IF EXISTS description;
-- +goose StatementEnd
