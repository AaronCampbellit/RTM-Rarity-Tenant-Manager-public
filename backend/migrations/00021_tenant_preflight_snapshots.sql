-- +goose Up
-- +goose StatementBegin
CREATE TABLE tenant_preflight_snapshots (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    mode      TEXT NOT NULL CHECK (mode IN ('sample','live')),
    ran_at    TIMESTAMPTZ NOT NULL,
    checks    JSONB NOT NULL DEFAULT '[]'::jsonb
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tenant_preflight_snapshots;
-- +goose StatementEnd
