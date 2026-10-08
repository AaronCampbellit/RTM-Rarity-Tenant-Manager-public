-- +goose Up
-- +goose StatementBegin
CREATE TABLE threatlocker_global_config (
    singleton     BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    instance      TEXT NOT NULL DEFAULT '',
    token         TEXT NOT NULL DEFAULT '',
    parent_org_id TEXT NOT NULL DEFAULT '',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS threatlocker_global_config;
-- +goose StatementEnd
