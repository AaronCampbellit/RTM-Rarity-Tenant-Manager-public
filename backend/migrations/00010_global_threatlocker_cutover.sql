-- +goose Up
-- +goose StatementBegin
-- ThreatLocker is configured once for the MSP workspace. Tenant rows no
-- longer carry portal credentials or organization identifiers.
ALTER TABLE tenants DROP COLUMN IF EXISTS threatlocker_org_id;
ALTER TABLE tenants DROP COLUMN IF EXISTS threatlocker_token;
ALTER TABLE tenants DROP COLUMN IF EXISTS threatlocker_instance;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenants ADD COLUMN threatlocker_instance TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN threatlocker_token    TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN threatlocker_org_id   TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd
