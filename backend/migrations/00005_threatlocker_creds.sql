-- +goose Up
-- +goose StatementBegin
-- Per-tenant ThreatLocker connection: the portal instance (region identifier,
-- e.g. "g"), an API token from a ThreatLocker API User, and the tenant's
-- organization GUID (sent as managedOrganizationId on every call). Instance
-- and token may be empty when the global RTM_THREATLOCKER_* app is used; the
-- org ID is always per-tenant. The token is write-only through the API:
-- handlers never return it and it must never be logged.
ALTER TABLE tenants ADD COLUMN threatlocker_instance TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN threatlocker_token    TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN threatlocker_org_id   TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenants DROP COLUMN IF EXISTS threatlocker_org_id;
ALTER TABLE tenants DROP COLUMN IF EXISTS threatlocker_token;
ALTER TABLE tenants DROP COLUMN IF EXISTS threatlocker_instance;
-- +goose StatementEnd
