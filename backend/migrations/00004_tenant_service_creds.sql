-- +goose Up
-- +goose StatementBegin
-- Per-tenant Exchange Online and SharePoint admin app registrations (optional;
-- empty = reuse the tenant's Graph app / the global RTM_ENTRA_* app). Secrets
-- are write-only through the API: handlers never return them and they must
-- never be logged. The SharePoint admin URL (e.g. https://contoso-admin.
-- sharepoint.com) is required for the SharePoint admin API, which can't derive
-- it reliably from the primary domain.
ALTER TABLE tenants ADD COLUMN exchange_client_id       TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN exchange_client_secret   TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN sharepoint_client_id     TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN sharepoint_client_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN sharepoint_admin_url     TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenants DROP COLUMN IF EXISTS sharepoint_admin_url;
ALTER TABLE tenants DROP COLUMN IF EXISTS sharepoint_client_secret;
ALTER TABLE tenants DROP COLUMN IF EXISTS sharepoint_client_id;
ALTER TABLE tenants DROP COLUMN IF EXISTS exchange_client_secret;
ALTER TABLE tenants DROP COLUMN IF EXISTS exchange_client_id;
-- +goose StatementEnd
