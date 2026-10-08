-- +goose Up
-- +goose StatementBegin
CREATE TABLE sharepoint_scans (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope                   TEXT NOT NULL,
    site_id                 TEXT NOT NULL DEFAULT '',
    node_id                 TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL,
    trigger                 TEXT NOT NULL,
    started_by              TEXT NOT NULL,
    started_at              TIMESTAMPTZ NOT NULL,
    completed_at            TIMESTAMPTZ,
    coverage                TEXT NOT NULL DEFAULT 'pending',
    site_count              INTEGER NOT NULL DEFAULT 0,
    library_count           INTEGER NOT NULL DEFAULT 0,
    folder_count            INTEGER NOT NULL DEFAULT 0,
    file_count              INTEGER NOT NULL DEFAULT 0,
    total_bytes             BIGINT NOT NULL DEFAULT 0,
    unique_permission_count INTEGER NOT NULL DEFAULT 0,
    warnings                JSONB NOT NULL DEFAULT '[]',
    error                   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sharepoint_scans_tenant_started_idx
    ON sharepoint_scans (tenant_id, started_at DESC);

CREATE TABLE sharepoint_inventory_nodes (
    tenant_id               TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope                   TEXT NOT NULL,
    scan_id                 TEXT NOT NULL REFERENCES sharepoint_scans(id) ON DELETE CASCADE,
    id                      TEXT NOT NULL,
    parent_id               TEXT NOT NULL DEFAULT '',
    site_id                 TEXT NOT NULL DEFAULT '',
    drive_id                TEXT NOT NULL DEFAULT '',
    item_id                 TEXT NOT NULL DEFAULT '',
    kind                    TEXT NOT NULL,
    name                    TEXT NOT NULL,
    path                    TEXT NOT NULL,
    web_url                 TEXT NOT NULL DEFAULT '',
    size_bytes              BIGINT NOT NULL DEFAULT 0,
    file_count              INTEGER NOT NULL DEFAULT 0,
    has_unique_permissions  BOOLEAN NOT NULL DEFAULT false,
    external_sharing        TEXT NOT NULL DEFAULT '',
    last_scanned_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, scope, id)
);
CREATE INDEX sharepoint_inventory_parent_idx
    ON sharepoint_inventory_nodes (tenant_id, scope, parent_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sharepoint_inventory_nodes;
DROP TABLE IF EXISTS sharepoint_scans;
-- +goose StatementEnd
