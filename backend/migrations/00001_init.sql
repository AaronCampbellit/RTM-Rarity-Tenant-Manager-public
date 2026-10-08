-- +goose Up
-- +goose StatementBegin
-- RTM schema, Goose-managed (ADR-018: Goose manages all schema changes).
-- Applied automatically at startup via the goose library (embedded FS) and by
-- the `goose` CLI (make migrate-up). This is the schema the pg store queries.
-- IDs are opaque strings; presentation-facing display fields (users count,
-- relative timestamps) are stored directly. River manages its own tables.

CREATE TABLE accounts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    is_admin      BOOLEAN NOT NULL DEFAULT false,
    status        TEXT NOT NULL DEFAULT 'Invited',
    password_hash TEXT NOT NULL
);

CREATE TABLE tenants (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    domain              TEXT NOT NULL,
    microsoft_tenant_id TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'Disconnected',
    users               INT NOT NULL DEFAULT 0,
    last_graph_test     TEXT NOT NULL DEFAULT '',
    modules             TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE technicians (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL,
    tenants     TEXT NOT NULL DEFAULT '0',
    status      TEXT NOT NULL DEFAULT 'Invited',
    last_active TEXT NOT NULL DEFAULT ''
);

CREATE TABLE working_sets (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'Users',
    items      INT NOT NULL DEFAULT 0,
    tenant     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    last_used  TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    tenant       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'Queued',
    progress     INT NOT NULL DEFAULT 0,
    started      TEXT NOT NULL DEFAULT '',
    duration     TEXT NOT NULL DEFAULT '—',
    triggered_by TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE change_history (
    id         TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    technician TEXT NOT NULL DEFAULT '',
    tenant     TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL,
    revert     TEXT NOT NULL DEFAULT '—',
    sort_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id             TEXT PRIMARY KEY,
    ts             TEXT NOT NULL,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    resource       TEXT NOT NULL DEFAULT '',
    result         TEXT NOT NULL,
    correlation_id TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_settings (
    key         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT false,
    locked      BOOLEAN NOT NULL DEFAULT false
);

-- Per-account tenant access (Security Spec: server-side tenant authorization).
-- Admins bypass this; technicians are granted explicit tenants.
CREATE TABLE tenant_access (
    account_id TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    PRIMARY KEY (account_id, tenant_id)
);

-- Current refresh-token id per account (rotation + reuse rejection).
CREATE TABLE refresh_tokens (
    account_id TEXT PRIMARY KEY,
    jti        TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for common filters / ordering.
CREATE INDEX idx_jobs_created_at    ON jobs (created_at DESC);
CREATE INDEX idx_jobs_status        ON jobs (status);
CREATE INDEX idx_changes_sort_at    ON change_history (sort_at DESC);
CREATE INDEX idx_audit_created_at   ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_action       ON audit_logs (action);
CREATE INDEX idx_working_sets_created ON working_sets (created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS tenant_access;
DROP TABLE IF EXISTS app_settings;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS change_history;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS working_sets;
DROP TABLE IF EXISTS technicians;
DROP TABLE IF EXISTS tenants;
DROP TABLE IF EXISTS accounts;
-- +goose StatementEnd
