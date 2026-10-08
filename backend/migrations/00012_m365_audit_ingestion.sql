-- +goose Up
-- +goose StatementBegin
CREATE TABLE security_audit_checkpoints (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    content_type    TEXT NOT NULL,
    status          TEXT NOT NULL,
    mode            TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    cursor_end      TIMESTAMPTZ NOT NULL,
    last_polled_at  TIMESTAMPTZ NOT NULL,
    last_event_at   TIMESTAMPTZ,
    events_received INTEGER NOT NULL DEFAULT 0,
    events_inserted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, content_type)
);

CREATE TABLE security_audit_events (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_record_id TEXT NOT NULL,
    content_type       TEXT NOT NULL,
    workload           TEXT NOT NULL DEFAULT '',
    operation          TEXT NOT NULL DEFAULT '',
    actor              TEXT NOT NULL DEFAULT '',
    client_ip          TEXT NOT NULL DEFAULT '',
    object_id          TEXT NOT NULL DEFAULT '',
    result_status      TEXT NOT NULL DEFAULT '',
    occurred_at        TIMESTAMPTZ NOT NULL,
    ingested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw                JSONB NOT NULL,
    sample             BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (tenant_id, provider_record_id)
);

CREATE INDEX idx_security_audit_events_tenant_time
    ON security_audit_events (tenant_id, occurred_at DESC);
CREATE INDEX idx_security_audit_events_operation
    ON security_audit_events (tenant_id, operation, occurred_at DESC);

CREATE TABLE security_native_detections (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_id     TEXT NOT NULL REFERENCES security_audit_events(id) ON DELETE CASCADE,
    rule_id      TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL,
    entities     JSONB NOT NULL DEFAULT '[]'::jsonb,
    occurred_at  TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    sample       BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (tenant_id, event_id, rule_id, rule_version)
);

CREATE INDEX idx_security_native_detections_tenant_time
    ON security_native_detections (tenant_id, occurred_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS security_native_detections;
DROP TABLE IF EXISTS security_audit_events;
DROP TABLE IF EXISTS security_audit_checkpoints;
-- +goose StatementEnd
