-- +goose Up
-- +goose StatementBegin
CREATE TABLE security_history_imports (
    tenant_id                TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    job_id                   TEXT NOT NULL DEFAULT '',
    requested_window         TEXT NOT NULL,
    window_hours             INTEGER NOT NULL DEFAULT 0 CHECK (window_hours BETWEEN 0 AND 168),
    historical_incident_mode TEXT NOT NULL CHECK (historical_incident_mode IN ('recent_24h','all','baseline_only')),
    status                   TEXT NOT NULL CHECK (status IN ('queued','running','completed','partial','failed')),
    progress                 INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    feeds_completed          INTEGER NOT NULL DEFAULT 0,
    feeds_total              INTEGER NOT NULL DEFAULT 0,
    events_received          INTEGER NOT NULL DEFAULT 0,
    events_inserted          INTEGER NOT NULL DEFAULT 0,
    detections_created       INTEGER NOT NULL DEFAULT 0,
    detail                   TEXT NOT NULL DEFAULT '',
    requested_at             TIMESTAMPTZ NOT NULL,
    started_at               TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    incident_cutoff_at       TIMESTAMPTZ
);

CREATE INDEX idx_security_history_imports_status
    ON security_history_imports (status, requested_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS security_history_imports;
-- +goose StatementEnd
