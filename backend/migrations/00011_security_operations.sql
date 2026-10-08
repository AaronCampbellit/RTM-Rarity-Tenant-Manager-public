-- +goose Up
-- +goose StatementBegin
-- Microsoft Defender remains the incident/evidence source of truth. RTM only
-- persists its local SOC workflow overlay so assigning or resolving an
-- incident does not duplicate sensitive provider payloads in PostgreSQL.
CREATE TABLE security_incident_states (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id TEXT NOT NULL,
    status      TEXT NOT NULL,
    owner       TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, incident_id),
    CONSTRAINT security_incident_states_status_check
        CHECK (status IN ('New', 'In Progress', 'Resolved', 'Dismissed'))
);

CREATE INDEX idx_security_incident_states_updated
    ON security_incident_states (updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS security_incident_states;
-- +goose StatementEnd
