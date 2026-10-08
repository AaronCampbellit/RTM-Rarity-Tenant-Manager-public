-- +goose Up
-- +goose StatementBegin
ALTER TABLE security_native_detections
    ADD COLUMN event_ids JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Storyline evaluation is intentionally global, so tenant-leading indexes do
-- not serve its bounded lookback queries efficiently.
CREATE INDEX idx_security_native_detections_global_time
    ON security_native_detections (occurred_at DESC);
CREATE INDEX idx_security_audit_events_global_time
    ON security_audit_events (occurred_at DESC);

UPDATE security_native_detections
SET event_ids = jsonb_build_array(event_id)
WHERE event_ids = '[]'::jsonb;

CREATE TABLE security_detection_events (
    detection_id TEXT NOT NULL REFERENCES security_native_detections(id) ON DELETE CASCADE,
    event_id     TEXT NOT NULL REFERENCES security_audit_events(id) ON DELETE CASCADE,
    relationship TEXT NOT NULL DEFAULT 'supporting',
    PRIMARY KEY (detection_id, event_id)
);

INSERT INTO security_detection_events (detection_id, event_id, relationship)
SELECT id, event_id, 'anchor' FROM security_native_detections
ON CONFLICT DO NOTHING;

CREATE INDEX idx_security_detection_events_event
    ON security_detection_events (event_id, detection_id);

CREATE TABLE security_detection_entities (
    detection_id TEXT NOT NULL REFERENCES security_native_detections(id) ON DELETE CASCADE,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type  TEXT NOT NULL,
    entity_key   TEXT NOT NULL,
    label        TEXT NOT NULL,
    PRIMARY KEY (detection_id, entity_key)
);

CREATE INDEX idx_security_detection_entities_key
    ON security_detection_entities (entity_key, detection_id);
CREATE INDEX idx_security_detection_entities_tenant_type
    ON security_detection_entities (tenant_id, entity_type, entity_key);

INSERT INTO security_detection_entities (detection_id, tenant_id, entity_type, entity_key, label)
SELECT detection.id,
       detection.tenant_id,
       COALESCE(NULLIF(entity.value->>'type',''), 'resource'),
       detection.tenant_id || '|' || lower(COALESCE(NULLIF(entity.value->>'type',''), 'resource')) || '|' || lower(entity.value->>'label'),
       entity.value->>'label'
FROM security_native_detections detection
CROSS JOIN LATERAL jsonb_array_elements(detection.entities) entity(value)
WHERE COALESCE(entity.value->>'label','') <> ''
ON CONFLICT DO NOTHING;

CREATE TABLE security_storylines (
    id                  TEXT PRIMARY KEY,
    correlation_key     TEXT NOT NULL UNIQUE,
    pack_id             TEXT NOT NULL,
    title               TEXT NOT NULL,
    summary             TEXT NOT NULL,
    severity            TEXT NOT NULL,
    risk_score          INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence          TEXT NOT NULL CHECK (confidence IN ('high','medium','low')),
    status              TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New','In Progress','Resolved','Dismissed')),
    owner               TEXT NOT NULL DEFAULT '',
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_ids          JSONB NOT NULL DEFAULT '[]'::jsonb,
    tenant_names        JSONB NOT NULL DEFAULT '[]'::jsonb,
    entities            JSONB NOT NULL DEFAULT '[]'::jsonb,
    stages              JSONB NOT NULL DEFAULT '[]'::jsonb,
    workloads           JSONB NOT NULL DEFAULT '[]'::jsonb,
    detection_ids       JSONB NOT NULL DEFAULT '[]'::jsonb,
    event_ids           JSONB NOT NULL DEFAULT '[]'::jsonb,
    signal_count        INTEGER NOT NULL DEFAULT 0,
    affected_users      INTEGER NOT NULL DEFAULT 0,
    affected_resources  INTEGER NOT NULL DEFAULT 0,
    reasons             JSONB NOT NULL DEFAULT '[]'::jsonb,
    weak_evidence       JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    sample              BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_security_storylines_active_risk
    ON security_storylines (status, risk_score DESC, last_seen DESC);
CREATE INDEX idx_security_storylines_last_seen
    ON security_storylines (last_seen DESC);

CREATE TABLE security_storyline_detections (
    storyline_id TEXT NOT NULL REFERENCES security_storylines(id) ON DELETE CASCADE,
    detection_id TEXT NOT NULL REFERENCES security_native_detections(id) ON DELETE CASCADE,
    PRIMARY KEY (storyline_id, detection_id)
);

CREATE INDEX idx_security_storyline_detections_detection
    ON security_storyline_detections (detection_id, storyline_id);

CREATE TABLE security_storyline_tenants (
    storyline_id TEXT NOT NULL REFERENCES security_storylines(id) ON DELETE CASCADE,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    PRIMARY KEY (storyline_id, tenant_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS security_storyline_tenants;
DROP TABLE IF EXISTS security_storyline_detections;
DROP TABLE IF EXISTS security_storylines;
DROP TABLE IF EXISTS security_detection_entities;
DROP TABLE IF EXISTS security_detection_events;
DROP INDEX IF EXISTS idx_security_audit_events_global_time;
DROP INDEX IF EXISTS idx_security_native_detections_global_time;
ALTER TABLE security_native_detections DROP COLUMN IF EXISTS event_ids;
-- +goose StatementEnd
