-- +goose Up
-- +goose StatementBegin
ALTER TABLE security_native_detections
    ADD COLUMN detection_type TEXT NOT NULL DEFAULT 'direct',
    ADD COLUMN confidence TEXT NOT NULL DEFAULT 'medium';

ALTER TABLE security_native_detections
    ADD CONSTRAINT security_native_detection_type_check
        CHECK (detection_type IN ('direct', 'threshold', 'correlation', 'heuristic')),
    ADD CONSTRAINT security_native_detection_confidence_check
        CHECK (confidence IN ('high', 'medium', 'low'));

CREATE INDEX idx_security_audit_events_actor_time
    ON security_audit_events (lower(actor), occurred_at DESC)
    WHERE actor <> '';
CREATE INDEX idx_security_audit_events_client_ip_time
    ON security_audit_events (client_ip, occurred_at DESC)
    WHERE client_ip <> '';
CREATE INDEX idx_security_native_detections_rule_time
    ON security_native_detections (rule_id, occurred_at DESC);

CREATE TABLE security_detection_replays (
    pack_version INTEGER PRIMARY KEY,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    events_scanned INTEGER NOT NULL,
    detections_inserted INTEGER NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS security_detection_replays;
DROP INDEX IF EXISTS idx_security_native_detections_rule_time;
DROP INDEX IF EXISTS idx_security_audit_events_client_ip_time;
DROP INDEX IF EXISTS idx_security_audit_events_actor_time;
ALTER TABLE security_native_detections
    DROP CONSTRAINT IF EXISTS security_native_detection_confidence_check,
    DROP CONSTRAINT IF EXISTS security_native_detection_type_check,
    DROP COLUMN IF EXISTS confidence,
    DROP COLUMN IF EXISTS detection_type;
-- +goose StatementEnd
