-- +goose Up
-- +goose StatementBegin
-- RTM keeps provider incident content in Microsoft, but needs a durable first
-- observation time so the SOC queue can report when an incident reached RTM.
ALTER TABLE security_incident_states
    ADD COLUMN received_at TIMESTAMPTZ;

-- Existing workflow overlays predate receipt tracking. Their first RTM-local
-- update is the closest durable observation available for a safe backfill.
UPDATE security_incident_states
SET received_at = updated_at
WHERE received_at IS NULL;

ALTER TABLE security_incident_states
    ALTER COLUMN received_at SET DEFAULT now(),
    ALTER COLUMN received_at SET NOT NULL;

CREATE INDEX idx_security_incident_states_received
    ON security_incident_states (received_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_security_incident_states_received;
ALTER TABLE security_incident_states DROP COLUMN IF EXISTS received_at;
-- +goose StatementEnd
