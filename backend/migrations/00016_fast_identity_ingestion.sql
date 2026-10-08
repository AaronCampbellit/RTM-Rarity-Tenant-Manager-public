-- +goose Up
-- +goose StatementBegin
ALTER TABLE security_audit_events
    ADD COLUMN available_at TIMESTAMPTZ,
    ADD COLUMN sources TEXT[] NOT NULL DEFAULT ARRAY['m365_audit']::TEXT[];

UPDATE security_audit_events
SET available_at = ingested_at
WHERE available_at IS NULL;

ALTER TABLE security_audit_events
    ALTER COLUMN available_at SET NOT NULL;

CREATE INDEX idx_security_audit_events_source_time
    ON security_audit_events USING GIN (sources);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_security_audit_events_source_time;
ALTER TABLE security_audit_events
    DROP COLUMN IF EXISTS sources,
    DROP COLUMN IF EXISTS available_at;
-- +goose StatementEnd
