-- +goose Up
-- +goose StatementBegin
-- Provider aliases already map every source record to one canonical event.
-- Retain the source-native payload and lifecycle timestamps on that durable
-- mapping so semantic deduplication never discards investigation evidence.
ALTER TABLE security_audit_event_aliases
    ADD COLUMN content_type TEXT NOT NULL DEFAULT '',
    ADD COLUMN available_at TIMESTAMPTZ,
    ADD COLUMN ingested_at TIMESTAMPTZ,
    ADD COLUMN raw JSONB;

-- Backfill only payloads whose stored content type proves the provider source.
-- Some existing Graph-first rows had their canonical payload replaced by the
-- later Management Activity copy; those cannot be recovered honestly here.
UPDATE security_audit_event_aliases alias
SET content_type = event.content_type,
    available_at = event.available_at,
    ingested_at = event.ingested_at,
    raw = event.raw
FROM security_audit_events event
WHERE event.tenant_id = alias.tenant_id
  AND event.provider_record_id = alias.provider_record_id
  AND (
      (alias.source = 'entra_graph' AND event.content_type LIKE 'Graph.%') OR
      (alias.source = 'm365_audit' AND event.content_type LIKE 'Audit.%')
  );

CREATE INDEX idx_security_audit_event_aliases_event_evidence
    ON security_audit_event_aliases (event_id, source)
    WHERE raw IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_security_audit_event_aliases_event_evidence;
ALTER TABLE security_audit_event_aliases
    DROP COLUMN IF EXISTS raw,
    DROP COLUMN IF EXISTS ingested_at,
    DROP COLUMN IF EXISTS available_at,
    DROP COLUMN IF EXISTS content_type;
-- +goose StatementEnd
