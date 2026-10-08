-- +goose Up
-- +goose StatementBegin
ALTER TABLE security_audit_events
    ADD COLUMN semantic_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN canonical_event_id TEXT REFERENCES security_audit_events(id) ON DELETE CASCADE;

UPDATE security_audit_events
SET semantic_key = tenant_id || '|' ||
    regexp_replace(lower(operation), '[^a-z0-9]', '', 'g') || '|' ||
    regexp_replace(lower(actor), '[^a-z0-9]', '', 'g') || '|' ||
    regexp_replace(lower(object_id), '[^a-z0-9]', '', 'g') || '|' ||
    regexp_replace(lower(client_ip), '[^a-z0-9]', '', 'g') || '|' ||
    regexp_replace(lower(result_status), '[^a-z0-9]', '', 'g')
WHERE operation <> '' AND actor <> '';

-- Mark historical cross-source copies without deleting immutable provider
-- evidence. Ten seconds is narrow enough to avoid merging repeated operator
-- actions while tolerating small publication timestamp differences.
WITH ordered AS (
    SELECT id, semantic_key, occurred_at, available_at,
           lag(occurred_at) OVER (PARTITION BY semantic_key ORDER BY occurred_at, available_at, id) AS previous_at
    FROM security_audit_events
    WHERE semantic_key <> ''
), marked AS (
    SELECT *, CASE WHEN previous_at IS NULL OR occurred_at - previous_at > interval '10 seconds' THEN 1 ELSE 0 END AS new_cluster
    FROM ordered
), clustered AS (
    SELECT *, sum(new_cluster) OVER (PARTITION BY semantic_key ORDER BY occurred_at, available_at, id) AS cluster_id
    FROM marked
), ranked AS (
    SELECT id,
           first_value(id) OVER (PARTITION BY semantic_key, cluster_id ORDER BY available_at, occurred_at, id) AS canonical_id,
           row_number() OVER (PARTITION BY semantic_key, cluster_id ORDER BY available_at, occurred_at, id) AS position
    FROM clustered
)
UPDATE security_audit_events event
SET canonical_event_id = ranked.canonical_id
FROM ranked
WHERE event.id = ranked.id AND ranked.position > 1;

CREATE TABLE security_audit_event_aliases (
    event_id           TEXT NOT NULL REFERENCES security_audit_events(id) ON DELETE CASCADE,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source             TEXT NOT NULL,
    provider_record_id TEXT NOT NULL,
    PRIMARY KEY (event_id, source, provider_record_id),
    UNIQUE (tenant_id, source, provider_record_id)
);

INSERT INTO security_audit_event_aliases (event_id, tenant_id, source, provider_record_id)
SELECT COALESCE(canonical_event_id, id), tenant_id, source, provider_record_id
FROM security_audit_events
CROSS JOIN LATERAL unnest(sources) AS source
ON CONFLICT DO NOTHING;

WITH source_rows AS (
    SELECT COALESCE(canonical_event_id, id) AS canonical_id, unnest(sources) AS source
    FROM security_audit_events
), merged AS (
    SELECT canonical_id, array_agg(DISTINCT source ORDER BY source) AS sources
    FROM source_rows GROUP BY canonical_id
)
UPDATE security_audit_events event
SET sources = merged.sources
FROM merged
WHERE event.id = merged.canonical_id;

CREATE INDEX idx_security_audit_events_semantic_time
    ON security_audit_events (tenant_id, semantic_key, occurred_at)
    WHERE semantic_key <> '' AND canonical_event_id IS NULL;
CREATE INDEX idx_security_audit_events_canonical
    ON security_audit_events (canonical_event_id)
    WHERE canonical_event_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS security_audit_event_aliases;
DROP INDEX IF EXISTS idx_security_audit_events_canonical;
DROP INDEX IF EXISTS idx_security_audit_events_semantic_time;
ALTER TABLE security_audit_events
    DROP COLUMN IF EXISTS canonical_event_id,
    DROP COLUMN IF EXISTS semantic_key;
-- +goose StatementEnd
