-- +goose Up
-- +goose StatementBegin
CREATE TABLE security_detection_rules (
    id             TEXT PRIMARY KEY,
    rule_id        TEXT NOT NULL,
    base_rule_id   TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    built_in       BOOLEAN NOT NULL DEFAULT false,
    detection_type TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT false,
    scope          TEXT NOT NULL,
    tenant_id      TEXT NOT NULL DEFAULT '',
    definition     JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision       INTEGER NOT NULL DEFAULT 1,
    updated_by     TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_id, scope, tenant_id),
    CHECK (detection_type IN ('direct', 'threshold', 'correlation', 'heuristic')),
    CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    CHECK (confidence IN ('high', 'medium', 'low')),
    CHECK (scope IN ('global', 'tenant')),
    CHECK ((scope = 'global' AND tenant_id = '') OR (scope = 'tenant' AND tenant_id <> '')),
    CHECK ((base_rule_id = '' AND built_in = false) OR (base_rule_id <> '' AND built_in = true))
);

CREATE INDEX idx_security_detection_rules_base_scope
    ON security_detection_rules (base_rule_id, scope, tenant_id);

CREATE TABLE security_detection_rule_revisions (
    rule_id     TEXT NOT NULL REFERENCES security_detection_rules(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL,
    snapshot    JSONB NOT NULL,
    actor       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, revision)
);

CREATE INDEX idx_security_audit_events_workload_time
    ON security_audit_events (lower(workload), occurred_at DESC);
CREATE INDEX idx_security_audit_events_result_time
    ON security_audit_events (lower(result_status), occurred_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_security_audit_events_result_time;
DROP INDEX IF EXISTS idx_security_audit_events_workload_time;
DROP TABLE IF EXISTS security_detection_rule_revisions;
DROP TABLE IF EXISTS security_detection_rules;
-- +goose StatementEnd
