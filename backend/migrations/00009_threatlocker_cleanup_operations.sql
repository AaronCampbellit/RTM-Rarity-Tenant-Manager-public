-- +goose Up
-- +goose StatementBegin
CREATE TABLE threatlocker_cleanup_operations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    request_payload JSONB NOT NULL,
    result_payload  JSONB NOT NULL DEFAULT '{}',
    error           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tl_cleanup_operations_scope_created
    ON threatlocker_cleanup_operations (tenant_id, created_at DESC);

CREATE UNIQUE INDEX idx_tl_cleanup_operations_active_fingerprint
    ON threatlocker_cleanup_operations (fingerprint)
    WHERE status IN ('submitted', 'verification_pending', 'needs_reconciliation');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS threatlocker_cleanup_operations;
-- +goose StatementEnd
