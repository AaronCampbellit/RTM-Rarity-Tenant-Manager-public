-- +goose Up
-- +goose StatementBegin
-- "App role assignment" is Microsoft terminology for an application
-- permission grant. Earlier rule matching also treated the phrase as a
-- directory-role membership change, producing a misleading duplicate.
DELETE FROM security_native_detections detection
USING security_audit_events event
WHERE detection.event_id = event.id
  AND detection.rule_id = 'privileged_role_change'
  AND lower(event.operation) LIKE '%app role assignment%';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Detection rows are derived evidence and are replayed by the versioned rule
-- pack; the removed false positive must not be recreated on rollback.
SELECT 1;
-- +goose StatementEnd
