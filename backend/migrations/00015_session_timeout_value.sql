-- +goose Up
-- +goose StatementBegin
ALTER TABLE app_settings
    ADD COLUMN value TEXT NOT NULL DEFAULT '';

UPDATE app_settings
SET label = 'Session timeout',
    description = 'Access tokens expire after the selected duration. Changes apply to new sign-ins and refreshed sessions.',
    enabled = true,
    value = '30'
WHERE key = 'session_timeout';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE app_settings
SET label = 'Session timeout — 30 minutes',
    description = 'Short-lived bearer token re-authentication.',
    enabled = true
WHERE key = 'session_timeout';

ALTER TABLE app_settings
    DROP COLUMN IF EXISTS value;
-- +goose StatementEnd
