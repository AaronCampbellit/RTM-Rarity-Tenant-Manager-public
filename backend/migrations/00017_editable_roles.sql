-- +goose Up
-- +goose StatementBegin
CREATE TABLE role_policies (
    name            TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    permission_keys TEXT[] NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO role_policies (name, description, permission_keys) VALUES
    ('Admin', 'Everything across all tenants, plus platform administration: connect/remove tenants, manage technicians, execute write actions, change settings.', ARRAY['tenants.manage','technicians.manage','roles.manage','settings.manage','changes.execute','security.manage','threatlocker.manage']),
    ('Technician', 'Work across all tenants: inventory, Exchange/SharePoint/ThreatLocker detail, reports, jobs, and change history.', ARRAY[]::TEXT[]);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS role_policies;
-- +goose StatementEnd
