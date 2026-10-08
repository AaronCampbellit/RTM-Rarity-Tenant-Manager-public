-- +goose Up
-- +goose StatementBegin
-- Everything the console shows must be real: change records carry their full
-- detail (before/after state, execution log, revert payload) written by the
-- worker, technicians derive from real login accounts, and the seeded demo
-- rows are purged from existing databases.

-- Full change detail, written by the worker when a job executes.
ALTER TABLE change_history ADD COLUMN detail JSONB NOT NULL DEFAULT '{}';

-- Operator role lives on the account (accounts are the technician source now).
ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'Engineer';
UPDATE accounts SET role = 'MSP Admin' WHERE is_admin;

-- The technicians display table duplicated (fake) people; drop it.
DROP TABLE IF EXISTS technicians;

-- Purge the seeded demo rows from databases created before this migration.
DELETE FROM jobs           WHERE id IN ('job_8f3a2c','job_7d1b90','job_6c0a55','job_5b9f12','job_4a8e77','job_2e6c44','job_1d5b22');
DELETE FROM change_history WHERE id IN ('chg_1','chg_2','chg_3','chg_4','chg_5','chg_6','chg_7','chg_8');
DELETE FROM audit_logs     WHERE id IN ('aud_1','aud_2','aud_3','aud_4','aud_5','aud_6');
DELETE FROM working_sets   WHERE id IN ('ws_1','ws_2','ws_3','ws_4','ws_5','ws_6');

-- The approval engine isn't built yet; don't claim approvals are required.
UPDATE app_settings SET enabled = false WHERE key = 'require_approval';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE technicians (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL,
    tenants     TEXT NOT NULL DEFAULT '0',
    status      TEXT NOT NULL DEFAULT 'Invited',
    last_active TEXT NOT NULL DEFAULT ''
);
ALTER TABLE accounts DROP COLUMN IF EXISTS role;
ALTER TABLE change_history DROP COLUMN IF EXISTS detail;
-- +goose StatementEnd
