-- +goose Up
-- +goose StatementBegin
ALTER TABLE jobs ADD COLUMN acknowledged BOOLEAN NOT NULL DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE jobs DROP COLUMN IF EXISTS acknowledged;
-- +goose StatementEnd
