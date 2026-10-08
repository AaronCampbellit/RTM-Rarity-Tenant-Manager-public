-- +goose Up
-- Source files can be as large as 1 GiB. Chunking keeps each encrypted/base64
-- value comfortably below PostgreSQL's per-value limit while preserving the
-- existing write-only, encrypted-at-rest evidence contract.
CREATE TABLE offline_investigation_file_chunks (
    file_id text NOT NULL REFERENCES offline_investigation_files(id) ON DELETE CASCADE,
    chunk_index integer NOT NULL,
    sealed_content text NOT NULL,
    PRIMARY KEY (file_id, chunk_index)
);

-- +goose Down
DROP TABLE offline_investigation_file_chunks;
