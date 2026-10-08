-- +goose Up
CREATE TABLE offline_investigations (
    id text PRIMARY KEY,
    name text NOT NULL,
    tenant_label text NOT NULL,
    status text NOT NULL DEFAULT 'draft',
    progress integer NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    detail text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    analyzed_at timestamptz,
    period_start timestamptz,
    period_end timestamptz,
    event_count integer NOT NULL DEFAULT 0,
    detection_count integer NOT NULL DEFAULT 0,
    high_priority_count integer NOT NULL DEFAULT 0,
    storyline_count integer NOT NULL DEFAULT 0,
    coverage jsonb NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE offline_investigation_files (
    id text PRIMARY KEY,
    investigation_id text NOT NULL REFERENCES offline_investigations(id) ON DELETE CASCADE,
    name text NOT NULL,
    media_type text NOT NULL,
    evidence_type text NOT NULL,
    size_bytes bigint NOT NULL,
    sha256 text NOT NULL,
    status text NOT NULL DEFAULT 'ready',
    record_count integer NOT NULL DEFAULT 0,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    sealed_content text NOT NULL,
    UNIQUE (investigation_id, sha256)
);

CREATE TABLE offline_investigation_events (
    investigation_id text NOT NULL REFERENCES offline_investigations(id) ON DELETE CASCADE,
    id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (investigation_id, id)
);

CREATE TABLE offline_investigation_detections (
    investigation_id text NOT NULL REFERENCES offline_investigations(id) ON DELETE CASCADE,
    id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (investigation_id, id)
);

CREATE TABLE offline_investigation_storylines (
    investigation_id text NOT NULL REFERENCES offline_investigations(id) ON DELETE CASCADE,
    id text NOT NULL,
    last_seen timestamptz NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (investigation_id, id)
);

CREATE INDEX offline_investigations_updated_idx ON offline_investigations(updated_at DESC);
CREATE INDEX offline_investigation_events_time_idx ON offline_investigation_events(investigation_id, occurred_at DESC);
CREATE INDEX offline_investigation_detections_time_idx ON offline_investigation_detections(investigation_id, occurred_at DESC);

-- +goose Down
DROP TABLE offline_investigation_storylines;
DROP TABLE offline_investigation_detections;
DROP TABLE offline_investigation_events;
DROP TABLE offline_investigation_files;
DROP TABLE offline_investigations;
