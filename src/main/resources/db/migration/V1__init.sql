CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.audit_events (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(200),
    correlation_id VARCHAR(100),
    payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit.audit_events(created_at DESC);
