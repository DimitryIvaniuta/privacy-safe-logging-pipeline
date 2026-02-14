ALTER TABLE audit.audit_events
    ADD COLUMN IF NOT EXISTS prev_hash BYTEA,
    ADD COLUMN IF NOT EXISTS hash BYTEA NOT NULL DEFAULT ''::bytea;

CREATE INDEX IF NOT EXISTS idx_audit_events_hash ON audit.audit_events(hash);
