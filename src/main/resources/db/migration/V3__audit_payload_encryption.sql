-- Audit payloads are now stored encrypted as an envelope JSON in audit.audit_events.payload.
-- To support key rotation operations, we index the kid extracted from JSONB.
CREATE INDEX IF NOT EXISTS idx_audit_events_payload_kid ON audit.audit_events ((payload->>'kid'));
