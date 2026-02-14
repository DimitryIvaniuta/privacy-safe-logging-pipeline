-- Key policy metadata for operational lifecycle (ACTIVE/DEPRECATED).
-- Key material is NOT stored here.
CREATE TABLE IF NOT EXISTS audit.crypto_key_policy (
    kid              VARCHAR(64) PRIMARY KEY,
    status           VARCHAR(16) NOT NULL, -- ACTIVE | DEPRECATED
    deprecated_at    TIMESTAMPTZ,
    deprecated_until TIMESTAMPTZ,
    deprecated_by    VARCHAR(128),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ensure current active kid is present and marked ACTIVE.
INSERT INTO audit.crypto_key_policy (kid, status)
SELECT s.active_kid, 'ACTIVE'
FROM audit.crypto_keyring_state s
WHERE NOT EXISTS (SELECT 1 FROM audit.crypto_key_policy p WHERE p.kid = s.active_kid);
