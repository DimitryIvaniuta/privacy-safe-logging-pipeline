-- Stores runtime-active key-id (kid) for audit payload encryption.
CREATE TABLE IF NOT EXISTS audit.crypto_keyring_state (
    id            INT PRIMARY KEY,
    active_kid    VARCHAR(64) NOT NULL,
    promoted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    promoted_by   VARCHAR(128),
    version       INT NOT NULL DEFAULT 0
);

-- Ensure singleton row exists (id=1). If already exists, no-op.
INSERT INTO audit.crypto_keyring_state (id, active_kid)
SELECT 1, 'k1'
WHERE NOT EXISTS (SELECT 1 FROM audit.crypto_keyring_state WHERE id = 1);
