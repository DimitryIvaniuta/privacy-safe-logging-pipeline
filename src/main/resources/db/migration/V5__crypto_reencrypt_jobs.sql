-- Background re-encryption jobs for key rotation.
CREATE TABLE IF NOT EXISTS audit.crypto_reencrypt_jobs (
    job_id          UUID PRIMARY KEY,
    from_kid        VARCHAR(64) NOT NULL,
    to_kid          VARCHAR(64) NOT NULL,
    status          VARCHAR(32) NOT NULL, -- NEW | RUNNING | DONE | FAILED | CANCELED
    batch_size      INT NOT NULL DEFAULT 200,
    throttle_ms     INT NOT NULL DEFAULT 25,

    last_created_at TIMESTAMPTZ,
    last_id         UUID,

    processed       BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    requested_by    VARCHAR(128),
    last_error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_crypto_reencrypt_jobs_status ON audit.crypto_reencrypt_jobs(status);
