package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages background re-encryption jobs (throttled, resumable).
 */
@Service
public class AuditReencryptJobService {

    private final JdbcTemplate jdbc;

    public AuditReencryptJobService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public UUID start(String fromKid, String toKid, int batchSize, int throttleMs, String requestedBy) {
        UUID jobId = UUID.randomUUID();
        int safeBatch = Math.max(1, Math.min(batchSize, 5_000));
        int safeThrottle = Math.max(0, Math.min(throttleMs, 10_000));

        jdbc.update(
                "insert into audit.crypto_reencrypt_jobs " +
                        "(job_id, from_kid, to_kid, status, batch_size, throttle_ms, requested_by, created_at, updated_at, started_at) " +
                        "values (?, ?, ?, 'RUNNING', ?, ?, ?, now(), now(), now())",
                jobId, fromKid, toKid, safeBatch, safeThrottle, requestedBy
        );
        return jobId;
    }

    public Optional<Job> get(UUID jobId) {
        return jdbc.query(
                "select job_id, from_kid, to_kid, status, batch_size, throttle_ms, " +
                        "last_created_at, last_id, processed, created_at, updated_at, started_at, finished_at, requested_by, last_error " +
                        "from audit.crypto_reencrypt_jobs where job_id = ?",
                (ResultSet rs) -> rs.next() ? Optional.of(map(rs)) : Optional.empty(),
                jobId
        );
    }

    @Transactional
    public boolean cancel(UUID jobId) {
        int updated = jdbc.update(
                "update audit.crypto_reencrypt_jobs set status = 'CANCELED', updated_at = now(), finished_at = now() " +
                        "where job_id = ? and status in ('NEW','RUNNING')",
                jobId
        );
        return updated > 0;
    }

    @Transactional
    Job claimNextRunningJob() {
        // One worker claim (FOR UPDATE SKIP LOCKED) to support multiple instances safely.
        return jdbc.query(
                "select job_id, from_kid, to_kid, status, batch_size, throttle_ms, " +
                        "last_created_at, last_id, processed, created_at, updated_at, started_at, finished_at, requested_by, last_error " +
                        "from audit.crypto_reencrypt_jobs " +
                        "where status = 'RUNNING' " +
                        "order by created_at asc " +
                        "limit 1 " +
                        "for update skip locked",
                (ResultSet rs) -> rs.next() ? map(rs) : null
        );
    }

    @Transactional
    void markDone(UUID jobId) {
        jdbc.update("update audit.crypto_reencrypt_jobs set status = 'DONE', updated_at = now(), finished_at = now() where job_id = ?",
                jobId);
    }

    @Transactional
    void markFailed(UUID jobId, String error) {
        jdbc.update("update audit.crypto_reencrypt_jobs set status = 'FAILED', updated_at = now(), finished_at = now(), last_error = ? where job_id = ?",
                error, jobId);
    }

    @Transactional
    void updateProgress(UUID jobId, long processedDelta, Instant lastCreatedAt, UUID lastId) {
        jdbc.update(
                "update audit.crypto_reencrypt_jobs " +
                        "set processed = processed + ?, last_created_at = ?, last_id = ?, updated_at = now() " +
                        "where job_id = ?",
                processedDelta, lastCreatedAt, lastId == null ? null : lastId, jobId
        );
    }

    private static Job map(ResultSet rs) throws java.sql.SQLException {
        return new Job(
                UUID.fromString(rs.getString("job_id")),
                rs.getString("from_kid"),
                rs.getString("to_kid"),
                rs.getString("status"),
                rs.getInt("batch_size"),
                rs.getInt("throttle_ms"),
                rs.getTimestamp("last_created_at") == null ? null : rs.getTimestamp("last_created_at").toInstant(),
                rs.getString("last_id") == null ? null : UUID.fromString(rs.getString("last_id")),
                rs.getLong("processed"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant(),
                rs.getTimestamp("started_at") == null ? null : rs.getTimestamp("started_at").toInstant(),
                rs.getTimestamp("finished_at") == null ? null : rs.getTimestamp("finished_at").toInstant(),
                rs.getString("requested_by"),
                rs.getString("last_error")
        );
    }

    public record Job(UUID jobId,
                      String fromKid,
                      String toKid,
                      String status,
                      int batchSize,
                      int throttleMs,
                      Instant lastCreatedAt,
                      UUID lastId,
                      long processed,
                      Instant createdAt,
                      Instant updatedAt,
                      Instant startedAt,
                      Instant finishedAt,
                      String requestedBy,
                      String lastError) {}
}
