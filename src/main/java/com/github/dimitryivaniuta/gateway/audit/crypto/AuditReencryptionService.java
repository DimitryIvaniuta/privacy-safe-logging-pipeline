package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Re-encrypts existing audit rows when rotating keys.
 *
 * <p>Important: the audit hash chain remains valid because it is computed over plaintext payload,
 * not over the encrypted envelope stored in DB.</p>
 */
@Service
public class AuditReencryptionService {

    private final JdbcTemplate jdbc;
    private final AuditCryptoService crypto;

    public AuditReencryptionService(JdbcTemplate jdbc, AuditCryptoService crypto) {
        this.jdbc = jdbc;
        this.crypto = crypto;
    }

    /**
     * Synchronous one-off re-encryption (kept for manual operations).
     */
    @Transactional
    public int reencryptBatch(String fromKid, String toKid, int limit) {
        BatchResult r = reencryptBatchWithCheckpoint(fromKid, toKid, limit, null, null);
        return (int) r.processed();
    }

    /**
     * Re-encrypts a batch starting after the last checkpoint (createdAt, id).
     * Uses {@code FOR UPDATE SKIP LOCKED} to be safe under concurrency.
     */
    @Transactional
    public BatchResult reencryptBatchWithCheckpoint(String fromKid,
                                                   String toKid,
                                                   int limit,
                                                   Instant lastCreatedAt,
                                                   UUID lastId) {
        int safeLimit = Math.max(1, Math.min(limit, 5_000));
        if (!crypto.hasKid(fromKid)) {
            throw new IllegalArgumentException("Unknown fromKid: " + fromKid);
        }
        if (!crypto.hasKid(toKid)) {
            throw new IllegalArgumentException("Unknown toKid: " + toKid);
        }

        final List<Row> rows;
        if (lastCreatedAt == null || lastId == null) {
            rows = jdbc.query(
                    "select id, created_at, event_type, payload::text as payload_json " +
                            "from audit.audit_events " +
                            "where payload->>'kid' = ? " +
                            "order by created_at asc, id asc " +
                            "limit ? " +
                            "for update skip locked",
                    (ResultSet rs, int i) -> new Row(
                            UUID.fromString(rs.getString("id")),
                            rs.getTimestamp("created_at").toInstant(),
                            rs.getString("event_type"),
                            rs.getString("payload_json")
                    ),
                    fromKid, safeLimit
            );
        } else {
            rows = jdbc.query(
                    "select id, created_at, event_type, payload::text as payload_json " +
                            "from audit.audit_events " +
                            "where payload->>'kid' = ? " +
                            "and (created_at, id) > (?, ?) " +
                            "order by created_at asc, id asc " +
                            "limit ? " +
                            "for update skip locked",
                    (ResultSet rs, int i) -> new Row(
                            UUID.fromString(rs.getString("id")),
                            rs.getTimestamp("created_at").toInstant(),
                            rs.getString("event_type"),
                            rs.getString("payload_json")
                    ),
                    fromKid, lastCreatedAt, lastId, safeLimit
            );
        }

        long processed = 0;
        Instant newLastCreatedAt = lastCreatedAt;
        UUID newLastId = lastId;

        for (Row r : rows) {
            String plaintext = crypto.decryptFromJson(r.payloadJson, r.id, r.createdAt, r.eventType);
            String newEnvelope = crypto.encryptToJsonWithKid(toKid, plaintext, r.id, r.createdAt, r.eventType);

            jdbc.update("update audit.audit_events set payload = (?::jsonb) where id = ?",
                    newEnvelope, r.id.toString());

            processed++;
            newLastCreatedAt = r.createdAt;
            newLastId = r.id;
        }

        boolean done = rows.size() < safeLimit;
        return new BatchResult(processed, newLastCreatedAt, newLastId, done);
    }

    private record Row(UUID id, Instant createdAt, String eventType, String payloadJson) {}

    public record BatchResult(long processed, Instant lastCreatedAt, UUID lastId, boolean done) {}
}
